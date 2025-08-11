const path = require('path');
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs-extra');
const cors = require('cors');
const yaml = require('yaml');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const winston = require('winston');
const { body, param, validationResult } = require('express-validator');
const { spawn } = require('child_process');

// Handle unhandled promise rejections early
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Don't exit the process, just log it
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    // Give time to log the error before exiting
    setTimeout(() => {
        process.exit(1);
    }, 1000);
});

// Configuration
const config = {
    vulhubPath: process.env.VULHUB_PATH || '/vulhub',
    port: parseInt(process.env.PORT) || 3000,
    nodeEnv: process.env.NODE_ENV || 'development',
    logLevel: process.env.LOG_LEVEL || 'info',
    corsOrigin: process.env.CORS_ORIGIN || '*',
    maxConcurrentOps: parseInt(process.env.MAX_CONCURRENT_OPS) || 5,
    maxRunningEnvironments: parseInt(process.env.MAX_RUNNING_ENVIRONMENTS) || 1,
    stopOnShutdown: process.env.STOP_ON_SHUTDOWN === 'true',
    scanCacheTTL: parseInt(process.env.SCAN_CACHE_TTL) || 300, // 5 minutes default
    composeTimeout: parseInt(process.env.COMPOSE_TIMEOUT) || 300 // 5 minutes default
};

// Configure logging
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        }),
        new winston.transports.File({ 
            filename: 'logs/error.log', 
            level: 'error' 
        }),
        new winston.transports.File({ 
            filename: 'logs/combined.log' 
        })
    ]
});

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Middleware
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true
}));
app.use(express.json());
app.use(express.static('public'));
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});

const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20, // Stricter limit for sensitive operations
    message: 'Too many requests for this operation, please try again later.'
});

app.use('/api/', limiter);
app.use('/api/environments/:id/start', strictLimiter);
app.use('/api/environments/:id/stop', strictLimiter);

// State management
const runningEnvironments = new Map();
const operationLocks = new Map();
const operationQueue = [];
let activeOperations = 0;

// Validation middleware
function handleValidationErrors(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
}

// Lock management for concurrent operations
async function acquireLock(envId) {
    if (operationLocks.has(envId)) {
        return false;
    }
    operationLocks.set(envId, {
        timestamp: Date.now()
    });
    return true;
}

function releaseLock(envId) {
    operationLocks.delete(envId);
}

// Clean up stale locks (older than 5 minutes)
setInterval(() => {
    const now = Date.now();
    const staleTimeout = 5 * 60 * 1000; // 5 minutes
    
    for (const [key, lock] of operationLocks.entries()) {
        if (now - lock.timestamp > staleTimeout) {
            logger.warn('Removing stale lock', { key, lock });
            operationLocks.delete(key);
        }
    }
}, 60000); // Check every minute

// Helper function to generate a valid Docker Compose project name
function generateProjectName(envId) {
    // Convert to lowercase and replace invalid characters with underscores
    return `vulhub_${envId.toLowerCase().replace(/[^a-z0-9_-]/g, '_')}`;
}

// Secure command execution with proper environment handling
async function execDockerCompose(args, cwd, options = {}) {
    logger.debug('Executing docker-compose', { args, cwd });
    
    return new Promise((resolve, reject) => {
        const env = {
            ...process.env,
            COMPOSE_PROJECT_NAME: options.projectName || generateProjectName(path.basename(cwd)),
            COMPOSE_HTTP_TIMEOUT: options.timeout ? Math.ceil(options.timeout / 1000).toString() : '300'
        };
        
        const child = spawn('docker', ['compose', ...args], {
            cwd,
            env,
            stdio: 'pipe'
        });
        
        let stdout = '';
        let stderr = '';
        
        child.stdout.on('data', (data) => {
            stdout += data.toString();
        });
        
        child.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        
        // Set timeout if specified
        let timeoutId;
        if (options.timeout) {
            timeoutId = setTimeout(() => {
                child.kill('SIGTERM');
                const error = new Error(`Docker compose operation timed out after ${options.timeout}ms`);
                error.code = 'TIMEOUT';
                error.stdout = stdout;
                error.stderr = stderr;
                reject(error);
            }, options.timeout);
        }
        
        child.on('close', (code) => {
            if (timeoutId) {
                clearTimeout(timeoutId);
            }
            
            if (code === 0) {
                resolve({ stdout, stderr });
            } else {
                const error = new Error(`Docker compose exited with code ${code}`);
                error.code = code;
                error.stdout = stdout;
                error.stderr = stderr;
                logger.error('Docker-compose failed', { code, stderr, args, cwd });
                reject(error);
            }
        });
        
        child.on('error', (err) => {
            if (timeoutId) {
                clearTimeout(timeoutId);
            }
            err.stdout = stdout;
            err.stderr = stderr;
            logger.error('Docker-compose spawn error', { error: err.message, args, cwd });
            reject(err);
        });
    });
}

// Scan vulhub directory for environments with caching
const environmentCache = {
    data: null,
    timestamp: 0,
    ttl: 60000 // 1 minute
};

async function scanVulhubEnvironments(forceRefresh = false) {
    try {
        // Check cache
        if (!forceRefresh && environmentCache.data && 
            Date.now() - environmentCache.timestamp < environmentCache.ttl) {
            return environmentCache.data;
        }

        const environments = [];
        
        if (!await fs.pathExists(config.vulhubPath)) {
            logger.error('Vulhub directory not found', { path: config.vulhubPath });
            return environments;
        }

        const categories = await fs.readdir(config.vulhubPath);
        
        for (const category of categories) {
            // Skip hidden directories and files
            if (category.startsWith('.')) continue;
            
            const categoryPath = path.join(config.vulhubPath, category);
            const stat = await fs.stat(categoryPath);
            
            if (!stat.isDirectory()) continue;
            
            try {
                const vulnerabilities = await fs.readdir(categoryPath);
                
                for (const vuln of vulnerabilities) {
                    // Skip hidden directories
                    if (vuln.startsWith('.')) continue;
                    
                    const vulnPath = path.join(categoryPath, vuln);
                    const vulnStat = await fs.stat(vulnPath);
                    
                    if (!vulnStat.isDirectory()) continue;
                    
                    const composePath = path.join(vulnPath, 'docker-compose.yml');
                    const composePathAlt = path.join(vulnPath, 'docker-compose.yaml');
                    
                    let actualComposePath = null;
                    if (await fs.pathExists(composePath)) {
                        actualComposePath = composePath;
                    } else if (await fs.pathExists(composePathAlt)) {
                        actualComposePath = composePathAlt;
                    }
                    
                    if (actualComposePath) {
                        try {
                            const composeContent = await fs.readFile(actualComposePath, 'utf8');
                            const composeData = yaml.parse(composeContent);
                            
                            // Extract port information
                            const ports = [];
                            const services = [];
                            
                            if (composeData.services) {
                                for (const [serviceName, service] of Object.entries(composeData.services)) {
                                    services.push(serviceName);
                                    
                                    if (service.ports) {
                                        service.ports.forEach(port => {
                                            const portStr = port.toString();
                                            const match = portStr.match(/^(\d+):(\d+)/);
                                            if (match) {
                                                ports.push({
                                                    host: match[1],
                                                    container: match[2]
                                                });
                                            }
                                        });
                                    }
                                }
                            }
                            
                            const envId = `${category}_${vuln}`.replace(/[^a-zA-Z0-9_-]/g, '_');
                            const envInfo = {
                                id: envId,
                                name: `${vuln}`,
                                category: category,
                                vulnerability: vuln,
                                path: path.join(category, vuln),
                                fullPath: vulnPath,
                                ports: ports,
                                services: services,
                                status: runningEnvironments.has(envId) ? 'running' : 'stopped',
                                composeVersion: composeData.version || '2'
                            };
                            
                            // Check if README exists
                            const readmePath = path.join(vulnPath, 'README.md');
                            if (await fs.pathExists(readmePath)) {
                                envInfo.hasReadme = true;
                            }
                            
                            environments.push(envInfo);
                        } catch (parseError) {
                            logger.error('Error parsing compose file', {
                                path: `${category}/${vuln}`,
                                error: parseError.message
                            });
                        }
                    }
                }
            } catch (categoryError) {
                logger.error('Error reading category', {
                    category,
                    error: categoryError.message
                });
            }
        }
        
        // Update cache
        environmentCache.data = environments;
        environmentCache.timestamp = Date.now();
        
        return environments;
    } catch (error) {
        logger.error('Error scanning vulhub environments', { error: error.message });
        return [];
    }
}

// Check if environment is actually running
async function checkEnvironmentStatus(env) {
    try {
        const projectName = generateProjectName(env.id);
        const result = await execDockerCompose(['ps', '-q'], env.fullPath, {
            projectName,
            timeout: 5000
        });
        return result.stdout.trim().length > 0;
    } catch (error) {
        logger.debug('Failed to check environment status', { id: env.id, error: error.message });
        return false;
    }
}

// Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Configuration endpoint
app.get('/api/config', (req, res) => {
    res.json({ 
        appHost: process.env.APP_HOST || null,
        // Add other configuration values as needed
    });
});

// Get all environments
app.get('/api/environments', 
    handleValidationErrors,
    async (req, res) => {
        try {
            const environments = await scanVulhubEnvironments();
            res.json(environments);
        } catch (error) {
            logger.error('Error fetching environments', { error: error.message });
            res.status(500).json({ error: 'Failed to fetch environments' });
        }
    }
);

// Start an environment
app.post('/api/environments/:id/start',
    param('id').matches(/^[a-zA-Z0-9_-]+$/).withMessage('Invalid environment ID'),
    handleValidationErrors,
    async (req, res) => {
        const { id } = req.params;
        
        // Use lock to prevent concurrent operations
        if (!await acquireLock(id)) {
            return res.status(409).json({ error: 'Operation already in progress for this environment' });
        }
        
        try {
            const environments = await scanVulhubEnvironments();
            const env = environments.find(e => e.id === id);
            
            if (!env) {
                releaseLock(id);
                return res.status(404).json({ error: 'Environment not found' });
            }
            
            // Check if we've reached the maximum number of running environments
            if (runningEnvironments.size >= config.maxRunningEnvironments) {
                releaseLock(id);
                const runningNames = Array.from(runningEnvironments.values())
                    .map(e => e.name)
                    .join(', ');
                return res.status(400).json({ 
                    error: `Maximum number of running environments (${config.maxRunningEnvironments}) reached`, 
                    details: `Currently running: ${runningNames}. Please stop one before starting another.` 
                });
            }
            
            // Check if environment is already marked as running
            if (runningEnvironments.has(id)) {
                releaseLock(id);
                return res.status(400).json({ error: 'Environment is already running' });
            }
            
            // Double-check by looking at actual Docker containers
            const projectName = generateProjectName(id);
            try {
                const psResult = await execDockerCompose(['ps', '-q'], env.fullPath, {
                    projectName,
                    timeout: 5000
                });
                
                if (psResult.stdout.trim()) {
                    // Containers exist, environment is already running
                    runningEnvironments.set(id, {
                        ...env,
                        startedAt: new Date(),
                        startedBy: 'existing',
                        projectName
                    });
                    releaseLock(id);
                    return res.status(400).json({ 
                        error: 'Environment is already running', 
                        details: 'Found existing containers for this environment' 
                    });
                }
            } catch (error) {
                // Error checking status, continue with start attempt
                logger.debug('Error checking existing containers', { id, error: error.message });
            }
            
            logger.info('Starting environment', { id, name: env.name });
            
            // Pull images first
            try {
                await execDockerCompose(['pull'], env.fullPath, {
                    projectName,
                    timeout: 300000 // 5 minutes timeout for pulling
                });
            } catch (error) {
                logger.error('Failed to pull images', { 
                    id, 
                    error: error.message,
                    stderr: error.stderr 
                });
                releaseLock(id);
                return res.status(500).json({ 
                    error: 'Failed to pull Docker images', 
                    details: error.stderr || error.message 
                });
            }
            
            // Start containers
            try {
                const result = await execDockerCompose(['up', '-d'], env.fullPath, {
                    projectName,
                    timeout: 120000 // 2 minutes timeout
                });
                
                // Verify containers are running
                const checkResult = await execDockerCompose(['ps'], env.fullPath, {
                    projectName
                });
                
                // Mark as running
                runningEnvironments.set(id, {
                    ...env,
                    startedAt: new Date(),
                    startedBy: 'anonymous',
                    projectName
                });
                
                // Broadcast status change
                broadcastStatusChange(id, 'running');
                
                logger.info('Environment started successfully', { id, name: env.name });
                
                releaseLock(id);
                res.json({ 
                    message: 'Environment started successfully',
                    logs: result.stdout 
                });
                
            } catch (error) {
                logger.error('Failed to start environment', { 
                    id, 
                    error: error.message,
                    stderr: error.stderr 
                });
                releaseLock(id);
                return res.status(500).json({ 
                    error: 'Failed to start environment', 
                    details: error.stderr || error.message 
                });
            }
            
        } catch (error) {
            logger.error('Error starting environment', { id, error: error.message });
            releaseLock(id);
            res.status(500).json({ 
                error: 'Failed to start environment', 
                details: error.message 
            });
        }
    }
);

// Stop an environment
app.post('/api/environments/:id/stop',
    param('id').matches(/^[a-zA-Z0-9_-]+$/).withMessage('Invalid environment ID'),
    handleValidationErrors,
    async (req, res) => {
        const { id } = req.params;
        
        // Use lock to prevent concurrent operations
        if (!await acquireLock(id)) {
            return res.status(409).json({ error: 'Operation already in progress for this environment' });
        }
        
        try {
            const runningEnv = runningEnvironments.get(id);
            
            if (!runningEnv) {
                releaseLock(id);
                return res.status(400).json({ error: 'Environment is not running' });
            }
            
            logger.info('Stopping environment', { id, name: runningEnv.name });
            
            // Generate the same project name
            const projectName = generateProjectName(id);
            
            try {
                const result = await execDockerCompose(['down', '-v'], runningEnv.fullPath, {
                    projectName,
                    timeout: 60000 // 1 minute timeout
                });
                
                // Remove from running environments
                runningEnvironments.delete(id);
                
                // Broadcast status change
                broadcastStatusChange(id, 'stopped');
                
                logger.info('Environment stopped successfully', { id, name: runningEnv.name });
                
                releaseLock(id);
                res.json({ 
                    message: 'Environment stopped successfully',
                    logs: result.stdout 
                });
                
            } catch (error) {
                logger.error('Failed to stop environment', { 
                    id, 
                    error: error.message,
                    stderr: error.stderr 
                });
                releaseLock(id);
                return res.status(500).json({ 
                    error: 'Failed to stop environment', 
                    details: error.stderr || error.message 
                });
            }
            
        } catch (error) {
            logger.error('Error stopping environment', { id, error: error.message });
            releaseLock(id);
            res.status(500).json({ 
                error: 'Failed to stop environment', 
                details: error.message 
            });
        }
    }
);

// Get environment logs
app.get('/api/environments/:id/logs',
    param('id').matches(/^[a-zA-Z0-9_-]+$/).withMessage('Invalid environment ID'),
    handleValidationErrors,
    async (req, res) => {
        const { id } = req.params;
        const tail = req.query.tail || '100';
        
        try {
            const environments = await scanVulhubEnvironments();
            const env = environments.find(e => e.id === id);
            
            if (!env) {
                return res.status(404).json({ error: 'Environment not found' });
            }
            
            const runningInfo = runningEnvironments.get(id);
            const projectName = runningInfo?.projectName || `vulhub_${id}`;
            
            const result = await execDockerCompose(
                ['logs', '--tail', tail],
                env.fullPath,
                {
                    env: {
                        COMPOSE_PROJECT_NAME: projectName
                    },
                    timeout: 10000
                }
            );
            
            res.json({ 
                logs: result.stdout || 'No logs available',
                stderr: result.stderr 
            });
            
        } catch (error) {
            logger.error('Error getting logs', { 
                id, 
                error: error.message 
            });
            
            res.json({ 
                logs: `Error retrieving logs: ${error.error || error.message}`,
                stderr: error.stderr 
            });
        }
    }
);

// Get streaming logs (SSE)
app.get('/api/environments/:id/logs/stream',
    param('id').matches(/^[a-zA-Z0-9_-]+$/).withMessage('Invalid environment ID'),
    handleValidationErrors,
    async (req, res) => {
        const { id } = req.params;
        
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no' // Disable Nginx buffering
        });
        
        try {
            const environments = await scanVulhubEnvironments();
            const env = environments.find(e => e.id === id);
            
            if (!env) {
                res.write('data: Environment not found\n\n');
                res.end();
                return;
            }
            
            const runningInfo = runningEnvironments.get(id);
            const projectName = runningInfo?.projectName || generateProjectName(id);
            
            const logProcess = spawn('docker', ['compose', 'logs', '-f', '--tail', '50'], {
                cwd: env.fullPath,
                env: {
                    ...process.env,
                    COMPOSE_PROJECT_NAME: projectName
                }
            });
            
            logProcess.stdout.on('data', (data) => {
                const lines = data.toString().split('\n');
                lines.forEach(line => {
                    if (line.trim()) {
                        res.write(`data: ${JSON.stringify({ type: 'log', content: line })}\n\n`);
                    }
                });
            });
            
            logProcess.stderr.on('data', (data) => {
                const lines = data.toString().split('\n');
                lines.forEach(line => {
                    if (line.trim()) {
                        res.write(`data: ${JSON.stringify({ type: 'error', content: line })}\n\n`);
                    }
                });
            });
            
            logProcess.on('close', (code) => {
                res.write(`data: ${JSON.stringify({ type: 'close', code })}\n\n`);
                res.end();
            });
            
            req.on('close', () => {
                logProcess.kill('SIGTERM');
            });
            
        } catch (error) {
            logger.error('Error streaming logs', { id, error: error.message });
            res.write(`data: ${JSON.stringify({ type: 'error', content: error.message })}\n\n`);
            res.end();
        }
    }
);

// Get environment details
app.get('/api/environments/:id/details',
    param('id').matches(/^[a-zA-Z0-9_-]+$/).withMessage('Invalid environment ID'),
    handleValidationErrors,
    async (req, res) => {
        const { id } = req.params;
        
        try {
            const environments = await scanVulhubEnvironments();
            const env = environments.find(e => e.id === id);
            
            if (!env) {
                return res.status(404).json({ error: 'Environment not found' });
            }
            
            const details = { ...env };
            
            // Read README if it exists
            const readmePath = path.join(env.fullPath, 'README.md');
            if (await fs.pathExists(readmePath)) {
                details.readme = await fs.readFile(readmePath, 'utf8');
            }
            
            // Get container status if running
            if (runningEnvironments.has(id)) {
                const runningInfo = runningEnvironments.get(id);
                const projectName = runningInfo?.projectName || `vulhub_${id}`;
                
                try {
                    const psResult = await execDockerCompose(['ps'], env.fullPath, {
                        env: {
                            COMPOSE_PROJECT_NAME: projectName
                        },
                        timeout: 5000
                    });
                    details.containerStatus = psResult.stdout;
                } catch (error) {
                    logger.debug('Could not get container status', { id, error: error.message });
                }
            }
            
            res.json(details);
        } catch (error) {
            logger.error('Error getting environment details', { id, error: error.message });
            res.status(500).json({ 
                error: 'Failed to get environment details', 
                details: error.message 
            });
        }
    }
);

// Serve static files from environment directories (no auth required)
app.get('/api/environments/:id/static/*',
    param('id').matches(/^[a-zA-Z0-9_-]+$/).withMessage('Invalid environment ID'),
    handleValidationErrors,
    async (req, res) => {
        const { id } = req.params;
        const filePath = req.params[0]; // Get the file path after /static/
        
        try {
            // Validate file path to prevent directory traversal
            if (filePath.includes('..') || path.isAbsolute(filePath)) {
                return res.status(400).json({ error: 'Invalid file path' });
            }
            
            const environments = await scanVulhubEnvironments();
            const env = environments.find(e => e.id === id);
            
            if (!env) {
                return res.status(404).json({ error: 'Environment not found' });
            }
            
            // Construct the full file path
            const fullFilePath = path.join(env.fullPath, filePath);
            
            // Check if file exists and is within the environment directory
            if (!fullFilePath.startsWith(env.fullPath) || !await fs.pathExists(fullFilePath)) {
                return res.status(404).json({ error: 'File not found' });
            }
            
            // Check if it's a file (not a directory)
            const stat = await fs.stat(fullFilePath);
            if (!stat.isFile()) {
                return res.status(400).json({ error: 'Not a file' });
            }
            
            // Set appropriate content type based on file extension
            const ext = path.extname(fullFilePath).toLowerCase();
            const contentTypes = {
                '.png': 'image/png',
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.gif': 'image/gif',
                '.svg': 'image/svg+xml',
                '.webp': 'image/webp',
                '.txt': 'text/plain',
                '.md': 'text/markdown',
                '.pdf': 'application/pdf'
            };
            
            const contentType = contentTypes[ext] || 'application/octet-stream';
            res.type(contentType);
            
            // Send the file
            res.sendFile(fullFilePath);
            
        } catch (error) {
            logger.error('Error serving static file', { 
                id, 
                filePath, 
                error: error.message 
            });
            res.status(500).json({ 
                error: 'Failed to serve file', 
                details: error.message 
            });
        }
    }
);

// WebSocket connection handling
wss.on('connection', (ws, req) => {
    logger.info('WebSocket client connected');
    
    // Setup heartbeat
    ws.isAlive = true;
    ws.on('pong', () => {
        ws.isAlive = true;
    });
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            logger.debug('WebSocket message received', { data });
            
            // Respond to ping with pong
            if (data.type === 'ping') {
                ws.send(JSON.stringify({ type: 'pong' }));
            }
        } catch (error) {
            logger.error('Invalid WebSocket message', { error: error.message });
        }
    });
    
    ws.on('close', () => {
        logger.info('WebSocket client disconnected');
    });
    
    ws.on('error', (error) => {
        logger.error('WebSocket error', { error: error.message });
    });
});

// WebSocket heartbeat interval
const wsHeartbeat = setInterval(() => {
    wss.clients.forEach((ws) => {
        if (ws.isAlive === false) {
            logger.debug('Terminating inactive WebSocket connection');
            return ws.terminate();
        }
        
        ws.isAlive = false;
        ws.ping();
    });
}, 30000); // Check every 30 seconds

// Clean up heartbeat on shutdown
wss.on('close', () => {
    clearInterval(wsHeartbeat);
});

// Broadcast message to all connected WebSocket clients
function broadcastMessage(message) {
    const messageStr = JSON.stringify(message);
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(messageStr);
        }
    });
}

// Broadcast status change to all clients
function broadcastStatusChange(environmentId, status) {
    broadcastMessage({
        type: 'status_change',
        environmentId,
        status,
        timestamp: new Date().toISOString()
    });
}

// Graceful shutdown
let isShuttingDown = false;

async function gracefulShutdown(signal) {
    if (isShuttingDown) return;
    isShuttingDown = true;
    
    logger.info('Graceful shutdown initiated', { signal });
    
    // Close server to stop accepting new connections
    server.close(() => {
        logger.info('HTTP server closed');
    });
    
    // Close all WebSocket connections
    wss.clients.forEach(client => {
        client.close(1001, 'Server shutting down');
    });
    
    // Wait for ongoing operations to complete (max 30 seconds)
    const shutdownTimeout = setTimeout(() => {
        logger.warn('Shutdown timeout reached, forcing exit');
        process.exit(0);
    }, 30000);
    
    // Stop all running environments if configured to do so
    if (config.stopOnShutdown) {
        logger.info('Stopping all running environments');
        for (const [id, info] of runningEnvironments.entries()) {
            try {
                await execDockerCompose(['down'], info.fullPath, {
                    env: {
                        COMPOSE_PROJECT_NAME: info.projectName
                    },
                    timeout: 10000
                });
                logger.info('Stopped environment on shutdown', { id });
            } catch (error) {
                logger.error('Failed to stop environment on shutdown', { 
                    id, 
                    error: error.message 
                });
            }
        }
    }
    
    clearTimeout(shutdownTimeout);
    logger.info('Graceful shutdown complete');
    process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
    logger.info('Vulhub Manager server started', {
        port: PORT,
        nodeEnv: config.nodeEnv,
        vulhubPath: config.vulhubPath
    });
    
    // Check Docker availability
    try {
        const result = await execDockerCompose(['version'], process.cwd(), {
            timeout: 5000
        });
        logger.info('Docker Compose is available', {
            version: result.stdout.trim()
        });
    } catch (error) {
        logger.error('Docker Compose is not available', {
            error: error.message
        });
    }
    
    // Function to check for running environments
    async function checkRunningEnvironments() {
        try {
            const envs = await scanVulhubEnvironments();
            let runningCount = 0;
            
            // Clear current running environments to rebuild from Docker state
            runningEnvironments.clear();
            
            for (const env of envs) {
                try {
                    const projectName = generateProjectName(env.id);
                    const psResult = await execDockerCompose(['ps', '-q'], env.fullPath, {
                        projectName,
                        timeout: 5000
                    });
                    
                    if (psResult.stdout.trim()) {
                        // Environment is running
                        runningEnvironments.set(env.id, {
                            ...env,
                            startedAt: new Date(),
                            startedBy: 'pre-existing',
                            projectName
                        });
                        runningCount++;
                        logger.debug('Found running environment', { 
                            id: env.id, 
                            name: env.name,
                            projectName 
                        });
                    }
                } catch (error) {
                    // Ignore errors, environment is probably not running
                }
            }
            
            return runningCount;
        } catch (error) {
            logger.error('Error checking running environments', { error: error.message });
            return 0;
        }
    }
    
    // Initial scan of environments
    try {
        const envs = await scanVulhubEnvironments();
        logger.info('Initial environment scan complete', { count: envs.length });
        
        // Check for already running environments
        logger.info('Checking for already running environments...');
        const runningCount = await checkRunningEnvironments();
        
        if (runningCount > 0) {
            logger.info('Found pre-existing running environments', { count: runningCount });
        }
        
        // Periodically check for running environments (every 10 seconds)
        setInterval(async () => {
            try {
                const previousCount = runningEnvironments.size;
                const currentCount = await checkRunningEnvironments();
                
                // Only log if the count changed
                if (currentCount !== previousCount) {
                    logger.info('Running environment count changed', { 
                        previous: previousCount, 
                        current: currentCount 
                    });
                }
            } catch (error) {
                logger.error('Periodic environment check failed', { error: error.message });
            }
        }, 10000);
        
    } catch (error) {
        logger.error('Failed to scan environments', { error: error.message });
    }
});
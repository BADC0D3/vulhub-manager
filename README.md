# Vulhub Manager

A web-based interface for managing Vulhub (Vulnerable Docker Environments). This tool provides an easy way to browse, start, stop, and monitor vulnerable Docker environments for security testing and education.

## Features

- 🐳 **Docker Integration**: Seamless management of Docker Compose environments
- 🔍 **Environment Discovery**: Automatically scans and catalogs available Vulhub environments
- 🚀 **One-Click Operations**: Start/stop environments with a single click
- 📊 **Real-time Status**: Live status updates via WebSocket
- 📋 **Log Viewer**: View container logs directly in the interface
- 📖 **Documentation**: Integrated README viewer with markdown support
- 🖼️ **Image Support**: Displays images from environment documentation with modal viewer
- 🔄 **Auto-refresh**: Periodic updates to keep information current
- 📱 **Responsive Design**: Works on desktop and mobile devices
- 🚫 **Single Instance Limit**: Only one environment can run at a time (configurable)
- 🌐 **Dynamic Host Support**: Automatically adapts to any hostname or IP address
- 🔗 **Clickable Links**: Direct access to vulnerable applications from the interface

## Prerequisites

- Docker and Docker Compose v2 installed
- Node.js 16+ (for development)
- Vulhub repository cloned to `/vulhub` (configurable)

## Quick Start

### Using Docker (Recommended)

1. Clone this repository:
```bash
git clone <repository-url>
cd vulhub-manager
```

2. Configure environment:
```bash
cp .env.example .env
# Edit .env to set your configuration
```

3. Run with Docker Compose:
```bash
docker compose up -d
```

4. Access the interface at `http://localhost:3000`

### Manual Installation

1. Install dependencies:
```bash
npm install
```

2. Configure environment:
```bash
cp .env.example .env
# Edit .env to set your configuration
```

3. Start the server:
```bash
npm start
```

## Configuration

Key environment variables in `.env`:

- `PORT`: Server port (default: 3000)
- `VULHUB_PATH`: Path to Vulhub repository (default: /vulhub)
- `NODE_ENV`: Environment mode (development/production)
- `LOG_LEVEL`: Logging level (default: info)
- `CORS_ORIGIN`: Allowed CORS origins (default: http://localhost:3000)
- `COMPOSE_TIMEOUT`: Docker compose operation timeout (default: 300s)
- `SCAN_CACHE_TTL`: Environment scan cache duration (default: 300s)
- `MAX_RUNNING_ENVIRONMENTS`: Maximum concurrent environments (default: 1)
- `APP_HOST`: Override automatic host detection (optional, e.g., 192.168.1.100)

### Docker Status Checking

VulhubWeb automatically checks for running Docker containers:
- **On Startup**: Scans all environments to detect any pre-existing running containers
- **Every 30 seconds**: Server-side check to update the status of all environments
- **Every 30 seconds**: Client-side refresh to update the UI with latest status
- **On-demand**: Status is updated whenever you start/stop environments

This ensures the UI always shows the correct status even if:
- Containers are started/stopped outside of VulhubWeb
- The VulhubWeb container is restarted
- Multiple users are managing environments

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/environments` | GET | List all environments |
| `/api/environments/:id/start` | POST | Start an environment |
| `/api/environments/:id/stop` | POST | Stop an environment |
| `/api/environments/:id/logs` | GET | Stream environment logs |
| `/api/environments/:id/details` | GET | Get environment details and README |
| `/api/environments/:id/static/*` | GET | Serve static files from environment |

## Architecture

- **Backend**: Node.js with Express
- **Frontend**: Vanilla JavaScript with WebSocket support
- **Real-time**: WebSocket for live updates and heartbeat
- **Docker**: Manages containers via docker compose v2
- **Security**: Rate limiting, input validation, path traversal protection

## Development

### Project Structure
```
vulhub-manager/
├── server.js           # Express server
├── public/            
│   └── index.html     # Frontend application
├── logs/              # Application logs
├── Dockerfile         # Docker image definition
├── docker-compose.yml # Development configuration
├── docker-compose.prod.yml # Production configuration
└── package.json       # Node.js dependencies
```

### Running Tests
```bash
npm test        # Run tests
npm run lint    # Run linter
```

### Development Mode
```bash
npm run dev     # Start with auto-reload
```

## Documentation

### 📚 Available Guides

- **[Documentation Index](DOCUMENTATION_INDEX.md)** - Complete index of all documentation files
- **[Deployment Guide](DEPLOYMENT.md)** - Production deployment, reverse proxy setup, security hardening
- **[Host Configuration](HOST_CONFIGURATION.md)** - Dynamic host configuration, remote access setup
- **[Troubleshooting Guide](TROUBLESHOOTING.md)** - Comprehensive troubleshooting solutions
- **[Vulnerable Apps Overview](vulnerabilities/README.md)** - Details about all 25 vulnerable applications
- **[Port Mapping Reference](vulnerabilities/PORT_MAPPING.md)** - Complete port assignments and conflict resolution
- **[Quick Start Guide](vulnerabilities/QUICK_START.md)** - Quick access URLs and default credentials

### 🎯 Quick Links

- **VulhubWeb Interface**: http://localhost:3000 (or http://YOUR_HOST:3000)
- **Total Applications**: 25 vulnerable applications across 6 categories
- **Port Range**: 3000-8095 (all applications use unique ports)

## Troubleshooting

### Common Issues

1. **Docker Permission Errors**
   - The container runs as root by default for Docker socket access
   - Ensure Docker socket is accessible at `/var/run/docker.sock`

2. **Port Already in Use**
   - Change PORT in .env file
   - Stop conflicting services
   - See [Port Mapping Reference](vulnerabilities/PORT_MAPPING.md)

3. **Environments Not Found**
   - Verify VULHUB_PATH is correct (should be `./vulnerabilities`)
   - Check directory permissions
   - Ensure categories structure exists (web/, api/, etc.)

4. **WebSocket Connection Issues**
   - Check firewall settings
   - Verify CORS configuration matches your access URL
   - See [Host Configuration](HOST_CONFIGURATION.md) for remote access

5. **Environment Start Failures**
   - Check if another environment is already running (single instance limit)
   - Some Docker images may need to be pulled first
   - Check Docker logs for specific errors
   - See [Troubleshooting Guide](TROUBLESHOOTING.md) for detailed solutions

## Security Considerations

⚠️ **WARNING**: This tool manages vulnerable Docker environments. Use only in isolated networks!

- No authentication - secure access at network level or with reverse proxy
- Implements rate limiting to prevent abuse
- Validates all inputs to prevent injection attacks
- Restricts file access to prevent directory traversal
- Limits concurrent environments to prevent resource exhaustion

## Docker Compose v2 Compatibility

This application uses the modern `docker compose` command (v2) syntax. Project names are automatically sanitized to meet Docker Compose v2 requirements:
- Lowercase letters, numbers, hyphens, and underscores only
- Must start with a letter or number

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Vulhub](https://github.com/vulhub/vulhub) - Vulnerable Docker environments

# Deployment Guide for Remote Servers

This guide helps you deploy Vulhub Manager on a remote server.

## Quick Start

1. **Clone and setup**:
```bash
git clone <your-repo-url> vulhub-manager
cd vulhub-manager

# Create .env file
cp .env.example .env
nano .env  # Edit configuration
```

2. **Configure for your server**:
```bash
# Set the CORS origin to match your access URL
# For HTTP access:
CORS_ORIGIN=http://YOUR_SERVER_IP:3000

# Optional: Set maximum concurrent environments (default is 1)
MAX_RUNNING_ENVIRONMENTS=1
```

3. **Start the application**:
```bash
# Using production configuration
docker compose -f docker-compose.prod.yml up -d

# OR for development
docker compose up -d
```

4. **Access the interface**:
Navigate to `http://YOUR_SERVER_IP:3000` in your browser.

## Environment Variables

Create a `.env` file with these settings:

```env
# Server Configuration
PORT=3000
NODE_ENV=production
LOG_LEVEL=info

# CORS - MUST match how you access the app
CORS_ORIGIN=http://your-server-ip:3000

# Vulhub Configuration
VULHUB_PATH=/vulhub
MAX_RUNNING_ENVIRONMENTS=1
COMPOSE_TIMEOUT=300
SCAN_CACHE_TTL=300
STOP_ON_SHUTDOWN=false
```

## Docker Setup

### Vulhub Repository

The application expects Vulhub to be available at `/vulhub`:

```bash
# Clone Vulhub repository
cd /
sudo git clone https://github.com/vulhub/vulhub.git

# OR mount it via docker-compose.prod.yml
volumes:
  - /path/to/your/vulhub:/vulhub:ro
```

### Build and Deploy

```bash
# Build the Docker image
docker compose -f docker-compose.prod.yml build

# Start the service
docker compose -f docker-compose.prod.yml up -d

# Check logs
docker compose -f docker-compose.prod.yml logs -f

# Verify health
curl http://localhost:3000/api/health
```

## Common Issues and Solutions

### Issue 1: Docker Socket Permissions

The production configuration runs the container as root to access the Docker socket. This is configured in `docker-compose.prod.yml`:

```yaml
user: root  # Required for Docker socket access
```

If you prefer not to run as root, you'll need to:
1. Add your user to the docker group
2. Adjust the container user accordingly
3. Ensure proper socket permissions

### Issue 2: Port Conflicts

If port 3000 is already in use:

```bash
# Change port in .env
PORT=8080

# Update docker-compose.prod.yml
ports:
  - "8080:3000"

# Update CORS origin
CORS_ORIGIN=http://YOUR_SERVER_IP:8080
```

### Issue 3: CORS Issues

Ensure your `CORS_ORIGIN` exactly matches the URL you use to access the app:

```bash
# Examples:
CORS_ORIGIN=http://localhost:3000
CORS_ORIGIN=http://192.168.1.2:3000
CORS_ORIGIN=http://vulhub.example.com
CORS_ORIGIN=https://vulhub.example.com  # If using HTTPS
```

### Issue 4: Environment Start Failures

Some Vulhub environments may have configuration issues:
- Check Docker logs for specific errors
- Try starting a known working environment (e.g., `nginx_nginx_parsing_vulnerability`)
- Ensure only one environment runs at a time (default limit)

## Production Best Practices

### 1. Network Security

Since there's no built-in authentication, secure at the network level:

```bash
# Firewall example (UFW)
sudo ufw allow from 192.168.1.0/24 to any port 3000
sudo ufw deny 3000
```

### 2. Reverse Proxy with Basic Auth

Use Nginx for HTTPS and basic authentication:

```nginx
server {
    listen 80;
    server_name vulhub.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name vulhub.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/vulhub.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vulhub.yourdomain.com/privkey.pem;

    # Basic authentication
    auth_basic "Vulhub Manager";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Create password file:
```bash
sudo htpasswd -c /etc/nginx/.htpasswd admin
```

Update CORS for HTTPS:
```bash
CORS_ORIGIN=https://vulhub.yourdomain.com
```

### 3. Resource Limits

Configure resource limits in `docker-compose.prod.yml`:

```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 1G
    reservations:
      cpus: '0.5'
      memory: 256M
```

### 4. Monitoring

Monitor the application:

```bash
# Check container status
docker ps | grep vulhub-manager

# View recent logs
docker logs vulhub-manager --tail=100

# Follow logs
docker logs -f vulhub-manager

# Check resource usage
docker stats vulhub-manager
```

## Maintenance

### Update Application

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml down
docker compose -f docker-compose.prod.yml up -d
```

### Backup Logs

```bash
# Create backup directory
mkdir -p backups

# Backup application logs
docker cp vulhub-manager:/app/logs ./backups/logs-$(date +%Y%m%d)

# Backup configuration
cp .env ./backups/.env.$(date +%Y%m%d)
```

### Clean Up

```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune

# Remove unused networks
docker network prune
```

## Troubleshooting Commands

```bash
# Test API endpoint
curl http://localhost:3000/api/health

# List environments
curl http://localhost:3000/api/environments

# Check Docker access from container
docker exec vulhub-manager docker ps

# Check environment variables
docker exec vulhub-manager env | grep -E "PORT|CORS|VULHUB"

# Test WebSocket connection
wscat -c ws://localhost:3000

# Check disk usage
df -h /var/lib/docker
```

## Performance Tips

1. **Limit concurrent environments**: Keep `MAX_RUNNING_ENVIRONMENTS=1` for single-user setups
2. **Regular cleanup**: Remove unused Docker resources
3. **Monitor disk space**: Vulhub images can consume significant space
4. **Use log rotation**: Configure Docker log rotation

## Security Notes

⚠️ **WARNING**: 
- Vulhub contains intentionally vulnerable applications
- Deploy only in isolated, controlled environments
- Never expose directly to the internet without proper security measures
- Use network isolation, authentication, and monitoring

## Support

If you encounter issues:

1. Check container logs for errors
2. Verify Docker and Docker Compose v2 are installed
3. Ensure CORS_ORIGIN matches your access URL
4. Test with a known working Vulhub environment
5. Check available disk space and resources 
# Host Configuration for VulhubWeb

## Overview
VulhubWeb now supports dynamic host configuration, allowing you to access the vulnerable applications from any host or IP address.

## How It Works

### Automatic Detection (Default)
By default, the application automatically uses the hostname from your browser's URL. This means:
- If you access VulhubWeb at `http://localhost:3000`, links will use `localhost`
- If you access VulhubWeb at `http://192.168.1.100:3000`, links will use `192.168.1.100`
- If you access VulhubWeb at `http://myserver.local:3000`, links will use `myserver.local`

### Manual Configuration (Override)
You can override the automatic detection by setting the `APP_HOST` environment variable.

## Configuration Methods

### Method 1: Environment Variable
```bash
export APP_HOST=192.168.1.100
docker compose up -d
```

### Method 2: .env File
Create or edit `.env` in the VulhubWeb directory:
```env
APP_HOST=192.168.1.100
```

### Method 3: Docker Compose Override
```yaml
services:
  vulhub-manager:
    environment:
      - APP_HOST=192.168.1.100
```

### Method 4: Command Line
```bash
APP_HOST=192.168.1.100 docker compose up -d
```

## Examples

### Local Development (Default)
No configuration needed. Access everything via `localhost`.

### LAN Access
If your server IP is `192.168.1.100`:
```bash
APP_HOST=192.168.1.100 docker compose up -d
```

### Domain Name
If you have a domain pointing to your server:
```bash
APP_HOST=vulnlab.example.com docker compose up -d
```

### Docker Machine/Remote Host
If running on a remote Docker host:
```bash
APP_HOST=$(docker-machine ip myhost) docker compose up -d
```

## Important Notes

1. **Port Accessibility**: Ensure all application ports (3001-8095) are accessible from your client machine
2. **Firewall Rules**: You may need to open ports in your firewall
3. **Protocol**: The APP_HOST configuration assumes HTTP. For HTTPS, you'll need a reverse proxy
4. **Dynamic Behavior**: Without APP_HOST set, the system automatically adapts to whatever hostname you use

## Troubleshooting

### Links Still Show localhost
1. Clear your browser cache
2. Restart the VulhubWeb container after setting APP_HOST
3. Check if the configuration is loaded: `curl http://your-host:3000/api/config`

### Cannot Access Applications
1. Verify the ports are open: `nmap -p 3001-8095 your-host`
2. Check Docker is binding to all interfaces, not just localhost
3. Ensure no firewall is blocking the ports

### Mixed Protocol Issues
If you're accessing VulhubWeb via HTTPS but applications via HTTP:
- Consider using a reverse proxy for all services
- Or access VulhubWeb via HTTP when APP_HOST is not set

## Security Considerations

⚠️ **WARNING**: Exposing these vulnerable applications to a network is dangerous!

- Only use on isolated networks
- Never expose to the public internet
- Use VPN for remote access
- Consider firewall rules to limit access
- Monitor for suspicious activity

## Advanced Configuration

### Reverse Proxy Setup
For production-like environments, use a reverse proxy:

```nginx
# Example Nginx configuration
server {
    listen 80;
    server_name vulnlab.example.com;

    # VulhubWeb Manager
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
    }

    # Juice Shop
    location /juice-shop/ {
        proxy_pass http://localhost:3001/;
        proxy_set_header Host $host;
    }

    # Add other applications...
}
```

### Docker Network Isolation
For better security, use custom Docker networks:

```yaml
networks:
  vulnlab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

services:
  vulhub-manager:
    networks:
      - vulnlab
    # ...
``` 
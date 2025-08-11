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

## Troubleshooting

### Common Issues

1. **Docker Permission Errors**
   - The container runs as root by default for Docker socket access
   - Ensure Docker socket is accessible at `/var/run/docker.sock`

2. **Port Already in Use**
   - Change PORT in .env file
   - Stop conflicting services

3. **Environments Not Found**
   - Verify VULHUB_PATH is correct
   - Check directory permissions

4. **WebSocket Connection Issues**
   - Check firewall settings
   - Verify CORS configuration matches your access URL

5. **Environment Start Failures**
   - Check if another environment is already running (single instance limit)
   - Some Vulhub environments may have configuration issues
   - Check Docker logs for specific errors

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

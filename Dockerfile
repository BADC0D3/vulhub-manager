# Dockerfile
FROM node:18-alpine

# Install Docker CLI and required packages
RUN apk add --no-cache \
    docker-cli \
    docker-compose \
    tini

# Create non-root user (but we'll override with root in docker-compose for Docker socket access)
RUN addgroup -g 1001 nodeapp && \
    adduser -u 1001 -G nodeapp -s /bin/sh -D nodeapp

# Create app directory
WORKDIR /app

# Copy package files as root to install dependencies
COPY package*.json ./

# Install dependencies
RUN npm ci --omit=dev && \
    npm cache clean --force

# Copy app source
COPY --chown=nodeapp:nodeapp . .

# Create logs directory and set permissions
RUN mkdir -p logs && \
    chown -R nodeapp:nodeapp /app

# Switch to non-root user (will be overridden by docker-compose.prod.yml)
USER nodeapp

# Expose port
EXPOSE 3000

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/api/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1); })"

# Use tini as init system
ENTRYPOINT ["/sbin/tini", "--"]

# Start the application
CMD ["node", "server.js"]
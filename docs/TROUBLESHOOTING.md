# VulhubWeb Troubleshooting Guide

## Common Issues and Solutions

### Issue: Shows 0 Running Environments After Container Restart

**Symptoms:**
- After restarting the VulhubWeb container, it shows 0 running environments
- You know there are containers running but they don't appear in the UI

**Solution:**
This is normal behavior. VulhubWeb needs a moment to detect running containers:
1. **Wait 10 seconds** - The system automatically checks every 10 seconds
2. **Refresh your browser** - The UI updates every 10 seconds automatically
3. **Check the logs** to see detection progress:
   ```bash
   docker compose logs vulhub-manager | grep "running environment"
   ```

**Why this happens:**
- On startup, VulhubWeb scans for running containers
- This scan may take a few seconds for many environments
- The UI will update automatically within 10 seconds

### Issue: Port Conflicts

**Symptoms:**
- Error: "bind: address already in use"
- Cannot start an environment

**Solution:**
1. Check what's using the port:
   ```bash
   lsof -i :PORT_NUMBER
   # or
   netstat -tulpn | grep PORT_NUMBER
   ```

2. Stop conflicting containers:
   ```bash
   docker ps | grep PORT_NUMBER
   docker stop CONTAINER_ID
   ```

3. Check the [PORT_MAPPING.md](../vulnerabilities/PORT_MAPPING.md) file for all port assignments

### Issue: Cannot Access Applications

**Symptoms:**
- Clicking links shows "Connection refused"
- Applications not accessible from browser

**Solutions:**

1. **Check if containers are running:**
   ```bash
   docker ps
   ```

2. **Verify port bindings:**
   ```bash
   docker ps --format "table {{.Names}}\t{{.Ports}}"
   ```

3. **Check firewall rules:**
   ```bash
   # Ubuntu/Debian
   sudo ufw status
   
   # CentOS/RHEL
   sudo firewall-cmd --list-all
   ```

4. **If accessing remotely, ensure Docker binds to all interfaces:**
   Check that ports show `0.0.0.0:PORT->...` not `127.0.0.1:PORT->...`

### Issue: Environment Won't Start

**Symptoms:**
- Clicking "Start" shows error
- Environment stays in "stopped" state

**Solutions:**

1. **Check Docker resources:**
   ```bash
   docker system df
   docker system prune -a  # Caution: removes unused images
   ```

2. **Check logs:**
   ```bash
   docker compose logs vulhub-manager | tail -50
   ```

3. **Manual start to see errors:**
   ```bash
   cd vulnerabilities/CATEGORY/APP_NAME
   docker compose up
   ```

### Issue: WebSocket Connection Lost

**Symptoms:**
- No real-time updates
- Console shows WebSocket errors

**Solution:**
1. Refresh the page
2. Check if behind a proxy - WebSocket support may be needed
3. Clear browser cache

### Issue: Images Not Found

**Symptoms:**
- "pull access denied" errors
- "image not found" errors

**Solution:**
1. Check internet connectivity
2. Some images may require login:
   ```bash
   docker login
   ```
3. Check if image still exists on Docker Hub
4. See STATUS.md for known image issues and replacements

### Issue: UI Not Updating

**Symptoms:**
- Status doesn't change after operations
- Have to manually refresh

**Solutions:**

1. **Check browser console for errors:**
   - Press F12 → Console tab
   - Look for red error messages

2. **Clear browser cache:**
   - Ctrl+Shift+R (Windows/Linux)
   - Cmd+Shift+R (Mac)

3. **Check WebSocket connection:**
   - Should reconnect automatically
   - Check for proxy/firewall blocking WebSocket

### Issue: Cannot Run Multiple Environments

**Symptoms:**
- Error when trying to start second environment
- "Maximum running environments reached"

**Solution:**
This is by design for safety. To change:

1. Edit docker-compose.yml:
   ```yaml
   environment:
     - MAX_RUNNING_ENVIRONMENTS=3  # Allow 3 concurrent
   ```

2. Restart VulhubWeb:
   ```bash
   docker compose restart vulhub-manager
   ```

⚠️ **Warning**: Running multiple vulnerable environments increases security risk!

### Issue: Logs Not Showing

**Symptoms:**
- Log viewer shows "No logs available"
- Logs are empty

**Solution:**
1. Wait a few seconds - containers may still be starting
2. Check if container is actually running:
   ```bash
   docker ps | grep ENVIRONMENT_NAME
   ```
3. View logs directly:
   ```bash
   docker logs CONTAINER_NAME
   ```

## Getting Help

If you're still having issues:

1. **Check the logs:**
   ```bash
   docker compose logs vulhub-manager | tail -100
   ```

2. **Collect debug information:**
   ```bash
   docker version
   docker compose version
   docker ps -a
   ```

3. **Check system resources:**
   ```bash
   df -h
   free -h
   ```

4. **Review configuration:**
   - Check .env file
   - Verify docker-compose.yml hasn't been modified
   - Ensure VULHUB_PATH is correct

## Performance Tips

1. **Limit concurrent environments** - Each uses memory and CPU
2. **Regularly clean Docker:**
   ```bash
   docker system prune -a --volumes
   ```
3. **Monitor resources:**
   ```bash
   docker stats
   ```
4. **Use SSDs** for better Docker performance
5. **Allocate sufficient RAM** to Docker (4GB minimum recommended) 
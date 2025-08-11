FROM ubuntu:20.04

# Install necessary tools
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat \
    python3 \
    python3-pip \
    vim \
    sudo \
    procps \
    libcap2-bin \
    strace \
    && rm -rf /var/lib/apt/lists/*

# Install Flask for web interface
RUN pip3 install flask

# Create vulnerable user with sudo privileges (bad practice)
RUN useradd -m -s /bin/bash vulnerable && \
    echo "vulnerable:vulnerable" | chpasswd && \
    echo "vulnerable ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Create app directory
WORKDIR /app

# Create the vulnerable web application
RUN echo 'from flask import Flask, request, render_template_string\n\
import subprocess\n\
import os\n\
\n\
app = Flask(__name__)\n\
\n\
HTML_TEMPLATE = """\n\
<!DOCTYPE html>\n\
<html>\n\
<head>\n\
    <title>Docker Escape Lab</title>\n\
    <style>\n\
        body { font-family: Arial, sans-serif; margin: 40px; }\n\
        .section { margin: 20px 0; padding: 20px; background: #f5f5f5; }\n\
        .warning { color: red; font-weight: bold; }\n\
        pre { background: #e0e0e0; padding: 10px; overflow: auto; }\n\
        textarea { width: 100%; }\n\
    </style>\n\
</head>\n\
<body>\n\
    <h1>Docker Escape Lab</h1>\n\
    <p class="warning">⚠️ This container is intentionally vulnerable!</p>\n\
    \n\
    <div class="section">\n\
        <h2>Container Information</h2>\n\
        <pre>{{ info }}</pre>\n\
    </div>\n\
    \n\
    <div class="section">\n\
        <h2>Command Execution</h2>\n\
        <form method="POST" action="/exec">\n\
            <p>Run command inside container:</p>\n\
            <input type="text" name="cmd" size="50" value="id">\n\
            <input type="submit" value="Execute">\n\
        </form>\n\
    </div>\n\
    \n\
    <div class="section">\n\
        <h2>Escape Techniques to Try:</h2>\n\
        <ol>\n\
            <li><strong>Check if running as root:</strong> <code>id</code></li>\n\
            <li><strong>Check capabilities:</strong> <code>capsh --print</code></li>\n\
            <li><strong>Check for Docker socket:</strong> <code>ls -la /var/run/docker.sock</code></li>\n\
            <li><strong>Check mounts:</strong> <code>mount</code></li>\n\
            <li><strong>Check processes:</strong> <code>ps aux</code></li>\n\
            <li><strong>Check kernel version:</strong> <code>uname -a</code></li>\n\
            <li><strong>Try to access host filesystem:</strong> <code>ls -la /host</code></li>\n\
        </ol>\n\
    </div>\n\
    \n\
    <div class="section">\n\
        <h2>Vulnerabilities in this container:</h2>\n\
        <ul>\n\
            <li>Running with excessive privileges</li>\n\
            <li>Mounted Docker socket (if enabled)</li>\n\
            <li>Weak AppArmor/SELinux policies</li>\n\
            <li>Kernel vulnerabilities</li>\n\
            <li>Shared namespaces</li>\n\
        </ul>\n\
    </div>\n\
    \n\
    {% if result %}\n\
    <div class="section">\n\
        <h3>Command Output:</h3>\n\
        <pre>{{ result }}</pre>\n\
    </div>\n\
    {% endif %}\n\
</body>\n\
</html>\n\
"""\n\
\n\
def get_container_info():\n\
    info = ""\n\
    \n\
    # Get basic info\n\
    info += "=== User Info ===\\n"\n\
    info += subprocess.getoutput("id") + "\\n\\n"\n\
    \n\
    info += "=== Hostname ===\\n"\n\
    info += subprocess.getoutput("hostname") + "\\n\\n"\n\
    \n\
    info += "=== Kernel ===\\n"\n\
    info += subprocess.getoutput("uname -a") + "\\n\\n"\n\
    \n\
    info += "=== Capabilities ===\\n"\n\
    info += subprocess.getoutput("capsh --print 2>&1 | grep Current || echo Capability check failed") + "\\n\\n"\n\
    \n\
    info += "=== Docker Socket ===\\n"\n\
    if os.path.exists("/var/run/docker.sock"):\n\
        info += "Docker socket is mounted! (DANGEROUS)\\n"\n\
    else:\n\
        info += "Docker socket not found\\n"\n\
    \n\
    return info\n\
\n\
@app.route("/")\n\
def index():\n\
    info = get_container_info()\n\
    return render_template_string(HTML_TEMPLATE, info=info)\n\
\n\
@app.route("/exec", methods=["POST"])\n\
def execute():\n\
    cmd = request.form.get("cmd", "")\n\
    \n\
    try:\n\
        # DANGEROUS: Direct command execution\n\
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)\n\
        result = result.decode("utf-8")\n\
    except subprocess.TimeoutExpired:\n\
        result = "Command timed out"\n\
    except Exception as e:\n\
        result = f"Error: {str(e)}"\n\
    \n\
    info = get_container_info()\n\
    return render_template_string(HTML_TEMPLATE, info=info, result=result)\n\
\n\
if __name__ == "__main__":\n\
    # Running as root is dangerous!\n\
    app.run(host="0.0.0.0", port=8080, debug=True)\n\
' > app.py

# Create a script that demonstrates various escape techniques
RUN echo '#!/bin/bash\n\
echo "Docker Escape Techniques Demonstrator"\n\
echo "==================================="\n\
echo ""\n\
echo "1. Checking if we are in a container:"\n\
if [ -f /.dockerenv ]; then\n\
    echo "   [!] .dockerenv file found - we are in a container"\n\
fi\n\
echo ""\n\
echo "2. Checking user privileges:"\n\
id\n\
echo ""\n\
echo "3. Checking capabilities:"\n\
capsh --print 2>/dev/null | grep Current || echo "   [-] Cannot check capabilities"\n\
echo ""\n\
echo "4. Checking for Docker socket:"\n\
if [ -S /var/run/docker.sock ]; then\n\
    echo "   [!] Docker socket is mounted - can control host Docker!"\n\
else\n\
    echo "   [-] Docker socket not found"\n\
fi\n\
echo ""\n\
echo "5. Checking cgroups:"\n\
cat /proc/1/cgroup\n\
' > /app/check_escape.sh && chmod +x /app/check_escape.sh

# INTENTIONAL VULNERABILITIES:
# 1. Running as root (bad)
# 2. Installing sudo (bad)
# 3. Excessive capabilities will be added via docker-compose
# 4. Docker socket can be mounted via docker-compose

EXPOSE 8080

# Run as root (intentionally vulnerable)
USER root

CMD ["python3", "/app/app.py"] 
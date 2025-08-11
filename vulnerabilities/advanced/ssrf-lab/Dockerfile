FROM python:3.9-slim

WORKDIR /app

# Install dependencies
RUN pip install flask requests pillow

# Create the vulnerable SSRF application
RUN echo 'from flask import Flask, request, render_template_string\n\
import requests\n\
from PIL import Image\n\
from io import BytesIO\n\
import base64\n\
\n\
app = Flask(__name__)\n\
\n\
HTML_TEMPLATE = """\n\
<!DOCTYPE html>\n\
<html>\n\
<head>\n\
    <title>SSRF Lab</title>\n\
    <style>\n\
        body { font-family: Arial, sans-serif; margin: 40px; }\n\
        .container { max-width: 800px; margin: auto; }\n\
        input[type="text"] { width: 500px; padding: 10px; }\n\
        button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }\n\
        .result { margin-top: 20px; padding: 20px; background: #f8f9fa; border: 1px solid #dee2e6; }\n\
        .error { color: red; }\n\
        .warning { background: #fff3cd; border: 1px solid #ffeeba; padding: 10px; margin: 10px 0; }\n\
    </style>\n\
</head>\n\
<body>\n\
    <div class="container">\n\
        <h1>SSRF (Server-Side Request Forgery) Lab</h1>\n\
        <div class="warning">\n\
            <strong>Warning:</strong> This application is intentionally vulnerable to SSRF attacks for educational purposes.\n\
        </div>\n\
        \n\
        <h2>URL Fetcher</h2>\n\
        <form method="POST" action="/fetch">\n\
            <input type="text" name="url" placeholder="Enter URL to fetch (e.g., http://example.com)" required>\n\
            <button type="submit">Fetch URL</button>\n\
        </form>\n\
        \n\
        <h2>Image Converter</h2>\n\
        <form method="POST" action="/convert">\n\
            <input type="text" name="image_url" placeholder="Enter image URL to convert" required>\n\
            <button type="submit">Convert to Base64</button>\n\
        </form>\n\
        \n\
        <h2>Try These (SSRF Examples):</h2>\n\
        <ul>\n\
            <li>http://localhost:80</li>\n\
            <li>http://127.0.0.1:22</li>\n\
            <li>http://169.254.169.254/latest/meta-data/</li>\n\
            <li>file:///etc/passwd</li>\n\
            <li>http://internal-service.local</li>\n\
        </ul>\n\
        \n\
        {% if result %}\n\
        <div class="result">\n\
            <h3>Result:</h3>\n\
            <pre>{{ result }}</pre>\n\
        </div>\n\
        {% endif %}\n\
        \n\
        {% if error %}\n\
        <div class="error">\n\
            <h3>Error:</h3>\n\
            <p>{{ error }}</p>\n\
        </div>\n\
        {% endif %}\n\
    </div>\n\
</body>\n\
</html>\n\
"""\n\
\n\
@app.route("/")\n\
def index():\n\
    return render_template_string(HTML_TEMPLATE)\n\
\n\
@app.route("/fetch", methods=["POST"])\n\
def fetch_url():\n\
    url = request.form.get("url")\n\
    \n\
    try:\n\
        # Vulnerable to SSRF - no URL validation\n\
        response = requests.get(url, timeout=5)\n\
        result = f"Status Code: {response.status_code}\\n\\nHeaders:\\n"\n\
        for header, value in response.headers.items():\n\
            result += f"{header}: {value}\\n"\n\
        result += f"\\nContent (first 1000 chars):\\n{response.text[:1000]}"\n\
        return render_template_string(HTML_TEMPLATE, result=result)\n\
    except Exception as e:\n\
        return render_template_string(HTML_TEMPLATE, error=str(e))\n\
\n\
@app.route("/convert", methods=["POST"])\n\
def convert_image():\n\
    image_url = request.form.get("image_url")\n\
    \n\
    try:\n\
        # Vulnerable to SSRF - fetches any URL as image\n\
        response = requests.get(image_url, timeout=5)\n\
        img = Image.open(BytesIO(response.content))\n\
        \n\
        # Convert to base64\n\
        buffered = BytesIO()\n\
        img.save(buffered, format="PNG")\n\
        img_base64 = base64.b64encode(buffered.getvalue()).decode()\n\
        \n\
        result = f"Image converted successfully!\\n\\nBase64 (first 200 chars):\\n{img_base64[:200]}..."\n\
        return render_template_string(HTML_TEMPLATE, result=result)\n\
    except Exception as e:\n\
        return render_template_string(HTML_TEMPLATE, error=str(e))\n\
\n\
if __name__ == "__main__":\n\
    app.run(host="0.0.0.0", port=5000, debug=True)\n\
' > app.py

EXPOSE 5000

CMD ["python", "app.py"] 
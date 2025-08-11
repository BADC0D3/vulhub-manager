FROM python:3.9-slim

WORKDIR /app

# Install dependencies
RUN pip install flask lxml

# Create vulnerable XXE application
RUN echo 'from flask import Flask, request, render_template_string\n\
import lxml.etree as ET\n\
import os\n\
\n\
app = Flask(__name__)\n\
\n\
TEMPLATE = """\n\
<!DOCTYPE html>\n\
<html>\n\
<head>\n\
    <title>XXE Lab - XML External Entity Injection</title>\n\
    <style>\n\
        body { font-family: Arial, sans-serif; margin: 40px; }\n\
        textarea { width: 100%; font-family: monospace; }\n\
        .examples { background: #f0f0f0; padding: 10px; margin: 10px 0; }\n\
        .warning { color: red; font-weight: bold; }\n\
        pre { background: #f5f5f5; padding: 10px; overflow: auto; }\n\
    </style>\n\
</head>\n\
<body>\n\
    <h1>XXE Lab - XML External Entity Injection</h1>\n\
    <p class="warning">⚠️ This application is intentionally vulnerable to XXE attacks!</p>\n\
    \n\
    <form method="POST">\n\
        <h2>XML Input:</h2>\n\
        <textarea name="xml" rows="15" cols="80"><?xml version="1.0"?>\n\
<!DOCTYPE data [\n\
  <!ENTITY file SYSTEM "file:///etc/passwd">\n\
]>\n\
<data>\n\
    <user>admin</user>\n\
    <pass>password</pass>\n\
    <secret>&file;</secret>\n\
</data></textarea><br><br>\n\
        <input type="submit" value="Parse XML">\n\
    </form>\n\
    \n\
    <div class="examples">\n\
        <h3>XXE Attack Examples:</h3>\n\
        <p><strong>1. File Disclosure:</strong></p>\n\
        <pre>&lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;]&gt;</pre>\n\
        \n\
        <p><strong>2. SSRF Attack:</strong></p>\n\
        <pre>&lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM "http://internal-server/"&gt;]&gt;</pre>\n\
        \n\
        <p><strong>3. Billion Laughs (DoS):</strong></p>\n\
        <pre>&lt;!DOCTYPE lolz [\n\
  &lt;!ENTITY lol "lol"&gt;\n\
  &lt;!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"&gt;\n\
  &lt;!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"&gt;\n\
]&gt;</pre>\n\
    </div>\n\
    \n\
    {% if result %}\n\
    <h2>Result:</h2>\n\
    <pre>{{ result }}</pre>\n\
    {% endif %}\n\
    \n\
    {% if error %}\n\
    <h2 style="color: red;">Error:</h2>\n\
    <pre>{{ error }}</pre>\n\
    {% endif %}\n\
</body>\n\
</html>\n\
"""\n\
\n\
# Create a test file for XXE to read\n\
with open("/tmp/secret.txt", "w") as f:\n\
    f.write("This is a secret file that should not be accessible!")\n\
\n\
@app.route("/", methods=["GET", "POST"])\n\
def index():\n\
    result = None\n\
    error = None\n\
    \n\
    if request.method == "POST":\n\
        xml_data = request.form.get("xml", "")\n\
        try:\n\
            # Vulnerable XXE parsing - allows external entities\n\
            parser = ET.XMLParser(\n\
                resolve_entities=True,  # This enables XXE!\n\
                no_network=False,       # Allows network access\n\
                dtd_validation=False,   # No DTD validation\n\
                load_dtd=True          # Load external DTDs\n\
            )\n\
            doc = ET.fromstring(xml_data.encode(), parser)\n\
            \n\
            # Process and display the parsed XML\n\
            result = ET.tostring(doc, pretty_print=True, encoding="unicode")\n\
            \n\
        except ET.XMLSyntaxError as e:\n\
            error = f"XML Syntax Error: {str(e)}"\n\
        except Exception as e:\n\
            error = f"Error: {str(e)}"\n\
    \n\
    return render_template_string(TEMPLATE, result=result, error=error)\n\
\n\
# Additional vulnerable endpoint for blind XXE\n\
@app.route("/parse", methods=["POST"])\n\
def parse_xml():\n\
    xml_data = request.data\n\
    try:\n\
        parser = ET.XMLParser(resolve_entities=True)\n\
        doc = ET.fromstring(xml_data, parser)\n\
        return "XML parsed successfully", 200\n\
    except Exception as e:\n\
        return f"Error: {str(e)}", 400\n\
\n\
if __name__ == "__main__":\n\
    app.run(host="0.0.0.0", port=8080, debug=True)\n\
' > app.py

EXPOSE 8080

CMD ["python", "app.py"] 
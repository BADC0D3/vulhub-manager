FROM python:3.9-slim

WORKDIR /app

# Install dependencies
RUN pip install flask lxml

# Create vulnerable XXE application
COPY <<EOF app.py
from flask import Flask, request, render_template_string
import lxml.etree as ET

app = Flask(__name__)

TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>XXE Lab</title></head>
<body>
    <h1>XML Parser - XXE Vulnerable</h1>
    <form method="POST">
        <textarea name="xml" rows="10" cols="50">
<?xml version="1.0"?>
<data>
    <user>admin</user>
    <pass>password</pass>
</data>
        </textarea><br>
        <input type="submit" value="Parse XML">
    </form>
    {% if result %}
    <h2>Result:</h2>
    <pre>{{ result }}</pre>
    {% endif %}
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        xml_data = request.form.get('xml', '')
        try:
            # Vulnerable XXE parsing
            parser = ET.XMLParser(resolve_entities=True)
            doc = ET.fromstring(xml_data.encode(), parser)
            result = ET.tostring(doc, pretty_print=True).decode()
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
EOF

EXPOSE 8080

CMD ["python", "app.py"] 
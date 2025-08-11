FROM node:14

WORKDIR /app

# Create package.json
RUN echo '{\n\
  "name": "express-vulnerable",\n\
  "version": "1.0.0",\n\
  "description": "Vulnerable Express.js application",\n\
  "main": "server.js",\n\
  "scripts": {\n\
    "start": "node server.js"\n\
  },\n\
  "dependencies": {\n\
    "express": "^4.17.1",\n\
    "body-parser": "^1.19.0",\n\
    "ejs": "^3.1.5",\n\
    "sqlite3": "^5.0.2"\n\
  }\n\
}' > package.json

# Install dependencies
RUN npm install

# Create vulnerable Express app
RUN echo 'const express = require("express");\n\
const bodyParser = require("body-parser");\n\
const sqlite3 = require("sqlite3").verbose();\n\
const { exec } = require("child_process");\n\
const path = require("path");\n\
\n\
const app = express();\n\
const port = 3000;\n\
\n\
app.use(bodyParser.urlencoded({ extended: true }));\n\
app.use(bodyParser.json());\n\
app.set("view engine", "ejs");\n\
\n\
// Initialize database\n\
const db = new sqlite3.Database(":memory:");\n\
db.serialize(() => {\n\
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");\n\
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", ["admin", "admin123"]);\n\
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", ["user", "user123"]);\n\
});\n\
\n\
// Home route\n\
app.get("/", (req, res) => {\n\
  res.send("<h1>Vulnerable Express App</h1><p>Try /search?username=admin or /execute?cmd=ls</p>");\n\
});\n\
\n\
// SQL Injection vulnerability\n\
app.get("/search", (req, res) => {\n\
  const username = req.query.username;\n\
  // Vulnerable to SQL injection\n\
  const query = `SELECT * FROM users WHERE username = "${username}"`;\n\
  \n\
  db.all(query, [], (err, rows) => {\n\
    if (err) {\n\
      res.status(500).json({ error: err.message });\n\
      return;\n\
    }\n\
    res.json({ users: rows });\n\
  });\n\
});\n\
\n\
// Command Injection vulnerability\n\
app.get("/execute", (req, res) => {\n\
  const cmd = req.query.cmd;\n\
  // Vulnerable to command injection\n\
  exec(cmd, (error, stdout, stderr) => {\n\
    if (error) {\n\
      res.status(500).send(`Error: ${error.message}`);\n\
      return;\n\
    }\n\
    res.send(`<pre>${stdout}</pre>`);\n\
  });\n\
});\n\
\n\
// Path Traversal vulnerability\n\
app.get("/file", (req, res) => {\n\
  const filename = req.query.name;\n\
  // Vulnerable to path traversal\n\
  const filepath = path.join(__dirname, filename);\n\
  res.sendFile(filepath);\n\
});\n\
\n\
// XSS vulnerability\n\
app.post("/comment", (req, res) => {\n\
  const comment = req.body.comment;\n\
  // Vulnerable to XSS - no sanitization\n\
  res.send(`<h2>Your comment:</h2><p>${comment}</p>`);\n\
});\n\
\n\
app.listen(port, "0.0.0.0", () => {\n\
  console.log(`Vulnerable Express app listening at http://0.0.0.0:${port}`);\n\
});' > server.js

# Create views directory for EJS templates
RUN mkdir views

EXPOSE 3000

CMD ["npm", "start"] 
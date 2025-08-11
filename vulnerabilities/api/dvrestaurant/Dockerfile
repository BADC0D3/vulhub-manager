FROM node:14

WORKDIR /app

# Create package.json
RUN echo '{\n\
  "name": "dvrestaurant",\n\
  "version": "1.0.0",\n\
  "description": "Damn Vulnerable Restaurant API",\n\
  "main": "server.js",\n\
  "scripts": {\n\
    "start": "node server.js"\n\
  },\n\
  "dependencies": {\n\
    "express": "^4.17.1",\n\
    "body-parser": "^1.19.0",\n\
    "jsonwebtoken": "^8.5.1",\n\
    "bcrypt": "^5.0.1",\n\
    "sqlite3": "^5.0.2",\n\
    "cors": "^2.8.5"\n\
  }\n\
}' > package.json

# Install dependencies
RUN npm install

# Create the vulnerable restaurant API
RUN echo 'const express = require("express");\n\
const bodyParser = require("body-parser");\n\
const jwt = require("jsonwebtoken");\n\
const bcrypt = require("bcrypt");\n\
const sqlite3 = require("sqlite3").verbose();\n\
const cors = require("cors");\n\
\n\
const app = express();\n\
const port = 8080;\n\
const JWT_SECRET = process.env.JWT_SECRET || "insecure-secret";\n\
\n\
app.use(cors());\n\
app.use(bodyParser.json());\n\
app.use(bodyParser.urlencoded({ extended: true }));\n\
\n\
// Initialize database\n\
const db = new sqlite3.Database(":memory:");\n\
db.serialize(() => {\n\
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)");\n\
  db.run("CREATE TABLE menu_items (id INTEGER PRIMARY KEY, name TEXT, price REAL, description TEXT)");\n\
  db.run("CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, items TEXT, total REAL, status TEXT)");\n\
  \n\
  // Add sample data\n\
  const adminPassword = bcrypt.hashSync("admin123", 10);\n\
  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ["admin", adminPassword, "admin"]);\n\
  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ["user", bcrypt.hashSync("user123", 10), "customer"]);\n\
  \n\
  db.run("INSERT INTO menu_items (name, price, description) VALUES (?, ?, ?)", ["Pizza", 12.99, "Delicious cheese pizza"]);\n\
  db.run("INSERT INTO menu_items (name, price, description) VALUES (?, ?, ?)", ["Burger", 8.99, "Classic beef burger"]);\n\
  db.run("INSERT INTO menu_items (name, price, description) VALUES (?, ?, ?)", ["Salad", 6.99, "Fresh garden salad"]);\n\
});\n\
\n\
// Home route\n\
app.get("/", (req, res) => {\n\
  res.json({\n\
    message: "Welcome to DVRestaurant API",\n\
    endpoints: [\n\
      "POST /login - Login with username/password",\n\
      "GET /menu - Get menu items",\n\
      "GET /menu/search?name=pizza - Search menu (vulnerable to SQL injection)",\n\
      "POST /order - Place an order (vulnerable to NoSQL injection)",\n\
      "GET /user/:id - Get user info (vulnerable to IDOR)",\n\
      "POST /admin/menu - Add menu item (broken auth)"\n\
    ]\n\
  });\n\
});\n\
\n\
// Vulnerable login - weak JWT implementation\n\
app.post("/login", (req, res) => {\n\
  const { username, password } = req.body;\n\
  \n\
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {\n\
    if (err || !user) {\n\
      return res.status(401).json({ error: "Invalid credentials" });\n\
    }\n\
    \n\
    bcrypt.compare(password, user.password, (err, match) => {\n\
      if (!match) {\n\
        return res.status(401).json({ error: "Invalid credentials" });\n\
      }\n\
      \n\
      // Vulnerable: JWT secret is predictable and includes sensitive data\n\
      const token = jwt.sign({\n\
        id: user.id,\n\
        username: user.username,\n\
        role: user.role,\n\
        password: user.password // Should never include password!\n\
      }, JWT_SECRET, { algorithm: "HS256" });\n\
      \n\
      res.json({ token, role: user.role });\n\
    });\n\
  });\n\
});\n\
\n\
// SQL Injection vulnerability\n\
app.get("/menu/search", (req, res) => {\n\
  const name = req.query.name || "";\n\
  // Vulnerable to SQL injection\n\
  const query = `SELECT * FROM menu_items WHERE name LIKE "%${name}%"`;\n\
  \n\
  db.all(query, [], (err, items) => {\n\
    if (err) {\n\
      res.status(500).json({ error: err.message });\n\
      return;\n\
    }\n\
    res.json({ items });\n\
  });\n\
});\n\
\n\
// Get all menu items\n\
app.get("/menu", (req, res) => {\n\
  db.all("SELECT * FROM menu_items", [], (err, items) => {\n\
    if (err) {\n\
      res.status(500).json({ error: err.message });\n\
      return;\n\
    }\n\
    res.json({ items });\n\
  });\n\
});\n\
\n\
// IDOR vulnerability - access any user data\n\
app.get("/user/:id", (req, res) => {\n\
  const userId = req.params.id;\n\
  // No authorization check - IDOR vulnerability\n\
  db.get("SELECT * FROM users WHERE id = ?", [userId], (err, user) => {\n\
    if (err || !user) {\n\
      res.status(404).json({ error: "User not found" });\n\
      return;\n\
    }\n\
    res.json({ user });\n\
  });\n\
});\n\
\n\
// Broken authentication - anyone can add menu items\n\
app.post("/admin/menu", (req, res) => {\n\
  const { name, price, description } = req.body;\n\
  // Missing authorization check!\n\
  db.run("INSERT INTO menu_items (name, price, description) VALUES (?, ?, ?)",\n\
    [name, price, description],\n\
    function(err) {\n\
      if (err) {\n\
        res.status(500).json({ error: err.message });\n\
        return;\n\
      }\n\
      res.json({ id: this.lastID, message: "Menu item added" });\n\
    }\n\
  );\n\
});\n\
\n\
// Mass assignment vulnerability\n\
app.post("/order", (req, res) => {\n\
  // Vulnerable: accepts any fields from request body\n\
  const orderData = req.body;\n\
  const query = `INSERT INTO orders (user_id, items, total, status) VALUES (?, ?, ?, ?)`;\n\
  \n\
  db.run(query, [\n\
    orderData.user_id || 1,\n\
    JSON.stringify(orderData.items || []),\n\
    orderData.total || 0,\n\
    orderData.status || "pending" // User can set their own status!\n\
  ], function(err) {\n\
    if (err) {\n\
      res.status(500).json({ error: err.message });\n\
      return;\n\
    }\n\
    res.json({ id: this.lastID, message: "Order placed", status: orderData.status });\n\
  });\n\
});\n\
\n\
app.listen(port, "0.0.0.0", () => {\n\
  console.log(`DVRestaurant API listening at http://0.0.0.0:${port}`);\n\
  console.log("Default credentials: admin/admin123 or user/user123");\n\
});' > server.js

EXPOSE 8080

CMD ["npm", "start"] 
FROM php:7.4-apache

WORKDIR /var/www/html

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Create vulnerable PHP application
RUN echo '<?php\n\
// PHP Deserialization Lab\n\
\n\
class User {\n\
    public $username;\n\
    public $isAdmin = false;\n\
    \n\
    public function __construct($username) {\n\
        $this->username = $username;\n\
    }\n\
    \n\
    public function __toString() {\n\
        return $this->username . " (Admin: " . ($this->isAdmin ? "Yes" : "No") . ")";\n\
    }\n\
}\n\
\n\
class FileManager {\n\
    public $filename;\n\
    \n\
    public function __construct($filename) {\n\
        $this->filename = $filename;\n\
    }\n\
    \n\
    // Dangerous magic method - gets called on destruction\n\
    public function __destruct() {\n\
        if(file_exists($this->filename)) {\n\
            echo "<pre>File contents:\\n";\n\
            echo htmlspecialchars(file_get_contents($this->filename));\n\
            echo "</pre>";\n\
        }\n\
    }\n\
}\n\
\n\
class Logger {\n\
    public $logFile;\n\
    public $logData;\n\
    \n\
    public function __construct($logFile = "/tmp/app.log") {\n\
        $this->logFile = $logFile;\n\
    }\n\
    \n\
    // Another dangerous magic method\n\
    public function __wakeup() {\n\
        if($this->logData) {\n\
            file_put_contents($this->logFile, $this->logData);\n\
        }\n\
    }\n\
}\n\
\n\
class CommandExecutor {\n\
    public $command;\n\
    \n\
    // Extremely dangerous - executes command on destruction\n\
    public function __destruct() {\n\
        if($this->command) {\n\
            echo "<pre>Command output:\\n";\n\
            echo htmlspecialchars(shell_exec($this->command));\n\
            echo "</pre>";\n\
        }\n\
    }\n\
}\n\
\n\
if(isset($_POST["data"])) {\n\
    $data = $_POST["data"];\n\
    \n\
    try {\n\
        // VULNERABLE: Unserializing user input!\n\
        $object = unserialize(base64_decode($data));\n\
        echo "<div class=\"success\">Object unserialized successfully!</div>";\n\
        echo "<pre>Object type: " . get_class($object) . "\\n";\n\
        echo "Object data: " . print_r($object, true) . "</pre>";\n\
    } catch(Exception $e) {\n\
        echo "<div class=\"error\">Error: " . htmlspecialchars($e->getMessage()) . "</div>";\n\
    }\n\
}\n\
\n\
// Helper to generate payloads\n\
if(isset($_GET["generate"])) {\n\
    $type = $_GET["generate"];\n\
    \n\
    switch($type) {\n\
        case "user":\n\
            $user = new User("admin");\n\
            $user->isAdmin = true;\n\
            $payload = base64_encode(serialize($user));\n\
            break;\n\
            \n\
        case "file":\n\
            $fm = new FileManager("/etc/passwd");\n\
            $payload = base64_encode(serialize($fm));\n\
            break;\n\
            \n\
        case "cmd":\n\
            $cmd = new CommandExecutor();\n\
            $cmd->command = "id";\n\
            $payload = base64_encode(serialize($cmd));\n\
            break;\n\
            \n\
        default:\n\
            $payload = "";\n\
    }\n\
    \n\
    echo json_encode(["payload" => $payload]);\n\
    exit;\n\
}\n\
?>\n\
<!DOCTYPE html>\n\
<html>\n\
<head>\n\
    <title>PHP Deserialization Lab</title>\n\
    <style>\n\
        body { font-family: Arial, sans-serif; margin: 40px; }\n\
        textarea { width: 100%; font-family: monospace; }\n\
        .section { margin: 20px 0; padding: 20px; background: #f5f5f5; }\n\
        .success { color: green; padding: 10px; background: #d4ffd4; }\n\
        .error { color: red; padding: 10px; background: #ffd4d4; }\n\
        .warning { color: red; font-weight: bold; }\n\
        pre { background: #e0e0e0; padding: 10px; overflow: auto; }\n\
        button { margin: 5px; padding: 10px; }\n\
    </style>\n\
</head>\n\
<body>\n\
    <h1>PHP Deserialization Lab</h1>\n\
    <p class="warning">⚠️ This application is intentionally vulnerable to PHP object injection!</p>\n\
    \n\
    <div class="section">\n\
        <h2>Unserialize Data</h2>\n\
        <form method="POST">\n\
            <p>Base64 encoded serialized PHP object:</p>\n\
            <textarea name="data" rows="5" cols="80" id="payload">Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjU6ImFkbWluIjtzOjc6ImlzQWRtaW4iO2I6MTt9</textarea><br>\n\
            <input type="submit" value="Unserialize">\n\
        </form>\n\
        \n\
        <h3>Generate Test Payloads:</h3>\n\
        <button onclick="generatePayload(\'user\')">User Object (Safe)</button>\n\
        <button onclick="generatePayload(\'file\')">File Reader (/etc/passwd)</button>\n\
        <button onclick="generatePayload(\'cmd\')">Command Executor (id)</button>\n\
    </div>\n\
    \n\
    <div class="section">\n\
        <h3>Available Classes:</h3>\n\
        <ul>\n\
            <li><strong>User</strong> - Basic user class (safe)</li>\n\
            <li><strong>FileManager</strong> - Reads files on __destruct()</li>\n\
            <li><strong>Logger</strong> - Writes files on __wakeup()</li>\n\
            <li><strong>CommandExecutor</strong> - Executes commands on __destruct()</li>\n\
        </ul>\n\
        \n\
        <h3>Example Exploit:</h3>\n\
        <pre><?php\n\
// Create malicious object\n\
$cmd = new CommandExecutor();\n\
$cmd->command = "cat /etc/passwd";\n\
\n\
// Serialize and encode\n\
$payload = base64_encode(serialize($cmd));\n\
echo $payload;\n\
?></pre>\n\
    </div>\n\
    \n\
    <script>\n\
    function generatePayload(type) {\n\
        fetch("?generate=" + type)\n\
            .then(response => response.json())\n\
            .then(data => {\n\
                document.getElementById("payload").value = data.payload;\n\
            });\n\
    }\n\
    </script>\n\
</body>\n\
</html>' > index.php

# Create .htaccess for pretty URLs
RUN echo 'Options +FollowSymLinks\n\
RewriteEngine On\n\
RewriteCond %{REQUEST_FILENAME} !-f\n\
RewriteCond %{REQUEST_FILENAME} !-d\n\
RewriteRule ^(.*)$ index.php [QSA,L]' > .htaccess

EXPOSE 80 
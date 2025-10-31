<?php
session_start();

// Weak session check
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

// VULNERABILITY: Directory traversal - read any file
$file_content = '';
if (isset($_GET['file'])) {
    $file_path = $_GET['file'];
    // No path sanitization - directory traversal vulnerability
    if (file_exists($file_path)) {
        $file_content = file_get_contents($file_path);
    } else {
        $file_content = "File not found: " . $file_path;
    }
}

// VULNERABILITY: Command injection
$ping_result = '';
if (isset($_GET['ping'])) {
    $host = $_GET['ping'];
    // No input sanitization - command injection vulnerability
    $ping_result = shell_exec("ping -c 3 " . $host);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - MedCare Health System</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 24px; }
        .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
        .card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .setting-group {
            padding: 20px;
            background: #f8f9fa;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .setting-group h3 {
            margin-bottom: 10px;
            color: #333;
        }
        input[type="text"] {
            width: 100%;
            padding: 10px;
            border: 2px solid #e1e8ed;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        .btn {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
        }
        .btn:hover { background: #764ba2; }
        pre {
            background: #2d2d30;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
        }
        .nav a {
            display: inline-block;
            margin-right: 15px;
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }
        .info-box {
            background: #fff3cd;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            border-left: 4px solid #ffc107;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚕️ MedCare Health System</h1>
        <div style="font-size: 14px;">
            Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?> 
            (<?php echo htmlspecialchars($_SESSION['role']); ?>) |
            <a href="logout.php" style="color: white;">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="card">
            <div class="nav">
                <a href="dashboard.php">← Back to Dashboard</a>
            </div>
            
            <h2>System Settings & Tools</h2>
            
            <div class="setting-group">
                <h3>🔧 Debug File Viewer</h3>
                <p style="color: #666; margin-bottom: 10px;">View system configuration files for debugging</p>
                <form method="GET" action="">
                    <input type="text" name="file" placeholder="Enter file path (e.g., .env, /etc/passwd)" 
                           value="<?php echo isset($_GET['file']) ? htmlspecialchars($_GET['file']) : ''; ?>">
                    <button type="submit" class="btn">View File</button>
                </form>
                <?php if ($file_content): ?>
                    <pre><?php echo htmlspecialchars($file_content); ?></pre>
                <?php endif; ?>
                <div class="info-box">
                    <strong>Quick Links:</strong><br>
                    <a href="?file=.env">View .env file</a> | 
                    <a href="?file=/etc/passwd">View /etc/passwd</a> |
                    <a href="?file=uploads/upload_log.txt">View upload logs</a>
                </div>
            </div>
            
            <div class="setting-group">
                <h3>🌐 Network Diagnostics</h3>
                <p style="color: #666; margin-bottom: 10px;">Test network connectivity</p>
                <form method="GET" action="">
                    <input type="text" name="ping" placeholder="Enter hostname or IP to ping" 
                           value="<?php echo isset($_GET['ping']) ? htmlspecialchars($_GET['ping']) : ''; ?>">
                    <button type="submit" class="btn">Ping Host</button>
                </form>
                <?php if ($ping_result): ?>
                    <pre><?php echo htmlspecialchars($ping_result); ?></pre>
                <?php endif; ?>
            </div>
            
            <div class="setting-group">
                <h3>📊 System Information</h3>
                <div style="margin-top: 10px;">
                    <strong>PHP Version:</strong> <?php echo phpversion(); ?><br>
                    <strong>Server Software:</strong> <?php echo $_SERVER['SERVER_SOFTWARE']; ?><br>
                    <strong>Document Root:</strong> <?php echo $_SERVER['DOCUMENT_ROOT']; ?><br>
                    <strong>Server Name:</strong> <?php echo $_SERVER['SERVER_NAME']; ?><br>
                    <strong>Server IP:</strong> <?php echo $_SERVER['SERVER_ADDR']; ?><br>
                    <strong>Session ID:</strong> <?php echo session_id(); ?><br>
                    <strong>Current User:</strong> <?php echo get_current_user(); ?><br>
                </div>
                <div style="margin-top: 15px;">
                    <a href="?phpinfo=1" class="btn">View Full PHP Info</a>
                </div>
                <?php if (isset($_GET['phpinfo'])): phpinfo(); endif; ?>
            </div>
            
            <div class="setting-group">
                <h3>🗄️ Database Configuration</h3>
                <div style="margin-top: 10px;">
                    <strong>Database Host:</strong> <?php echo getenv('DB_HOST'); ?><br>
                    <strong>Database Name:</strong> <?php echo getenv('DB_NAME'); ?><br>
                    <strong>Database User:</strong> <?php echo getenv('DB_USER'); ?><br>
                    <strong>Database Password:</strong> <?php echo str_repeat('*', strlen(getenv('DB_PASS'))); ?>
                    <a href="#" onclick="alert('Password: <?php echo getenv('DB_PASS'); ?>'); return false;" style="color: #667eea; margin-left: 10px;">Show</a>
                </div>
            </div>
            
            <div class="setting-group">
                <h3>🔐 Session Management</h3>
                <div style="margin-top: 10px;">
                    <strong>User ID:</strong> <?php echo $_SESSION['user_id']; ?><br>
                    <strong>Username:</strong> <?php echo $_SESSION['username']; ?><br>
                    <strong>Role:</strong> <?php echo $_SESSION['role']; ?><br>
                    <strong>Session Data:</strong>
                    <pre><?php print_r($_SESSION); ?></pre>
                </div>
            </div>
            
        </div>
    </div>
</body>
</html>


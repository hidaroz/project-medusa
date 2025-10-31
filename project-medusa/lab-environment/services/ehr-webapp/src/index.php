<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MedCare Health System - Patient Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 400px;
            width: 90%;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
            color: #667eea;
            font-size: 32px;
            font-weight: bold;
        }
        .logo::before {
            content: "⚕️ ";
        }
        h2 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e8ed;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        .links {
            text-align: center;
            margin-top: 20px;
            font-size: 14px;
        }
        .links a {
            color: #667eea;
            text-decoration: none;
        }
        .links a:hover {
            text-decoration: underline;
        }
        .info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            font-size: 12px;
            color: #666;
        }
        .info strong {
            color: #333;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #f5c6cb;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: #999;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">MedCare Health</div>
        <h2>Patient Portal Login</h2>
        
        <?php
        // Display PHP version (information disclosure vulnerability)
        if (isset($_GET['info'])) {
            phpinfo();
            exit;
        }
        
        // Intentionally vulnerable login check
        if (isset($_POST['username']) && isset($_POST['password'])) {
            // SQL Injection vulnerability - NO input sanitization
            $username = $_POST['username'];
            $password = $_POST['password'];
            
            // Display verbose error (information disclosure)
            try {
                $conn = new mysqli(
                    getenv('DB_HOST'),
                    getenv('DB_USER'),
                    getenv('DB_PASS'),
                    getenv('DB_NAME')
                );
                
                if ($conn->connect_error) {
                    echo "<div class='error'>Database Connection Error: " . $conn->connect_error . "</div>";
                } else {
                    // INTENTIONAL SQL INJECTION VULNERABILITY
                    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
                    echo "<!-- Debug Query: $query -->";
                    
                    $result = $conn->query($query);
                    
                    if ($result && $result->num_rows > 0) {
                        $user = $result->fetch_assoc();
                        session_start();
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['username'] = $user['username'];
                        $_SESSION['role'] = $user['role'];
                        header("Location: dashboard.php");
                        exit;
                    } else {
                        echo "<div class='error'>Invalid credentials. Please try again.</div>";
                    }
                    $conn->close();
                }
            } catch (Exception $e) {
                // Verbose error messages (information disclosure)
                echo "<div class='error'>Error: " . $e->getMessage() . "<br>";
                echo "File: " . $e->getFile() . "<br>";
                echo "Line: " . $e->getLine() . "</div>";
            }
        }
        ?>
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
        
        <div class="links">
            <a href="register.php">Create New Account</a> | 
            <a href="search.php">Search Patients</a> |
            <a href="api.php">API Docs</a>
        </div>
        
        <div class="info">
            <strong>Demo Credentials:</strong><br>
            Patient: patient1 / patient123<br>
            Doctor: doctor1 / doctor123<br>
            Admin: admin / admin123
        </div>
        
        <div class="footer">
            MedCare Health System v2.1.0<br>
            © 2024 - For Testing Purposes Only
            <!-- Debug: Add ?info=1 to see phpinfo() -->
        </div>
    </div>
</body>
</html>


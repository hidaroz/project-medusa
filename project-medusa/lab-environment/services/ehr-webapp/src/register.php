<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - MedCare Health System</title>
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
            max-width: 500px;
            width: 90%;
        }
        h2 { text-align: center; color: #333; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #555; font-weight: 500; }
        input[type="text"],
        input[type="password"],
        input[type="email"],
        select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e8ed;
            border-radius: 5px;
            font-size: 14px;
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
        }
        .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .back-link { display: inline-block; margin-bottom: 20px; color: #667eea; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <a href="index.php" class="back-link">← Back to Login</a>
        <h2>Create New Account</h2>
        
        <?php
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $username = $_POST['username'];
            $password = $_POST['password'];
            $email = $_POST['email'];
            $role = $_POST['role'];
            
            try {
                $conn = new mysqli(
                    getenv('DB_HOST'),
                    getenv('DB_USER'),
                    getenv('DB_PASS'),
                    getenv('DB_NAME')
                );
                
                if ($conn->connect_error) {
                    echo "<div class='error'>Database error: " . $conn->connect_error . "</div>";
                } else {
                    // INTENTIONAL VULNERABILITY: No password hashing
                    // INTENTIONAL VULNERABILITY: SQL injection in INSERT
                    $query = "INSERT INTO users (username, password, email, role, created_at) 
                             VALUES ('$username', '$password', '$email', '$role', NOW())";
                    
                    echo "<!-- Debug Query: $query -->";
                    
                    if ($conn->query($query)) {
                        echo "<div class='success'>Account created successfully! You can now <a href='index.php'>login</a>.</div>";
                    } else {
                        // Verbose error (information disclosure)
                        echo "<div class='error'>Error: " . $conn->error . "<br>Query: " . htmlspecialchars($query) . "</div>";
                    }
                    $conn->close();
                }
            } catch (Exception $e) {
                echo "<div class='error'>" . $e->getMessage() . "</div>";
            }
        }
        ?>
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <label for="role">Role</label>
                <select id="role" name="role" required>
                    <option value="patient">Patient</option>
                    <option value="doctor">Doctor</option>
                    <option value="nurse">Nurse</option>
                    <option value="admin">Administrator</option>
                </select>
            </div>
            <button type="submit" class="btn">Create Account</button>
        </form>
        
        <div style="margin-top: 20px; text-align: center; font-size: 14px; color: #666;">
            Already have an account? <a href="index.php" style="color: #667eea;">Login here</a>
        </div>
    </div>
</body>
</html>


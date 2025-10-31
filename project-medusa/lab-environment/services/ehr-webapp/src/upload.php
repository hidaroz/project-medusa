<?php
session_start();

// Weak authentication check
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$upload_message = '';
$upload_error = '';

// INTENTIONAL VULNERABILITY: Insecure file upload - no validation
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['file'])) {
    $target_dir = "uploads/";
    
    // Create uploads directory if it doesn't exist
    if (!is_dir($target_dir)) {
        mkdir($target_dir, 0777, true);
    }
    
    // VULNERABILITY: No file type validation
    // VULNERABILITY: No file size validation
    // VULNERABILITY: Direct use of user-supplied filename
    $target_file = $target_dir . basename($_FILES["file"]["name"]);
    
    // VULNERABILITY: No content verification
    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        $upload_message = "File uploaded successfully: " . htmlspecialchars(basename($_FILES["file"]["name"]));
        
        // Log the upload (information disclosure)
        $log_entry = date('Y-m-d H:i:s') . " - User: " . $_SESSION['username'] . 
                    " uploaded: " . $_FILES["file"]["name"] . " (" . $_FILES["file"]["size"] . " bytes)\n";
        file_put_contents("uploads/upload_log.txt", $log_entry, FILE_APPEND);
    } else {
        $upload_error = "Error uploading file. Debug info: " . print_r($_FILES, true);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload - MedCare Health System</title>
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
        .user-info { font-size: 14px; }
        .container { max-width: 800px; margin: 30px auto; padding: 0 20px; }
        .card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .upload-area {
            border: 2px dashed #667eea;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            margin: 20px 0;
            background: #f8f9fa;
        }
        .upload-area input[type="file"] {
            display: none;
        }
        .upload-label {
            display: inline-block;
            padding: 12px 30px;
            background: #667eea;
            color: white;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
        }
        .upload-label:hover { background: #764ba2; }
        .btn {
            padding: 12px 30px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            font-size: 16px;
        }
        .btn:hover { background: #764ba2; }
        .success {
            background: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #c3e6cb;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #f5c6cb;
        }
        .file-list {
            margin-top: 20px;
        }
        .file-item {
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .file-item a {
            color: #667eea;
            text-decoration: none;
        }
        .nav a {
            display: inline-block;
            margin-right: 15px;
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚕️ MedCare Health System</h1>
        <div class="user-info">
            Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?> |
            <a href="logout.php" style="color: white;">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="card">
            <div class="nav">
                <a href="dashboard.php">← Back to Dashboard</a>
            </div>
            
            <h2>File Upload</h2>
            <p style="color: #666; margin-bottom: 20px;">Upload patient documents, test results, and medical records</p>
            
            <?php if ($upload_message): ?>
                <div class="success"><?php echo $upload_message; ?></div>
            <?php endif; ?>
            
            <?php if ($upload_error): ?>
                <div class="error"><?php echo $upload_error; ?></div>
            <?php endif; ?>
            
            <form method="POST" enctype="multipart/form-data">
                <div class="upload-area">
                    <p style="font-size: 48px; margin-bottom: 20px;">📁</p>
                    <label for="file" class="upload-label">Choose File</label>
                    <input type="file" id="file" name="file" onchange="showFileName(this)">
                    <p id="file-name" style="margin-top: 15px; color: #666;"></p>
                </div>
                <button type="submit" class="btn">Upload File</button>
            </form>
            
            <div style="margin-top: 30px; padding: 15px; background: #fff3cd; border-radius: 5px; border-left: 4px solid #ffc107;">
                <strong>⚠️ Notice:</strong> All file types are accepted. Uploaded files are stored in the uploads/ directory.
            </div>
        </div>
        
        <div class="card">
            <h3>Recently Uploaded Files</h3>
            <div class="file-list">
                <?php
                $upload_dir = "uploads/";
                if (is_dir($upload_dir)) {
                    $files = array_diff(scandir($upload_dir), array('.', '..'));
                    if (count($files) > 0) {
                        foreach (array_reverse($files) as $file) {
                            $file_path = $upload_dir . $file;
                            $file_size = filesize($file_path);
                            $file_time = date("Y-m-d H:i:s", filemtime($file_path));
                            
                            echo "<div class='file-item'>";
                            echo "<div>";
                            echo "<strong>" . htmlspecialchars($file) . "</strong><br>";
                            echo "<small style='color: #666;'>" . number_format($file_size) . " bytes | " . $file_time . "</small>";
                            echo "</div>";
                            // VULNERABILITY: Direct file access without authorization
                            echo "<a href='uploads/" . htmlspecialchars($file) . "' target='_blank'>Download</a>";
                            echo "</div>";
                        }
                    } else {
                        echo "<p style='color: #666;'>No files uploaded yet.</p>";
                    }
                }
                ?>
            </div>
        </div>
    </div>
    
    <script>
        function showFileName(input) {
            if (input.files && input.files[0]) {
                document.getElementById('file-name').textContent = 'Selected: ' + input.files[0].name;
            }
        }
    </script>
</body>
</html>


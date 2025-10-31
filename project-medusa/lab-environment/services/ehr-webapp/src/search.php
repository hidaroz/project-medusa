<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patient Search - MedCare Health System</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            text-align: center;
        }
        .container { max-width: 900px; margin: 30px auto; padding: 0 20px; }
        .card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .search-box {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        .search-box input {
            flex: 1;
            padding: 12px;
            border: 2px solid #e1e8ed;
            border-radius: 5px;
            font-size: 14px;
        }
        .search-box button {
            padding: 12px 30px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
        }
        .search-box button:hover { background: #764ba2; }
        .results { margin-top: 20px; }
        .result-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
        }
        .result-item:hover { background: #e9ecef; }
        .result-item a { color: #667eea; text-decoration: none; font-weight: 600; }
        .result-item a:hover { text-decoration: underline; }
        .back-link { display: inline-block; margin-bottom: 20px; color: #667eea; text-decoration: none; }
        .back-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚕️ Patient Search</h1>
    </div>
    
    <div class="container">
        <div class="card">
            <a href="index.php" class="back-link">← Back to Home</a>
            <h2>Search Patient Records</h2>
            
            <form method="GET" action="">
                <div class="search-box">
                    <input type="text" name="search" placeholder="Search by name, SSN, or patient ID..." 
                           value="<?php echo isset($_GET['search']) ? htmlspecialchars($_GET['search']) : ''; ?>">
                    <button type="submit">Search</button>
                </div>
            </form>
            
            <?php
            if (isset($_GET['search'])) {
                $search = $_GET['search'];
                
                try {
                    $conn = new mysqli(
                        getenv('DB_HOST'),
                        getenv('DB_USER'),
                        getenv('DB_PASS'),
                        getenv('DB_NAME')
                    );
                    
                    if ($conn->connect_error) {
                        echo "<div class='alert alert-danger'>Connection failed: " . $conn->connect_error . "</div>";
                    } else {
                        // INTENTIONAL SQL INJECTION VULNERABILITY - No input sanitization
                        $query = "SELECT id, first_name, last_name, ssn, date_of_birth, phone FROM patients WHERE 
                                 first_name LIKE '%$search%' OR 
                                 last_name LIKE '%$search%' OR 
                                 ssn LIKE '%$search%' OR 
                                 id LIKE '%$search%'";
                        
                        // Information disclosure - show query in HTML comment
                        echo "<!-- SQL Query: $query -->";
                        
                        $result = $conn->query($query);
                        
                        if ($result) {
                            if ($result->num_rows > 0) {
                                echo "<div class='results'>";
                                echo "<h3>Found " . $result->num_rows . " patient(s):</h3>";
                                
                                while ($row = $result->fetch_assoc()) {
                                    echo "<div class='result-item'>";
                                    echo "<strong>" . htmlspecialchars($row['first_name'] . " " . $row['last_name']) . "</strong><br>";
                                    echo "Patient ID: " . htmlspecialchars($row['id']) . " | ";
                                    echo "SSN: " . htmlspecialchars($row['ssn']) . " | ";
                                    echo "DOB: " . htmlspecialchars($row['date_of_birth']) . " | ";
                                    echo "Phone: " . htmlspecialchars($row['phone']) . "<br>";
                                    echo "<a href='dashboard.php?patient_id=" . $row['id'] . "'>View Full Record →</a>";
                                    echo "</div>";
                                }
                                echo "</div>";
                            } else {
                                echo "<p>No patients found matching your search.</p>";
                            }
                        } else {
                            // Verbose error message (information disclosure)
                            echo "<div style='background: #f8d7da; padding: 15px; border-radius: 5px; color: #721c24;'>";
                            echo "<strong>SQL Error:</strong> " . $conn->error . "<br>";
                            echo "<strong>Query:</strong> " . htmlspecialchars($query);
                            echo "</div>";
                        }
                        
                        $conn->close();
                    }
                } catch (Exception $e) {
                    echo "<div style='background: #f8d7da; padding: 15px; border-radius: 5px; color: #721c24;'>";
                    echo "<strong>Error:</strong> " . $e->getMessage() . "<br>";
                    echo "<strong>File:</strong> " . $e->getFile() . " (Line " . $e->getLine() . ")";
                    echo "</div>";
                }
            }
            ?>
            
            <div style="margin-top: 30px; padding: 15px; background: #e7f3ff; border-radius: 5px; border-left: 4px solid #2196F3;">
                <strong>Search Tips:</strong><br>
                • Search by patient name (first or last)<br>
                • Search by SSN (format: XXX-XX-XXXX)<br>
                • Search by patient ID number<br>
                • Partial matches are supported
            </div>
        </div>
    </div>
</body>
</html>


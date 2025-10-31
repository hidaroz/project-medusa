<?php
session_start();

// Weak session check
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

$conn = new mysqli(
    getenv('DB_HOST'),
    getenv('DB_USER'),
    getenv('DB_PASS'),
    getenv('DB_NAME')
);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reports - MedCare Health System</title>
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
        .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e1e8ed;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
        }
        tr:hover { background: #f8f9fa; }
        .nav a {
            display: inline-block;
            margin-right: 15px;
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }
        .btn {
            padding: 8px 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            font-size: 14px;
        }
        .btn:hover { background: #764ba2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚕️ MedCare Health System</h1>
        <div style="font-size: 14px;">
            Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?> |
            <a href="logout.php" style="color: white;">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="card">
            <div class="nav">
                <a href="dashboard.php">← Back to Dashboard</a>
            </div>
            
            <h2>Patient Reports & Analytics</h2>
            
            <div style="margin: 20px 0;">
                <a href="?report=all_patients" class="btn">All Patients</a>
                <a href="?report=recent_visits" class="btn">Recent Visits</a>
                <a href="?report=insurance" class="btn">Insurance Data</a>
                <a href="?export=csv" class="btn">Export to CSV</a>
            </div>
            
            <?php
            // VULNERABILITY: Information disclosure - sensitive data exposure
            if (isset($_GET['report'])) {
                $report_type = $_GET['report'];
                
                if ($report_type == 'all_patients') {
                    // No access control check
                    $query = "SELECT id, first_name, last_name, ssn, date_of_birth, phone, email, insurance_provider 
                             FROM patients ORDER BY id";
                    $result = $conn->query($query);
                    
                    echo "<h3>All Patient Records</h3>";
                    echo "<table>";
                    echo "<tr><th>ID</th><th>Name</th><th>SSN</th><th>DOB</th><th>Phone</th><th>Email</th><th>Insurance</th><th>Action</th></tr>";
                    
                    while ($row = $result->fetch_assoc()) {
                        echo "<tr>";
                        echo "<td>" . htmlspecialchars($row['id']) . "</td>";
                        echo "<td>" . htmlspecialchars($row['first_name'] . ' ' . $row['last_name']) . "</td>";
                        echo "<td>" . htmlspecialchars($row['ssn']) . "</td>";
                        echo "<td>" . htmlspecialchars($row['date_of_birth']) . "</td>";
                        echo "<td>" . htmlspecialchars($row['phone']) . "</td>";
                        echo "<td>" . htmlspecialchars($row['email']) . "</td>";
                        echo "<td>" . htmlspecialchars($row['insurance_provider']) . "</td>";
                        echo "<td><a href='dashboard.php?patient_id=" . $row['id'] . "'>View</a></td>";
                        echo "</tr>";
                    }
                    echo "</table>";
                    
                } elseif ($report_type == 'insurance') {
                    $query = "SELECT insurance_provider, COUNT(*) as count FROM patients GROUP BY insurance_provider";
                    $result = $conn->query($query);
                    
                    echo "<h3>Insurance Provider Distribution</h3>";
                    echo "<table>";
                    echo "<tr><th>Insurance Provider</th><th>Patient Count</th></tr>";
                    
                    while ($row = $result->fetch_assoc()) {
                        echo "<tr>";
                        echo "<td>" . htmlspecialchars($row['insurance_provider']) . "</td>";
                        echo "<td>" . htmlspecialchars($row['count']) . "</td>";
                        echo "</tr>";
                    }
                    echo "</table>";
                }
            }
            
            // VULNERABILITY: Unrestricted data export
            if (isset($_GET['export']) && $_GET['export'] == 'csv') {
                header('Content-Type: text/csv');
                header('Content-Disposition: attachment; filename="patient_data_export.csv"');
                
                $output = fopen('php://output', 'w');
                fputcsv($output, array('ID', 'First Name', 'Last Name', 'SSN', 'DOB', 'Phone', 'Email', 'Address', 'Insurance'));
                
                $query = "SELECT * FROM patients";
                $result = $conn->query($query);
                
                while ($row = $result->fetch_assoc()) {
                    fputcsv($output, $row);
                }
                
                fclose($output);
                exit;
            }
            ?>
            
            <div style="margin-top: 30px; padding: 15px; background: #e7f3ff; border-radius: 5px;">
                <strong>Available Reports:</strong><br>
                • All Patients: Complete patient database with PII<br>
                • Recent Visits: Last 30 days activity<br>
                • Insurance Data: Provider distribution<br>
                • CSV Export: Full database dump
            </div>
        </div>
    </div>
</body>
</html>
<?php $conn->close(); ?>


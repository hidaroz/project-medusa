<?php
session_start();

// Weak session check (vulnerability)
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

// IDOR Vulnerability - No authorization check for patient_id
$patient_id = isset($_GET['patient_id']) ? $_GET['patient_id'] : null;

$conn = new mysqli(
    getenv('DB_HOST'),
    getenv('DB_USER'),
    getenv('DB_PASS'),
    getenv('DB_NAME')
);

$patient_data = null;
if ($patient_id) {
    // IDOR - Direct access to any patient record without authorization
    $query = "SELECT * FROM patients WHERE id = $patient_id";
    $result = $conn->query($query);
    if ($result && $result->num_rows > 0) {
        $patient_data = $result->fetch_assoc();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - MedCare Health System</title>
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
        .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .card h2 { margin-bottom: 20px; color: #333; }
        .nav {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
        }
        .nav a {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            transition: background 0.3s;
        }
        .nav a:hover { background: #764ba2; }
        .patient-info { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; }
        .info-item { padding: 10px; background: #f8f9fa; border-radius: 5px; }
        .info-item strong { color: #667eea; }
        .alert { background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #ffc107; }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚕️ MedCare Health System</h1>
        <div class="user-info">
            Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?> 
            (<?php echo htmlspecialchars($_SESSION['role']); ?>) |
            <a href="logout.php" style="color: white;">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="nav">
            <a href="dashboard.php">Dashboard</a>
            <a href="search.php">Patient Search</a>
            <a href="upload.php">Upload Files</a>
            <a href="reports.php">Reports</a>
            <a href="settings.php">Settings</a>
        </div>
        
        <div class="card">
            <h2>Dashboard</h2>
            <div class="alert">
                <strong>Notice:</strong> You are accessing patient records. All access is logged and monitored.
            </div>
            
            <?php if ($patient_data): ?>
                <h3>Patient Record #<?php echo $patient_id; ?></h3>
                <div class="patient-info">
                    <div class="info-item">
                        <strong>Name:</strong> <?php echo htmlspecialchars($patient_data['first_name'] . ' ' . $patient_data['last_name']); ?>
                    </div>
                    <div class="info-item">
                        <strong>DOB:</strong> <?php echo htmlspecialchars($patient_data['date_of_birth']); ?>
                    </div>
                    <div class="info-item">
                        <strong>SSN:</strong> <?php echo htmlspecialchars($patient_data['ssn']); ?>
                    </div>
                    <div class="info-item">
                        <strong>Phone:</strong> <?php echo htmlspecialchars($patient_data['phone']); ?>
                    </div>
                    <div class="info-item">
                        <strong>Email:</strong> <?php echo htmlspecialchars($patient_data['email']); ?>
                    </div>
                    <div class="info-item">
                        <strong>Address:</strong> <?php echo htmlspecialchars($patient_data['address']); ?>
                    </div>
                    <div class="info-item">
                        <strong>Insurance:</strong> <?php echo htmlspecialchars($patient_data['insurance_provider']); ?>
                    </div>
                    <div class="info-item">
                        <strong>Policy #:</strong> <?php echo htmlspecialchars($patient_data['insurance_policy_number']); ?>
                    </div>
                </div>
                
                <!-- XSS Vulnerability - Unsanitized medical notes -->
                <div style="margin-top: 20px;">
                    <h3>Medical Notes</h3>
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 10px;">
                        <?php echo $patient_data['medical_notes']; ?>
                    </div>
                </div>
            <?php else: ?>
                <p>Welcome to your dashboard. Use the navigation above to access patient records and system features.</p>
                <p style="margin-top: 10px; color: #666;">
                    <small>Try accessing patient records: dashboard.php?patient_id=1</small>
                </p>
            <?php endif; ?>
        </div>
        
        <div class="card">
            <h2>Quick Stats</h2>
            <div class="patient-info">
                <div class="info-item"><strong>Total Patients:</strong> 1,247</div>
                <div class="info-item"><strong>Active Cases:</strong> 89</div>
                <div class="info-item"><strong>Appointments Today:</strong> 12</div>
                <div class="info-item"><strong>Pending Labs:</strong> 34</div>
            </div>
        </div>
    </div>
</body>
</html>
<?php $conn->close(); ?>


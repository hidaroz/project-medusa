<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Documentation - MedCare Health System</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #667eea;
            margin-bottom: 10px;
        }
        .back-link {
            display: inline-block;
            margin-bottom: 20px;
            color: #667eea;
            text-decoration: none;
        }
        .endpoint {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        .method {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
            margin-right: 10px;
        }
        .get { background: #4caf50; color: white; }
        .post { background: #2196F3; color: white; }
        .put { background: #ff9800; color: white; }
        .delete { background: #f44336; color: white; }
        code {
            background: #2d2d30;
            color: #d4d4d4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        pre {
            background: #2d2d30;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="index.php" class="back-link">← Back to Home</a>
        <h1>📚 API Documentation</h1>
        <p style="color: #666; margin-bottom: 30px;">MedCare Health System REST API v1.0</p>
        
        <h2 style="margin-top: 30px; color: #333;">Base URL</h2>
        <code>http://localhost:3000/api</code>
        
        <h2 style="margin-top: 30px; margin-bottom: 15px; color: #333;">Authentication Endpoints</h2>
        
        <div class="endpoint">
            <span class="method post">POST</span>
            <strong>/api/login</strong>
            <p style="margin-top: 10px; color: #666;">Authenticate user and receive JWT token</p>
            <pre>
// Request
{
  "username": "admin",
  "password": "admin123"
}

// Response
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "email": "admin@medcare.local"
  }
}</pre>
        </div>
        
        <h2 style="margin-top: 30px; margin-bottom: 15px; color: #333;">Patient Endpoints</h2>
        
        <div class="endpoint">
            <span class="method get">GET</span>
            <strong>/api/patients</strong>
            <p style="margin-top: 10px; color: #666;">Get all patients (no authentication required)</p>
            <pre>
// Response
{
  "count": 10,
  "data": [
    {
      "id": 1,
      "first_name": "John",
      "last_name": "Doe",
      "ssn": "123-45-6789",
      ...
    }
  ]
}</pre>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span>
            <strong>/api/patients/:id</strong>
            <p style="margin-top: 10px; color: #666;">Get specific patient by ID</p>
            <pre>
// Example: GET /api/patients/1

// Response
{
  "success": true,
  "data": {
    "id": 1,
    "first_name": "John",
    "last_name": "Doe",
    "date_of_birth": "1975-03-15",
    "ssn": "123-45-6789",
    ...
  }
}</pre>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span>
            <strong>/api/patients/search/:term</strong>
            <p style="margin-top: 10px; color: #666;">Search patients by name or SSN</p>
            <pre>
// Example: GET /api/patients/search/John

// Response
{
  "count": 2,
  "data": [...]
}</pre>
        </div>
        
        <h2 style="margin-top: 30px; margin-bottom: 15px; color: #333;">User Management</h2>
        
        <div class="endpoint">
            <span class="method get">GET</span>
            <strong>/api/users</strong>
            <p style="margin-top: 10px; color: #666;">List all users (no authentication required)</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span>
            <strong>/api/users/check/:username</strong>
            <p style="margin-top: 10px; color: #666;">Check if username exists</p>
        </div>
        
        <h2 style="margin-top: 30px; margin-bottom: 15px; color: #333;">Admin Endpoints</h2>
        
        <div class="endpoint">
            <span class="method get">GET</span>
            <strong>/api/admin/schema</strong>
            <p style="margin-top: 10px; color: #666;">Get database schema information</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span>
            <strong>/api/admin/config</strong>
            <p style="margin-top: 10px; color: #666;">Get system configuration (includes credentials)</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span>
            <strong>/api/info</strong>
            <p style="margin-top: 10px; color: #666;">Get server information</p>
        </div>
        
        <h2 style="margin-top: 30px; margin-bottom: 15px; color: #333;">Debug Endpoints</h2>
        
        <div class="endpoint">
            <span class="method post">POST</span>
            <strong>/api/debug/query</strong>
            <p style="margin-top: 10px; color: #666;">Execute arbitrary SQL query</p>
            <pre>
// Request
{
  "query": "SELECT * FROM users"
}</pre>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span>
            <strong>/api/debug/file/:filename</strong>
            <p style="margin-top: 10px; color: #666;">Read configuration files</p>
        </div>
        
        <div style="margin-top: 40px; padding: 20px; background: #fff3cd; border-radius: 5px; border-left: 4px solid #ffc107;">
            <strong>⚠️ Security Notice</strong>
            <p style="margin-top: 10px;">This API contains intentional security vulnerabilities for testing purposes. Do NOT use in production!</p>
        </div>
    </div>
</body>
</html>


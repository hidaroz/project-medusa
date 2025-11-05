const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const fs = require('fs');

const app = express();
const PORT = 3000;

// INTENTIONAL VULNERABILITY: Weak JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret123';

// Middleware
app.use(cors({ origin: '*' })); // INTENTIONAL: Permissive CORS
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan('combined')); // Verbose logging

// Database connection (intentionally exposed)
const dbConfig = {
    host: process.env.DB_HOST || 'ehr-database',
    user: process.env.DB_USER || 'ehrapp',
    password: process.env.DB_PASS || 'Welcome123!',
    database: process.env.DB_NAME || 'healthcare_db'
};

const db = mysql.createPool(dbConfig);

// Log database config (INTENTIONAL VULNERABILITY: Information disclosure)
console.log('Database Configuration:', dbConfig);
console.log('JWT Secret:', JWT_SECRET);

// ============================================================================
// AUTHENTICATION ENDPOINTS
// ============================================================================

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// INTENTIONAL VULNERABILITY: Login endpoint with weak authentication
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // INTENTIONAL: SQL Injection vulnerability
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    console.log('Login attempt - Query:', query); // Information disclosure
    
    db.query(query, (err, results) => {
        if (err) {
            // INTENTIONAL: Verbose error messages
            return res.status(500).json({
                error: 'Database error',
                message: err.message,
                sql: err.sql,
                sqlMessage: err.sqlMessage
            });
        }
        
        if (results.length > 0) {
            const user = results[0];
            // INTENTIONAL: Weak JWT token
            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            res.json({
                success: true,
                token: token,
                user: {
                    id: user.id,
                    username: user.username,
                    role: user.role,
                    email: user.email
                }
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// ============================================================================
// PATIENT ENDPOINTS (INTENTIONAL VULNERABILITIES)
// ============================================================================

// INTENTIONAL: No authentication required
app.get('/api/patients', (req, res) => {
    const query = 'SELECT * FROM patients LIMIT 100';
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({
                error: 'Database error',
                message: err.message,
                stack: err.stack // INTENTIONAL: Stack trace disclosure
            });
        }
        res.json({ count: results.length, data: results });
    });
});

// INTENTIONAL: IDOR vulnerability - no authorization check
app.get('/api/patients/:id', (req, res) => {
    const patientId = req.params.id;
    
    // INTENTIONAL: SQL Injection via parameter
    const query = `SELECT * FROM patients WHERE id = ${patientId}`;
    
    console.log('Patient query:', query); // Information disclosure
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({
                error: 'Database error',
                message: err.message,
                sql: query // INTENTIONAL: Query disclosure
            });
        }
        
        if (results.length > 0) {
            res.json({ success: true, data: results[0] });
        } else {
            res.status(404).json({ error: 'Patient not found' });
        }
    });
});

// INTENTIONAL: Search with SQL injection vulnerability
app.get('/api/patients/search/:term', (req, res) => {
    const searchTerm = req.params.term;
    
    // INTENTIONAL: SQL Injection
    const query = `SELECT * FROM patients WHERE 
                   first_name LIKE '%${searchTerm}%' OR 
                   last_name LIKE '%${searchTerm}%' OR 
                   ssn LIKE '%${searchTerm}%'`;
    
    console.log('Search query:', query);
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({
                error: err.message,
                query: query,
                stack: err.stack
            });
        }
        res.json({ count: results.length, data: results });
    });
});

// ============================================================================
// APPOINTMENTS ENDPOINTS
// ============================================================================

// Get all appointments (INTENTIONAL: No auth required)
app.get('/api/appointments', (req, res) => {
    const query = 'SELECT * FROM appointments ORDER BY date DESC LIMIT 100';
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({
                error: 'Database error',
                message: err.message
            });
        }
        res.json({ count: results.length, data: results });
    });
});

// Get appointments by patient ID (INTENTIONAL: IDOR vulnerability)
app.get('/api/appointments/patient/:patientId', (req, res) => {
    const patientId = req.params.patientId;
    const query = `SELECT * FROM appointments WHERE patient_id = ${patientId} ORDER BY date DESC`;
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ count: results.length, data: results });
    });
});

// ============================================================================
// PRESCRIPTIONS/MEDICATIONS ENDPOINTS
// ============================================================================

// Get all prescriptions (INTENTIONAL: No auth required)
app.get('/api/prescriptions', (req, res) => {
    const query = 'SELECT * FROM prescriptions LIMIT 100';
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({
                error: 'Database error',
                message: err.message
            });
        }
        res.json({ count: results.length, data: results });
    });
});

// Alias for medications endpoint
app.get('/api/medications', (req, res) => {
    const query = 'SELECT * FROM prescriptions LIMIT 100';
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({
                error: 'Database error',
                message: err.message
            });
        }
        res.json({ count: results.length, data: results });
    });
});

// Get prescriptions by patient ID (INTENTIONAL: IDOR vulnerability)
app.get('/api/prescriptions/patient/:patientId', (req, res) => {
    const patientId = req.params.patientId;
    const query = `SELECT * FROM prescriptions WHERE patient_id = ${patientId}`;
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ count: results.length, data: results });
    });
});

// ============================================================================
// LAB RESULTS ENDPOINTS
// ============================================================================

// Get all lab results (INTENTIONAL: No auth required)
app.get('/api/lab-results', (req, res) => {
    const query = 'SELECT * FROM lab_results ORDER BY test_date DESC LIMIT 100';
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({
                error: 'Database error',
                message: err.message
            });
        }
        res.json({ count: results.length, data: results });
    });
});

// Get lab results by patient ID (INTENTIONAL: IDOR vulnerability)
app.get('/api/lab-results/patient/:patientId', (req, res) => {
    const patientId = req.params.patientId;
    const query = `SELECT * FROM lab_results WHERE patient_id = ${patientId} ORDER BY test_date DESC`;
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ count: results.length, data: results });
    });
});

// ============================================================================
// MEDICAL RECORDS ENDPOINTS
// ============================================================================

// Get all medical records (INTENTIONAL: No auth required)
app.get('/api/medical-records', (req, res) => {
    const query = 'SELECT * FROM medical_records ORDER BY record_date DESC LIMIT 100';
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({
                error: 'Database error',
                message: err.message
            });
        }
        res.json({ count: results.length, data: results });
    });
});

// Get medical records by patient ID (INTENTIONAL: IDOR vulnerability)
app.get('/api/medical-records/patient/:patientId', (req, res) => {
    const patientId = req.params.patientId;
    const query = `SELECT * FROM medical_records WHERE patient_id = ${patientId} ORDER BY record_date DESC`;
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ count: results.length, data: results });
    });
});

// ============================================================================
// USER MANAGEMENT ENDPOINTS
// ============================================================================

// INTENTIONAL: User enumeration endpoint (no auth)
app.get('/api/users', (req, res) => {
    const query = 'SELECT id, username, email, role, created_at FROM users';
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ users: results });
    });
});

// INTENTIONAL: Check if username exists (user enumeration)
app.get('/api/users/check/:username', (req, res) => {
    const username = req.params.username;
    const query = `SELECT username FROM users WHERE username = '${username}'`;
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ exists: results.length > 0 });
    });
});

// ============================================================================
// SYSTEM INFO ENDPOINTS (INTENTIONAL INFORMATION DISCLOSURE)
// ============================================================================

// INTENTIONAL: Expose database schema
app.get('/api/admin/schema', (req, res) => {
    const query = 'SHOW TABLES';
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        const tables = results.map(row => Object.values(row)[0]);
        const schema = {};
        
        let completed = 0;
        tables.forEach(table => {
            db.query(`DESCRIBE ${table}`, (err, columns) => {
                if (!err) {
                    schema[table] = columns;
                }
                completed++;
                if (completed === tables.length) {
                    res.json({ tables: tables, schema: schema });
                }
            });
        });
    });
});

// INTENTIONAL: Expose environment variables
app.get('/api/admin/config', (req, res) => {
    res.json({
        database: dbConfig,
        jwt_secret: JWT_SECRET,
        node_env: process.env.NODE_ENV,
        environment: process.env
    });
});

// INTENTIONAL: Server information disclosure
app.get('/api/info', (req, res) => {
    res.json({
        server: 'MedCare API v1.0.0',
        node_version: process.version,
        platform: process.platform,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        env: process.env.NODE_ENV || 'production',
        database: {
            host: dbConfig.host,
            user: dbConfig.user,
            database: dbConfig.database
        }
    });
});

// ============================================================================
// FILE UPLOAD ENDPOINT (INTENTIONAL VULNERABILITY)
// ============================================================================

// INTENTIONAL: Unrestricted file upload
app.post('/api/upload', (req, res) => {
    // Simplified - just demonstrate the vulnerability
    res.json({
        message: 'File upload endpoint',
        vulnerability: 'No file type restrictions, no auth required',
        upload_path: '/var/www/uploads/'
    });
});

// ============================================================================
// DEBUG ENDPOINTS (INTENTIONAL VULNERABILITIES)
// ============================================================================

// INTENTIONAL: Execute arbitrary SQL (for testing)
app.post('/api/debug/query', (req, res) => {
    const { query } = req.body;
    
    if (!query) {
        return res.status(400).json({ error: 'Query parameter required' });
    }
    
    console.log('Debug query execution:', query);
    
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({
                error: err.message,
                sql: query,
                stack: err.stack
            });
        }
        res.json({ success: true, results: results });
    });
});

// INTENTIONAL: Read arbitrary files
app.get('/api/debug/file/:filename', (req, res) => {
    const filename = req.params.filename;
    const filepath = `/opt/config/${filename}`;
    
    fs.readFile(filepath, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).json({
                error: err.message,
                path: filepath
            });
        }
        res.json({ file: filename, content: data });
    });
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

// Catch all 404
app.use((req, res) => {
    res.status(404).json({
        error: 'Route not found',
        path: req.path,
        method: req.method,
        headers: req.headers // INTENTIONAL: Expose headers
    });
});

// Global error handler (verbose)
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: err.message,
        stack: err.stack, // INTENTIONAL: Stack trace
        path: req.path,
        method: req.method
    });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║   MedCare Health System API Server                       ║
║   Status: RUNNING                                         ║
║   Port: ${PORT}                                              ║
║   ⚠️  CONTAINS INTENTIONAL VULNERABILITIES                ║
║   FOR TESTING PURPOSES ONLY                               ║
╚═══════════════════════════════════════════════════════════╝
    `);
    
    console.log('\nAvailable Endpoints:');
    console.log('  POST   /api/login');
    console.log('  GET    /api/patients');
    console.log('  GET    /api/patients/:id');
    console.log('  GET    /api/patients/search/:term');
    console.log('  GET    /api/appointments');
    console.log('  GET    /api/appointments/patient/:patientId');
    console.log('  GET    /api/prescriptions');
    console.log('  GET    /api/medications (alias for prescriptions)');
    console.log('  GET    /api/prescriptions/patient/:patientId');
    console.log('  GET    /api/lab-results');
    console.log('  GET    /api/lab-results/patient/:patientId');
    console.log('  GET    /api/medical-records');
    console.log('  GET    /api/medical-records/patient/:patientId');
    console.log('  GET    /api/users');
    console.log('  GET    /api/users/check/:username');
    console.log('  GET    /api/admin/schema');
    console.log('  GET    /api/admin/config');
    console.log('  GET    /api/info');
    console.log('  POST   /api/debug/query');
    console.log('  GET    /api/debug/file/:filename');
    console.log('  GET    /health\n');
});


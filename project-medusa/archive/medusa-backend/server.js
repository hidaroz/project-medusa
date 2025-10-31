const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const patientsRoutes = require('./src/routes/patients');
const employeesRoutes = require('./src/routes/employees');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());

// Routes
app.use('/api/patients', patientsRoutes);
app.use('/api/employees', employeesRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    service: 'Medusa Backend API',
    version: '1.0.0'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Medusa Backend API - Mock EHR System',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      patients: '/api/patients',
      employees: '/api/employees'
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Something went wrong!',
    message: err.message
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.originalUrl
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Medusa Backend API running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`👥 Patients API: http://localhost:${PORT}/api/patients`);
  console.log(`👨‍💼 Employees API: http://localhost:${PORT}/api/employees`);
});

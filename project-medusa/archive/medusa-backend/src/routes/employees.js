const express = require('express');
const { getAllEmployees, getEmployeeById, getEmployeeCredentials } = require('../../../data/employees.js');

const router = express.Router();

// GET /api/employees - Get all employees
router.get('/', (req, res) => {
  try {
    const employees = getAllEmployees();
    res.json({
      success: true,
      count: employees.length,
      data: employees
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch employees',
      message: error.message
    });
  }
});

// GET /api/employees/:id - Get specific employee by ID
router.get('/:id', (req, res) => {
  try {
    const employeeId = req.params.id;
    const employee = getEmployeeById(employeeId);

    if (employee) {
      res.json({
        success: true,
        data: employee
      });
    } else {
      res.status(404).json({
        success: false,
        error: 'Employee not found',
        employeeId: employeeId
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch employee',
      message: error.message
    });
  }
});

// GET /api/employees/:id/credentials - Get employee credentials
router.get('/:id/credentials', (req, res) => {
  try {
    const employeeId = req.params.id;
    const credentials = getEmployeeCredentials(employeeId);

    if (credentials) {
      res.json({
        success: true,
        data: credentials,
        warning: 'Sensitive credentials - handle with extreme care'
      });
    } else {
      res.status(404).json({
        success: false,
        error: 'Employee not found or no credentials available',
        employeeId: employeeId
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch credentials',
      message: error.message
    });
  }
});

module.exports = router;

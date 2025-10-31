const express = require('express');
const { getAllPatients, getPatientById, getPatientSensitiveData } = require('../../../data/patients.js');

const router = express.Router();

// GET /api/patients - Get all patients
router.get('/', (req, res) => {
  try {
    const patients = getAllPatients();
    res.json({
      success: true,
      count: patients.length,
      data: patients
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch patients',
      message: error.message
    });
  }
});

// GET /api/patients/:id - Get specific patient by ID
router.get('/:id', (req, res) => {
  try {
    const patientId = req.params.id;
    const patient = getPatientById(patientId);

    if (patient) {
      res.json({
        success: true,
        data: patient
      });
    } else {
      res.status(404).json({
        success: false,
        error: 'Patient not found',
        patientId: patientId
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch patient',
      message: error.message
    });
  }
});

// GET /api/patients/:id/sensitive - Get sensitive patient data
router.get('/:id/sensitive', (req, res) => {
  try {
    const patientId = req.params.id;
    const sensitiveData = getPatientSensitiveData(patientId);

    if (sensitiveData) {
      res.json({
        success: true,
        data: sensitiveData,
        warning: 'Sensitive data - handle with care'
      });
    } else {
      res.status(404).json({
        success: false,
        error: 'Patient not found or no sensitive data available',
        patientId: patientId
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch sensitive data',
      message: error.message
    });
  }
});

module.exports = router;

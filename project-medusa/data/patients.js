// Mock patient data for the EHR system

const mockPatients = [
  {
    id: "P001",
    firstName: "Sarah",
    lastName: "Johnson",
    dateOfBirth: "1985-03-15",
    gender: "Female",
    bloodType: "O+",
    allergies: ["Penicillin", "Shellfish"],
    conditions: ["Type 2 Diabetes", "Hypertension"],
    medications: [
      {
        id: "M001",
        name: "Metformin",
        dosage: "500mg",
        frequency: "Twice daily",
        route: "Oral",
        startDate: "2024-01-15",
        prescribingPhysician: "Dr. Emily Chen",
        status: "active"
      }
    ],
    lastVisit: "2024-01-15",
    nextAppointment: "2024-02-15",
    phone: "+1-555-0123",
    email: "sarah.johnson@email.com",
    address: "123 Main St, Anytown, ST 12345",
    emergencyContact: {
      name: "John Johnson",
      relationship: "Spouse",
      phone: "+1-555-0124"
    },
    insuranceProvider: "BlueCross BlueShield",
    insuranceNumber: "BC123456789",
    primaryPhysician: "Dr. Emily Chen",
    vitalSigns: [
      {
        temperature: 98.6,
        bloodPressure: "120/80",
        heartRate: 72,
        respiratoryRate: 16,
        oxygenSaturation: 98,
        weight: 150,
        height: 65,
        bmi: 25.0,
        recordedDate: "2024-01-15",
        recordedBy: "Nurse Smith"
      }
    ],
    labResults: [
      {
        id: "L001",
        testName: "HbA1c",
        result: "7.2",
        unit: "%",
        referenceRange: "<7.0",
        status: "abnormal",
        orderDate: "2024-01-15",
        resultDate: "2024-01-16",
        orderingPhysician: "Dr. Emily Chen"
      }
    ],
    appointments: [
      {
        id: "A001",
        date: "2024-02-15",
        time: "10:00 AM",
        type: "Follow-up",
        provider: "Dr. Emily Chen",
        status: "scheduled"
      }
    ],
    mrn: "MRN001",
    status: "active",
    lastUpdated: "2024-01-15T10:30:00Z",
    // Sensitive Data
    ssn: "123-45-6789",
    driverLicense: "DL123456789",
    financialInfo: {
      creditCardNumber: "4532-1234-5678-9012",
      creditCardExpiry: "12/25",
      creditCardCVV: "123",
      bankAccountNumber: "1234567890",
      bankRoutingNumber: "021000021",
      outstandingBalance: 250.00,
      paymentHistory: []
    },
    sensitiveConditions: ["Depression", "Anxiety"],
    familyHistory: ["Diabetes", "Heart Disease"],
    socialHistory: {
      smokingStatus: "never",
      alcoholUse: "moderate",
      drugUse: "none",
      occupation: "Teacher",
      maritalStatus: "Married"
    }
  },
  {
    id: "P002",
    firstName: "Michael",
    lastName: "Rodriguez",
    dateOfBirth: "1978-11-22",
    gender: "Male",
    bloodType: "A-",
    allergies: ["Latex"],
    conditions: ["Asthma", "Seasonal Allergies"],
    medications: [
      {
        id: "M002",
        name: "Albuterol",
        dosage: "90mcg",
        frequency: "As needed",
        route: "Inhaler",
        startDate: "2023-12-01",
        prescribingPhysician: "Dr. Sarah Wilson",
        status: "active"
      }
    ],
    lastVisit: "2024-01-10",
    nextAppointment: "2024-03-10",
    phone: "+1-555-0125",
    email: "michael.rodriguez@email.com",
    address: "456 Oak Ave, Somewhere, ST 67890",
    emergencyContact: {
      name: "Maria Rodriguez",
      relationship: "Wife",
      phone: "+1-555-0126"
    },
    insuranceProvider: "Aetna",
    insuranceNumber: "AE987654321",
    primaryPhysician: "Dr. Sarah Wilson",
    vitalSigns: [
      {
        temperature: 98.4,
        bloodPressure: "118/76",
        heartRate: 68,
        respiratoryRate: 18,
        oxygenSaturation: 97,
        weight: 175,
        height: 70,
        bmi: 25.1,
        recordedDate: "2024-01-10",
        recordedBy: "Nurse Johnson"
      }
    ],
    labResults: [],
    appointments: [
      {
        id: "A002",
        date: "2024-03-10",
        time: "2:00 PM",
        type: "Annual Physical",
        provider: "Dr. Sarah Wilson",
        status: "scheduled"
      }
    ],
    mrn: "MRN002",
    status: "active",
    lastUpdated: "2024-01-10T14:20:00Z",
    // Sensitive Data
    ssn: "987-65-4321",
    driverLicense: "DL987654321",
    financialInfo: {
      creditCardNumber: "5555-4444-3333-2222",
      creditCardExpiry: "08/26",
      creditCardCVV: "456",
      bankAccountNumber: "9876543210",
      bankRoutingNumber: "021000021",
      outstandingBalance: 0.00,
      paymentHistory: []
    },
    sensitiveConditions: [],
    familyHistory: ["Asthma", "Allergies"],
    socialHistory: {
      smokingStatus: "former",
      alcoholUse: "none",
      drugUse: "none",
      occupation: "Engineer",
      maritalStatus: "Married"
    }
  }
];

function getPatientById(id) {
  return mockPatients.find(patient => patient.id === id);
}

function getAllPatients() {
  return mockPatients;
}

function getPatientSensitiveData(id) {
  const patient = getPatientById(id);
  if (patient) {
    // Return patient with all sensitive data included
    return patient;
  }
  return undefined;
}

module.exports = {
  mockPatients,
  getPatientById,
  getAllPatients,
  getPatientSensitiveData
};
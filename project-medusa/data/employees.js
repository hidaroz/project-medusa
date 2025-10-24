// Mock employee data for the EHR system

const mockEmployees = [
  {
    id: "E001",
    firstName: "Dr. Emily",
    lastName: "Chen",
    email: "emily.chen@hospital.com",
    department: "Internal Medicine",
    position: "Attending Physician",
    employeeId: "EMP001",
    hireDate: "2020-01-15",
    salary: 250000,
    status: "active",
    phone: "+1-555-1001",
    address: "789 Doctor Lane, Medical City, ST 11111",
    emergencyContact: {
      name: "David Chen",
      relationship: "Spouse",
      phone: "+1-555-1002"
    },
    // Sensitive Data
    ssn: "111-22-3333",
    credentials: {
      username: "echen",
      password: "SecurePass123!",
      lastLogin: "2024-01-15T08:30:00Z",
      failedLoginAttempts: 0,
      passwordLastChanged: "2024-01-01T00:00:00Z",
      mfaEnabled: true,
      mfaSecret: "JBSWY3DPEHPK3PXP",
      accessLevel: "physician",
      permissions: [
        "read_patients",
        "write_patients",
        "read_medical_records",
        "write_medical_records",
        "prescribe_medications",
        "order_labs",
        "view_sensitive_data"
      ]
    },
    financialInfo: {
      bankAccountNumber: "1111111111",
      bankRoutingNumber: "021000021",
      directDepositAmount: 20833.33,
      taxWithholding: 62500.00,
      retirementContribution: 25000.00
    },
    performanceReviews: [
      {
        year: 2023,
        rating: "exceeds_expectations",
        comments: "Excellent patient care and team collaboration",
        reviewer: "Dr. Sarah Wilson"
      }
    ],
    disciplinaryActions: [],
    benefitsInfo: {
      healthInsurance: "Premium Plan",
      dentalInsurance: "Standard Plan",
      visionInsurance: "Basic Plan",
      lifeInsurance: 500000,
      disabilityInsurance: "Long-term",
      retirementPlan: "401k with 6% match"
    }
  },
  {
    id: "E002",
    firstName: "Sarah",
    lastName: "Wilson",
    email: "sarah.wilson@hospital.com",
    department: "Pulmonology",
    position: "Attending Physician",
    employeeId: "EMP002",
    hireDate: "2019-06-01",
    salary: 280000,
    status: "active",
    phone: "+1-555-2001",
    address: "456 Specialist Blvd, Medical City, ST 22222",
    emergencyContact: {
      name: "Robert Wilson",
      relationship: "Husband",
      phone: "+1-555-2002"
    },
    // Sensitive Data
    ssn: "222-33-4444",
    credentials: {
      username: "swilson",
      password: "MedPass456!",
      lastLogin: "2024-01-15T09:15:00Z",
      failedLoginAttempts: 0,
      passwordLastChanged: "2023-12-15T00:00:00Z",
      mfaEnabled: true,
      mfaSecret: "JBSWY3DPEHPK3PXP",
      accessLevel: "physician",
      permissions: [
        "read_patients",
        "write_patients",
        "read_medical_records",
        "write_medical_records",
        "prescribe_medications",
        "order_labs",
        "view_sensitive_data",
        "admin_functions"
      ]
    },
    financialInfo: {
      bankAccountNumber: "2222222222",
      bankRoutingNumber: "021000021",
      directDepositAmount: 23333.33,
      taxWithholding: 70000.00,
      retirementContribution: 28000.00
    },
    performanceReviews: [
      {
        year: 2023,
        rating: "outstanding",
        comments: "Exceptional leadership and clinical expertise",
        reviewer: "Dr. Michael Brown"
      }
    ],
    disciplinaryActions: [],
    benefitsInfo: {
      healthInsurance: "Premium Plan",
      dentalInsurance: "Premium Plan",
      visionInsurance: "Premium Plan",
      lifeInsurance: 750000,
      disabilityInsurance: "Long-term",
      retirementPlan: "401k with 6% match"
    }
  },
  {
    id: "E003",
    firstName: "Jennifer",
    lastName: "Smith",
    email: "jennifer.smith@hospital.com",
    department: "Nursing",
    position: "Registered Nurse",
    employeeId: "EMP003",
    hireDate: "2021-03-01",
    salary: 75000,
    status: "active",
    phone: "+1-555-3001",
    address: "321 Care Street, Medical City, ST 33333",
    emergencyContact: {
      name: "James Smith",
      relationship: "Husband",
      phone: "+1-555-3002"
    },
    // Sensitive Data
    ssn: "333-44-5555",
    credentials: {
      username: "jsmith",
      password: "NursePass789!",
      lastLogin: "2024-01-15T07:45:00Z",
      failedLoginAttempts: 0,
      passwordLastChanged: "2024-01-01T00:00:00Z",
      mfaEnabled: false,
      accessLevel: "nurse",
      permissions: [
        "read_patients",
        "write_patients",
        "read_medical_records",
        "update_vital_signs",
        "administer_medications"
      ]
    },
    financialInfo: {
      bankAccountNumber: "3333333333",
      bankRoutingNumber: "021000021",
      directDepositAmount: 6250.00,
      taxWithholding: 18750.00,
      retirementContribution: 7500.00
    },
    performanceReviews: [
      {
        year: 2023,
        rating: "meets_expectations",
        comments: "Reliable and compassionate patient care",
        reviewer: "Nurse Manager Lisa Davis"
      }
    ],
    disciplinaryActions: [],
    benefitsInfo: {
      healthInsurance: "Standard Plan",
      dentalInsurance: "Standard Plan",
      visionInsurance: "Basic Plan",
      lifeInsurance: 250000,
      disabilityInsurance: "Short-term",
      retirementPlan: "401k with 3% match"
    }
  }
];

function getEmployeeById(id) {
  return mockEmployees.find(employee => employee.id === id);
}

function getAllEmployees() {
  return mockEmployees;
}

function getEmployeeCredentials(id) {
  const employee = getEmployeeById(id);
  if (employee) {
    // Return employee with all credential data included
    return employee;
  }
  return undefined;
}

module.exports = {
  mockEmployees,
  getEmployeeById,
  getAllEmployees,
  getEmployeeCredentials
};

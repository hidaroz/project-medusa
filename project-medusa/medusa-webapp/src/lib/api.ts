// API client for Medusa Backend

const API_BASE_URL = 'http://localhost:3001/api';

// Types for API responses
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  count?: number;
  error?: string;
  message?: string;
  warning?: string;
}

export interface Patient {
  id: string;
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  gender: string;
  bloodType: string;
  allergies: string[];
  conditions: string[];
  medications: Array<{
    name: string;
    dosage: string;
    frequency: string;
    startDate: string;
    endDate?: string;
  }>;
  lastVisit: string;
  nextAppointment: string;
  phone: string;
  email: string;
  address: string;
  emergencyContact: {
    name: string;
    relationship: string;
    phone: string;
  };
  insuranceProvider: string;
  insuranceNumber: string;
  primaryPhysician: string;
  vitalSigns: Array<{
    date: string;
    bloodPressure: string;
    heartRate: number;
    temperature: number;
    weight: number;
    height: number;
  }>;
  labResults: Array<{
    testName: string;
    result: string;
    date: string;
    normalRange: string;
  }>;
  appointments: Array<{
    date: string;
    time: string;
    doctor: string;
    reason: string;
    status: string;
  }>;
  mrn: string;
  status: string;
  lastUpdated: string;
  ssn: string;
  driverLicense: string;
  financialInfo: {
    creditCardNumber: string;
    creditCardExpiry: string;
    creditCardCVV: string;
    bankAccountNumber: string;
    bankRoutingNumber: string;
    outstandingBalance: number;
    paymentHistory: Array<{
      date: string;
      amount: number;
      method: string;
      status: string;
    }>;
  };
  sensitiveConditions: string[];
  familyHistory: string[];
  socialHistory: {
    smokingStatus: string;
    alcoholUse: string;
    drugUse: string;
    occupation: string;
    maritalStatus: string;
  };
}

export interface Employee {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  department: string;
  position: string;
  employeeId: string;
  hireDate: string;
  salary: number;
  status: string;
  phone: string;
  address: string;
  emergencyContact: {
    name: string;
    relationship: string;
    phone: string;
  };
  ssn: string;
  credentials: {
    username: string;
    password: string;
    lastLogin: string;
    failedLoginAttempts: number;
    passwordLastChanged: string;
    mfaEnabled: boolean;
    mfaSecret?: string;
    accessLevel: string;
    permissions: string[];
  };
  financialInfo: {
    bankAccountNumber: string;
    bankRoutingNumber: string;
    directDepositAmount: number;
    taxWithholding: number;
    retirementContribution: number;
  };
  performanceReviews: Array<{
    date: string;
    reviewer: string;
    rating: number;
    comments: string;
  }>;
  disciplinaryActions: Array<{
    date: string;
    type: string;
    description: string;
    severity: string;
  }>;
  benefitsInfo: {
    healthInsurance: string;
    dentalInsurance: string;
    visionInsurance: string;
    lifeInsurance: number;
    disabilityInsurance: string;
    retirementPlan: string;
  };
}

// Patient API functions
export async function getAllPatients(): Promise<Patient[]> {
  try {
    const response = await fetch(`${API_BASE_URL}/patients`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result: ApiResponse<Patient[]> = await response.json();
    if (result.success && result.data) {
      return result.data;
    } else {
      throw new Error(result.error || 'Failed to fetch patients');
    }
  } catch (error) {
    console.error('Error fetching patients:', error);
    throw error;
  }
}

export async function getPatientById(id: string): Promise<Patient> {
  try {
    const response = await fetch(`${API_BASE_URL}/patients/${id}`);
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Patient not found');
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result: ApiResponse<Patient> = await response.json();
    if (result.success && result.data) {
      return result.data;
    } else {
      throw new Error(result.error || 'Failed to fetch patient');
    }
  } catch (error) {
    console.error('Error fetching patient:', error);
    throw error;
  }
}

export async function getPatientSensitiveData(id: string): Promise<Patient> {
  try {
    const response = await fetch(`${API_BASE_URL}/patients/${id}/sensitive`);
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Patient not found');
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result: ApiResponse<Patient> = await response.json();
    if (result.success && result.data) {
      return result.data;
    } else {
      throw new Error(result.error || 'Failed to fetch sensitive data');
    }
  } catch (error) {
    console.error('Error fetching sensitive data:', error);
    throw error;
  }
}

// Employee API functions
export async function getAllEmployees(): Promise<Employee[]> {
  try {
    const response = await fetch(`${API_BASE_URL}/employees`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result: ApiResponse<Employee[]> = await response.json();
    if (result.success && result.data) {
      return result.data;
    } else {
      throw new Error(result.error || 'Failed to fetch employees');
    }
  } catch (error) {
    console.error('Error fetching employees:', error);
    throw error;
  }
}

export async function getEmployeeById(id: string): Promise<Employee> {
  try {
    const response = await fetch(`${API_BASE_URL}/employees/${id}`);
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Employee not found');
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result: ApiResponse<Employee> = await response.json();
    if (result.success && result.data) {
      return result.data;
    } else {
      throw new Error(result.error || 'Failed to fetch employee');
    }
  } catch (error) {
    console.error('Error fetching employee:', error);
    throw error;
  }
}

export async function getEmployeeCredentials(id: string): Promise<Employee> {
  try {
    const response = await fetch(`${API_BASE_URL}/employees/${id}/credentials`);
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Employee not found');
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result: ApiResponse<Employee> = await response.json();
    if (result.success && result.data) {
      return result.data;
    } else {
      throw new Error(result.error || 'Failed to fetch credentials');
    }
  } catch (error) {
    console.error('Error fetching credentials:', error);
    throw error;
  }
}

// Health check function
export async function checkHealth(): Promise<{ status: string; timestamp: string }> {
  try {
    const response = await fetch('http://localhost:3001/health');
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('Error checking health:', error);
    throw error;
  }
}

// Mock system config data (since we don't have a system config API yet)
export interface SystemConfig {
  database: {
    host: string;
    username: string;
    password: string;
    connectionString: string;
    encryptionKey: string;
  };
  api: {
    apiKey: string;
    secretKey: string;
    jwtSecret: string;
    encryptionKey: string;
  };
  backup: {
    cloudCredentials: {
      accessKey: string;
      secretKey: string;
      bucketName: string;
    };
  };
}

export function getSystemConfig(): SystemConfig {
  return {
    database: {
      host: "prod-db.medcare.internal",
      username: "medcare_admin",
      password: "SuperSecurePassword123!",
      connectionString: "postgresql://medcare_admin:SuperSecurePassword123!@prod-db.medcare.internal:5432/medcare_prod",
      encryptionKey: "aes-256-gcm-key-32bytes-long-secret"
    },
    api: {
      apiKey: "sk-prod-1234567890abcdef",
      secretKey: "secret-key-very-long-and-secure",
      jwtSecret: "jwt-secret-key-for-token-signing",
      encryptionKey: "api-encryption-key-32-chars"
    },
    backup: {
      cloudCredentials: {
        accessKey: "AKIAIOSFODNN7EXAMPLE",
        secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        bucketName: "medcare-backup-prod"
      }
    }
  };
}

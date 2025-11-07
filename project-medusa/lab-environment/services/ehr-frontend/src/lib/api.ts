// API client for MedCare EHR Backend

import { transformPatient, transformPatients, transformEmployee, transformEmployees } from './transformers';

// Get API base URL - handles both server-side (Docker network) and client-side (browser) contexts
function getApiBaseUrl(): string {
  // Check for environment variable first (works for both server and client with NEXT_PUBLIC_ prefix)
  const envUrl = process.env.NEXT_PUBLIC_EHR_API_URL;

  // If running in browser (client-side), use localhost with exposed port
  if (typeof window !== 'undefined') {
    // Client-side: use localhost with the exposed port (3001)
    // This works when accessing from browser (localhost:8080 -> localhost:3001)
    return envUrl && !envUrl.includes('ehr-api')
      ? (envUrl.endsWith('/api') ? envUrl : `${envUrl}/api`)
      : 'http://localhost:3001/api';
  }

  // Server-side: use Docker network hostname or environment variable
  if (envUrl) {
    // Ensure /api is appended
    return envUrl.endsWith('/api') ? envUrl : `${envUrl}/api`;
  }

  // Default fallback for server-side (Docker network)
  return 'http://ehr-api:3000/api';
}

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
    id?: string;
    patientId?: string;
    patientName?: string;
    patientAllergies?: string[];
    name: string;
    dosage: string;
    frequency: string;
    prescribedDate: string;
    status?: string;
    route?: string;
    startDate?: string;
    prescribingPhysician?: string;
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
    oxygenSaturation?: number;
    recordedDate?: string;
    recordedBy?: string;
  }>;
  labResults: Array<{
    id?: string;
    testName: string;
    result: string;
    date: string;
    normalRange?: string;
    unit?: string;
    referenceRange?: string;
    orderDate?: string;
    resultDate?: string;
    orderingPhysician?: string;
    status?: string;
  }>;
  appointments: Array<{
    id: string;
    date: string;
    time: string;
    provider: string;
    reason: string;
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
  biometricData?: {
    fingerprints?: string;
    retinalScan?: string;
    dnaProfile?: string;
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
    rating: number;
    comments: string;
    reviewer: string;
  }>;
  disciplinaryActions: Array<{
    date: string;
    type: string;
    description: string;
    status: string;
  }>;
  benefitsInfo: {
    healthInsurance: string;
    dentalInsurance: string;
    visionInsurance: string;
    lifeInsurance: number;
    disabilityInsurance: string;
    retirementPlan: string;
  };
  backgroundCheck?: {
    creditScore: number;
    criminalHistory: string[];
    drugTestResults: string;
  };
}

// Patient API functions
export async function getAllPatients(): Promise<Patient[]> {
  try {
    const apiUrl = getApiBaseUrl();
    const response = await fetch(`${apiUrl}/patients`, {
      cache: 'no-store', // Disable caching for fresh data
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result = await response.json();

    // Handle different response formats
    let apiPatients: any[];
    if (result.success && result.data) {
      apiPatients = result.data;
    } else if (result.data) {
      apiPatients = result.data;
    } else if (Array.isArray(result)) {
      apiPatients = result;
    } else {
      throw new Error(result.error || 'Failed to fetch patients');
    }

    // Transform snake_case API data to camelCase
    return transformPatients(apiPatients);
  } catch (error) {
    console.error('Error fetching patients:', error);
    throw error;
  }
}

export async function getPatientById(id: string): Promise<Patient> {
  try {
    const apiUrl = getApiBaseUrl();
    const response = await fetch(`${apiUrl}/patients/${id}`, {
      cache: 'no-store',
    });
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Patient not found');
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result = await response.json();

    // Handle different response formats
    let apiPatient: any;
    if (result.success && result.data) {
      apiPatient = result.data;
    } else if (result.data) {
      apiPatient = result.data;
    } else {
      throw new Error(result.error || 'Failed to fetch patient');
    }

    // Transform snake_case API data to camelCase
    return transformPatient(apiPatient);
  } catch (error) {
    console.error('Error fetching patient:', error);
    throw error;
  }
}

export async function getPatientSensitiveData(id: string): Promise<Patient> {
  try {
    const apiUrl = getApiBaseUrl();
    const response = await fetch(`${apiUrl}/patients/${id}/sensitive`);
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
    const apiUrl = getApiBaseUrl();
    const response = await fetch(`${apiUrl}/employees`, {
      cache: 'no-store',
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result = await response.json();

    // Handle different response formats
    let apiEmployees: any[];
    if (result.success && result.data) {
      apiEmployees = result.data;
    } else if (result.data) {
      apiEmployees = result.data;
    } else if (Array.isArray(result)) {
      apiEmployees = result;
    } else {
      throw new Error(result.error || 'Failed to fetch employees');
    }

    // Transform snake_case API data to camelCase
    return transformEmployees(apiEmployees);
  } catch (error) {
    console.error('Error fetching employees:', error);
    throw error;
  }
}

export async function getEmployeeById(id: string): Promise<Employee> {
  try {
    const apiUrl = getApiBaseUrl();
    const response = await fetch(`${apiUrl}/employees/${id}`, {
      cache: 'no-store',
    });
    if (!response.ok) {
      if (response.status === 404) {
        throw new Error('Employee not found');
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const result = await response.json();

    // Handle different response formats
    let apiEmployee: any;
    if (result.success && result.data) {
      apiEmployee = result.data;
    } else if (result.data) {
      apiEmployee = result.data;
    } else {
      throw new Error(result.error || 'Failed to fetch employee');
    }

    // Transform snake_case API data to camelCase
    return transformEmployee(apiEmployee);
  } catch (error) {
    console.error('Error fetching employee:', error);
    throw error;
  }
}

export async function getEmployeeCredentials(id: string): Promise<Employee> {
  try {
    const apiUrl = getApiBaseUrl();
    const response = await fetch(`${apiUrl}/employees/${id}/credentials`);
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
    // Get base URL without /api for health endpoint
    let apiUrl: string;
    if (typeof window !== 'undefined') {
      apiUrl = 'http://localhost:3001';
    } else {
      const envUrl = process.env.NEXT_PUBLIC_EHR_API_URL;
      apiUrl = envUrl || 'http://ehr-api:3000';
    }
    
    const response = await fetch(`${apiUrl}/health`);
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

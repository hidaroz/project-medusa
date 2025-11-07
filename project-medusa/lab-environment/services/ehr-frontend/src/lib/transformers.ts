// Data transformation utilities to convert API responses to frontend format
// Handles snake_case to camelCase conversion and data normalization

import { Patient, Employee } from './api';

// API Response types (snake_case from MySQL database)
interface ApiPatient {
  id: number;
  first_name: string;
  last_name: string;
  dob: string;
  ssn: string;
  phone: string;
  email: string;
  address: string;
  city?: string;
  state?: string;
  zip_code?: string;
  insurance_provider: string;
  insurance_policy_number: string;
  blood_type: string;
  allergies: string;
  medical_notes: string;
  emergency_contact_name: string;
  emergency_contact_phone: string;
  primary_physician: string;
  created_at: string;
  updated_at: string;
}

interface ApiEmployee {
  id: number;
  first_name: string;
  last_name: string;
  email: string;
  department: string;
  position: string;
  employee_id: string;
  hire_date: string;
  salary: number;
  status: string;
  phone: string;
  address: string;
  ssn: string;
  created_at: string;
  updated_at: string;
}

/**
 * Transform API patient data (snake_case) to frontend format (camelCase)
 */
export function transformPatient(apiPatient: ApiPatient): Patient {
  // Parse allergies from comma-separated string to array
  const allergies = apiPatient.allergies
    ? apiPatient.allergies.split(',').map(a => a.trim()).filter(Boolean)
    : [];

  // Parse medical notes to extract conditions (simple heuristic)
  const conditions = apiPatient.medical_notes
    ? [apiPatient.medical_notes]
    : [];

  // Generate MRN from ID (Medical Record Number)
  const mrn = `MRN${String(apiPatient.id).padStart(8, '0')}`;

  // Format date strings
  const dateOfBirth = new Date(apiPatient.dob).toISOString().split('T')[0];
  const lastVisit = new Date(apiPatient.updated_at).toLocaleDateString('en-US');
  const lastUpdated = new Date(apiPatient.updated_at).toISOString();

  return {
    id: String(apiPatient.id),
    firstName: apiPatient.first_name,
    lastName: apiPatient.last_name,
    dateOfBirth,
    gender: 'Not specified', // Not in API, default value
    bloodType: apiPatient.blood_type,
    allergies,
    conditions,
    medications: [], // Will be populated separately if needed
    lastVisit,
    nextAppointment: 'Not scheduled',
    phone: apiPatient.phone,
    email: apiPatient.email,
    address: `${apiPatient.address}${apiPatient.city ? ', ' + apiPatient.city : ''}${apiPatient.state ? ', ' + apiPatient.state : ''}${apiPatient.zip_code ? ' ' + apiPatient.zip_code : ''}`,
    emergencyContact: {
      name: apiPatient.emergency_contact_name,
      relationship: 'Not specified',
      phone: apiPatient.emergency_contact_phone,
    },
    insuranceProvider: apiPatient.insurance_provider,
    insuranceNumber: apiPatient.insurance_policy_number,
    primaryPhysician: apiPatient.primary_physician,
    vitalSigns: [],
    labResults: [],
    appointments: [],
    mrn,
    status: 'active', // Default status
    lastUpdated,
    ssn: apiPatient.ssn,
    driverLicense: 'Not available',
    financialInfo: {
      creditCardNumber: '',
      creditCardExpiry: '',
      creditCardCVV: '',
      bankAccountNumber: '',
      bankRoutingNumber: '',
      outstandingBalance: 0,
      paymentHistory: [],
    },
    sensitiveConditions: [],
    familyHistory: [],
    socialHistory: {
      smokingStatus: 'Unknown',
      alcoholUse: 'Unknown',
      drugUse: 'Unknown',
      occupation: 'Unknown',
      maritalStatus: 'Unknown',
    },
  };
}

/**
 * Transform array of API patients to frontend format
 */
export function transformPatients(apiPatients: ApiPatient[]): Patient[] {
  return apiPatients.map(transformPatient);
}

/**
 * Transform API employee data (snake_case) to frontend format (camelCase)
 */
export function transformEmployee(apiEmployee: ApiEmployee): Employee {
  return {
    id: String(apiEmployee.id),
    firstName: apiEmployee.first_name,
    lastName: apiEmployee.last_name,
    email: apiEmployee.email,
    department: apiEmployee.department,
    position: apiEmployee.position,
    employeeId: apiEmployee.employee_id,
    hireDate: new Date(apiEmployee.hire_date).toLocaleDateString('en-US'),
    salary: apiEmployee.salary,
    status: apiEmployee.status,
    phone: apiEmployee.phone,
    address: apiEmployee.address,
    emergencyContact: {
      name: 'Not specified',
      relationship: 'Not specified',
      phone: 'Not specified',
    },
    ssn: apiEmployee.ssn,
    credentials: {
      username: apiEmployee.email,
      password: '********',
      lastLogin: 'Never',
      failedLoginAttempts: 0,
      passwordLastChanged: 'Unknown',
      mfaEnabled: false,
      accessLevel: 'Standard',
      permissions: [],
    },
    financialInfo: {
      bankAccountNumber: '',
      bankRoutingNumber: '',
      directDepositAmount: apiEmployee.salary,
      taxWithholding: 0,
      retirementContribution: 0,
    },
    performanceReviews: [],
    disciplinaryActions: [],
    benefitsInfo: {
      healthInsurance: 'Not specified',
      dentalInsurance: 'Not specified',
      visionInsurance: 'Not specified',
      lifeInsurance: 0,
      disabilityInsurance: 'Not specified',
      retirementPlan: 'Not specified',
    },
  };
}

/**
 * Transform array of API employees to frontend format
 */
export function transformEmployees(apiEmployees: ApiEmployee[]): Employee[] {
  return apiEmployees.map(transformEmployee);
}

/**
 * Safe accessor for nested properties with fallback
 */
export function safeGet<T>(obj: any, path: string, defaultValue: T): T {
  const keys = path.split('.');
  let result = obj;

  for (const key of keys) {
    if (result === null || result === undefined) {
      return defaultValue;
    }
    result = result[key];
  }

  return result !== undefined ? result : defaultValue;
}
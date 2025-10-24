// Mock patient data for the EHR system

export interface VitalSigns {
  temperature?: number;
  bloodPressure?: string;
  heartRate?: number;
  respiratoryRate?: number;
  oxygenSaturation?: number;
  weight?: number;
  height?: number;
  bmi?: number;
  recordedDate: string;
  recordedBy: string;
}

export interface LabResult {
  id: string;
  testName: string;
  result: string;
  unit?: string;
  referenceRange?: string;
  status: 'normal' | 'abnormal' | 'critical';
  orderDate: string;
  resultDate: string;
  orderingPhysician: string;
}

export interface Medication {
  id: string;
  name: string;
  dosage: string;
  frequency: string;
  route: string;
  startDate: string;
  endDate?: string;
  prescribingPhysician: string;
  status: 'active' | 'discontinued' | 'completed';
}

export interface Appointment {
  id: string;
  date: string;
  time: string;
  type: string;
  provider: string;
  status: 'scheduled' | 'completed' | 'cancelled' | 'no-show';
  notes?: string;
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
  medications: Medication[];
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
  vitalSigns: VitalSigns[];
  labResults: LabResult[];
  appointments: Appointment[];
  mrn: string; // Medical Record Number
  status: 'active' | 'inactive' | 'deceased';
  lastUpdated: string;
  // Highly Sensitive Data
  ssn: string; // Social Security Number
  driverLicense: string;
  passportNumber?: string;
  financialInfo: {
    creditCardNumber: string;
    creditCardExpiry: string;
    creditCardCVV: string;
    bankAccountNumber: string;
    bankRoutingNumber: string;
    outstandingBalance: number;
    paymentHistory: PaymentRecord[];
  };
  sensitiveConditions: string[]; // Mental health, substance abuse, HIV, etc.
  familyHistory: string[];
  socialHistory: {
    smokingStatus: 'never' | 'former' | 'current';
    alcoholUse: 'none' | 'moderate' | 'heavy';
    drugUse: 'none' | 'recreational' | 'abuse';
    occupation: string;
    maritalStatus: string;
    children: number;
  };
  legalGuardian?: {
    name: string;
    relationship: string;
    phone: string;
    address: string;
    ssn: string;
  };
  insuranceDetails: {
    groupNumber: string;
    policyHolderSSN: string;
    copayAmount: number;
    deductibleRemaining: number;
    priorAuthorizationRequired: boolean;
  };
  biometricData: {
    fingerprints?: string; // Base64 encoded
    retinalScan?: string; // Base64 encoded
    dnaProfile?: string; // Genetic markers
  };
}

export interface PaymentRecord {
  date: string;
  amount: number;
  method: 'credit_card' | 'check' | 'cash' | 'insurance';
  transactionId: string;
  status: 'completed' | 'pending' | 'failed';
}

export const mockPatients: Patient[] = [
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
      },
      {
        id: "M002",
        name: "Lisinopril",
        dosage: "10mg",
        frequency: "Once daily",
        route: "Oral",
        startDate: "2024-02-01",
        prescribingPhysician: "Dr. Emily Chen",
        status: "active"
      }
    ],
    lastVisit: "2024-09-15",
    nextAppointment: "2024-10-20",
    phone: "(555) 123-4567",
    email: "sarah.j@email.com",
    address: "123 Oak Street, Springfield, IL 62701",
    emergencyContact: {
      name: "Michael Johnson",
      relationship: "Spouse",
      phone: "(555) 123-4568"
    },
    insuranceProvider: "Blue Cross Blue Shield",
    insuranceNumber: "BCBS-8472619",
    primaryPhysician: "Dr. Emily Chen",
    vitalSigns: [
      {
        temperature: 98.6,
        bloodPressure: "120/80",
        heartRate: 72,
        respiratoryRate: 16,
        oxygenSaturation: 98,
        weight: 145,
        height: 65,
        bmi: 24.1,
        recordedDate: "2024-09-15",
        recordedBy: "Nurse Smith"
      }
    ],
    labResults: [
      {
        id: "L001",
        testName: "Hemoglobin A1C",
        result: "7.2",
        unit: "%",
        referenceRange: "<7.0",
        status: "abnormal",
        orderDate: "2024-09-15",
        resultDate: "2024-09-16",
        orderingPhysician: "Dr. Emily Chen"
      },
      {
        id: "L002",
        testName: "Complete Blood Count",
        result: "Normal",
        status: "normal",
        orderDate: "2024-09-15",
        resultDate: "2024-09-16",
        orderingPhysician: "Dr. Emily Chen"
      }
    ],
    appointments: [
      {
        id: "A001",
        date: "2024-10-20",
        time: "10:00 AM",
        type: "Follow-up",
        provider: "Dr. Emily Chen",
        status: "scheduled"
      }
    ],
    mrn: "MRN-001234",
    status: "active",
    lastUpdated: "2024-09-15",
    // Highly Sensitive Data
    ssn: "123-45-6789",
    driverLicense: "D123456789",
    passportNumber: "P987654321",
    financialInfo: {
      creditCardNumber: "4532-1234-5678-9012",
      creditCardExpiry: "12/26",
      creditCardCVV: "123",
      bankAccountNumber: "1234567890",
      bankRoutingNumber: "021000021",
      outstandingBalance: 1250.75,
      paymentHistory: [
        {
          date: "2024-09-15",
          amount: 150.00,
          method: "credit_card",
          transactionId: "TXN-001234",
          status: "completed"
        },
        {
          date: "2024-08-15",
          amount: 200.00,
          method: "credit_card",
          transactionId: "TXN-001235",
          status: "completed"
        }
      ]
    },
    sensitiveConditions: ["Major Depressive Disorder", "Generalized Anxiety Disorder"],
    familyHistory: ["Type 2 Diabetes (Mother)", "Hypertension (Father)", "Breast Cancer (Maternal Grandmother)"],
    socialHistory: {
      smokingStatus: "never",
      alcoholUse: "moderate",
      drugUse: "none",
      occupation: "Software Engineer",
      maritalStatus: "Married",
      children: 2
    },
    legalGuardian: {
      name: "Michael Johnson",
      relationship: "Spouse",
      phone: "(555) 123-4568",
      address: "123 Oak Street, Springfield, IL 62701",
      ssn: "987-65-4321"
    },
    insuranceDetails: {
      groupNumber: "GRP-001234",
      policyHolderSSN: "123-45-6789",
      copayAmount: 25.00,
      deductibleRemaining: 1250.00,
      priorAuthorizationRequired: false
    },
    biometricData: {
      fingerprints: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
      retinalScan: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
      dnaProfile: "ATCGATCGATCGATCGATCGATCGATCGATCG"
    }
  },
  {
    id: "P002",
    firstName: "Robert",
    lastName: "Martinez",
    dateOfBirth: "1972-11-08",
    gender: "Male",
    bloodType: "A+",
    allergies: ["Latex", "Aspirin"],
    conditions: ["Asthma", "Seasonal Allergies"],
    medications: [
      {
        id: "M003",
        name: "Albuterol Inhaler",
        dosage: "90mcg",
        frequency: "As needed",
        route: "Inhalation",
        startDate: "2024-03-01",
        prescribingPhysician: "Dr. James Wilson",
        status: "active"
      },
      {
        id: "M004",
        name: "Cetirizine",
        dosage: "10mg",
        frequency: "Once daily",
        route: "Oral",
        startDate: "2024-04-15",
        prescribingPhysician: "Dr. James Wilson",
        status: "active"
      }
    ],
    lastVisit: "2024-09-28",
    nextAppointment: "2024-11-05",
    phone: "(555) 234-5678",
    email: "r.martinez@email.com",
    address: "456 Maple Avenue, Springfield, IL 62702",
    emergencyContact: {
      name: "Maria Martinez",
      relationship: "Wife",
      phone: "(555) 234-5679"
    },
    insuranceProvider: "United Healthcare",
    insuranceNumber: "UHC-3847562",
    primaryPhysician: "Dr. James Wilson",
    vitalSigns: [
      {
        temperature: 98.4,
        bloodPressure: "118/76",
        heartRate: 68,
        respiratoryRate: 18,
        oxygenSaturation: 96,
        weight: 180,
        height: 70,
        bmi: 25.8,
        recordedDate: "2024-09-28",
        recordedBy: "Nurse Johnson"
      }
    ],
    labResults: [
      {
        id: "L003",
        testName: "Pulmonary Function Test",
        result: "FEV1: 85% predicted",
        status: "normal",
        orderDate: "2024-09-28",
        resultDate: "2024-09-28",
        orderingPhysician: "Dr. James Wilson"
      }
    ],
    appointments: [
      {
        id: "A002",
        date: "2024-11-05",
        time: "2:00 PM",
        type: "Follow-up",
        provider: "Dr. James Wilson",
        status: "scheduled"
      }
    ],
    mrn: "MRN-001235",
    status: "active",
    lastUpdated: "2024-09-28",
    // Highly Sensitive Data
    ssn: "234-56-7890",
    driverLicense: "D234567890",
    financialInfo: {
      creditCardNumber: "5555-4444-3333-2222",
      creditCardExpiry: "08/27",
      creditCardCVV: "456",
      bankAccountNumber: "2345678901",
      bankRoutingNumber: "021000022",
      outstandingBalance: 850.25,
      paymentHistory: [
        {
          date: "2024-09-28",
          amount: 100.00,
          method: "credit_card",
          transactionId: "TXN-001236",
          status: "completed"
        }
      ]
    },
    sensitiveConditions: ["Substance Use Disorder (Alcohol)", "PTSD"],
    familyHistory: ["Asthma (Father)", "Heart Disease (Mother)"],
    socialHistory: {
      smokingStatus: "former",
      alcoholUse: "heavy",
      drugUse: "none",
      occupation: "Construction Worker",
      maritalStatus: "Married",
      children: 3
    },
    insuranceDetails: {
      groupNumber: "GRP-001235",
      policyHolderSSN: "234-56-7890",
      copayAmount: 30.00,
      deductibleRemaining: 2000.00,
      priorAuthorizationRequired: true
    },
    biometricData: {
      fingerprints: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    }
  },
  {
    id: "P003",
    firstName: "Emily",
    lastName: "Chen",
    dateOfBirth: "1990-07-22",
    gender: "Female",
    bloodType: "B+",
    allergies: ["Codeine"],
    conditions: ["Migraine", "Anxiety"],
    medications: [
      {
        id: "M005",
        name: "Sumatriptan",
        dosage: "50mg",
        frequency: "As needed",
        route: "Oral",
        startDate: "2024-05-01",
        prescribingPhysician: "Dr. Sarah Thompson",
        status: "active"
      },
      {
        id: "M006",
        name: "Sertraline",
        dosage: "25mg",
        frequency: "Once daily",
        route: "Oral",
        startDate: "2024-06-15",
        prescribingPhysician: "Dr. Sarah Thompson",
        status: "active"
      }
    ],
    lastVisit: "2024-10-01",
    nextAppointment: "2024-10-15",
    phone: "(555) 345-6789",
    email: "emily.chen@email.com",
    address: "789 Pine Road, Springfield, IL 62703",
    emergencyContact: {
      name: "David Chen",
      relationship: "Brother",
      phone: "(555) 345-6780"
    },
    insuranceProvider: "Aetna",
    insuranceNumber: "AET-9273841",
    primaryPhysician: "Dr. Sarah Thompson",
    vitalSigns: [
      {
        temperature: 98.2,
        bloodPressure: "110/70",
        heartRate: 75,
        respiratoryRate: 14,
        oxygenSaturation: 99,
        weight: 125,
        height: 63,
        bmi: 22.1,
        recordedDate: "2024-10-01",
        recordedBy: "Nurse Davis"
      }
    ],
    labResults: [],
    appointments: [
      {
        id: "A003",
        date: "2024-10-15",
        time: "11:00 AM",
        type: "Follow-up",
        provider: "Dr. Sarah Thompson",
        status: "scheduled"
      }
    ],
    mrn: "MRN-001236",
    status: "active",
    lastUpdated: "2024-10-01",
    // Highly Sensitive Data
    ssn: "345-67-8901",
    driverLicense: "D345678901",
    financialInfo: {
      creditCardNumber: "4111-1111-1111-1111",
      creditCardExpiry: "06/28",
      creditCardCVV: "789",
      bankAccountNumber: "3456789012",
      bankRoutingNumber: "021000023",
      outstandingBalance: 450.00,
      paymentHistory: [
        {
          date: "2024-10-01",
          amount: 75.00,
          method: "credit_card",
          transactionId: "TXN-001237",
          status: "completed"
        }
      ]
    },
    sensitiveConditions: ["HIV Positive", "Bipolar Disorder"],
    familyHistory: ["Mental Health Disorders (Mother)", "Cancer (Father)"],
    socialHistory: {
      smokingStatus: "never",
      alcoholUse: "none",
      drugUse: "recreational",
      occupation: "Graphic Designer",
      maritalStatus: "Single",
      children: 0
    },
    insuranceDetails: {
      groupNumber: "GRP-001236",
      policyHolderSSN: "345-67-8901",
      copayAmount: 20.00,
      deductibleRemaining: 500.00,
      priorAuthorizationRequired: false
    },
    biometricData: {
      retinalScan: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    }
  },
  {
    id: "P004",
    firstName: "James",
    lastName: "Williams",
    dateOfBirth: "1965-01-30",
    gender: "Male",
    bloodType: "AB-",
    allergies: ["Sulfa Drugs", "Iodine"],
    conditions: ["Coronary Artery Disease", "High Cholesterol"],
    medications: [
      {
        id: "M007",
        name: "Atorvastatin",
        dosage: "40mg",
        frequency: "Once daily",
        route: "Oral",
        startDate: "2024-01-01",
        prescribingPhysician: "Dr. Robert Davis",
        status: "active"
      },
      {
        id: "M008",
        name: "Aspirin",
        dosage: "81mg",
        frequency: "Once daily",
        route: "Oral",
        startDate: "2024-01-01",
        prescribingPhysician: "Dr. Robert Davis",
        status: "active"
      },
      {
        id: "M009",
        name: "Metoprolol",
        dosage: "25mg",
        frequency: "Twice daily",
        route: "Oral",
        startDate: "2024-01-01",
        prescribingPhysician: "Dr. Robert Davis",
        status: "active"
      }
    ],
    lastVisit: "2024-09-20",
    nextAppointment: "2024-10-25",
    phone: "(555) 456-7890",
    email: "j.williams@email.com",
    address: "321 Birch Lane, Springfield, IL 62704",
    emergencyContact: {
      name: "Linda Williams",
      relationship: "Wife",
      phone: "(555) 456-7891"
    },
    insuranceProvider: "Medicare",
    insuranceNumber: "MED-5738291",
    primaryPhysician: "Dr. Robert Davis",
    vitalSigns: [
      {
        temperature: 98.1,
        bloodPressure: "135/85",
        heartRate: 65,
        respiratoryRate: 16,
        oxygenSaturation: 97,
        weight: 195,
        height: 72,
        bmi: 26.4,
        recordedDate: "2024-09-20",
        recordedBy: "Nurse Wilson"
      }
    ],
    labResults: [
      {
        id: "L004",
        testName: "Lipid Panel",
        result: "Total Cholesterol: 185 mg/dL",
        status: "normal",
        orderDate: "2024-09-20",
        resultDate: "2024-09-21",
        orderingPhysician: "Dr. Robert Davis"
      }
    ],
    appointments: [
      {
        id: "A004",
        date: "2024-10-25",
        time: "9:00 AM",
        type: "Cardiology Follow-up",
        provider: "Dr. Robert Davis",
        status: "scheduled"
      }
    ],
    mrn: "MRN-001237",
    status: "active",
    lastUpdated: "2024-09-20",
    // Highly Sensitive Data
    ssn: "456-78-9012",
    driverLicense: "D456789012",
    financialInfo: {
      creditCardNumber: "6011-1111-1111-1117",
      creditCardExpiry: "03/29",
      creditCardCVV: "012",
      bankAccountNumber: "4567890123",
      bankRoutingNumber: "021000024",
      outstandingBalance: 2100.50,
      paymentHistory: [
        {
          date: "2024-09-20",
          amount: 300.00,
          method: "credit_card",
          transactionId: "TXN-001238",
          status: "completed"
        }
      ]
    },
    sensitiveConditions: ["Cardiac Arrhythmia", "Sleep Apnea"],
    familyHistory: ["Heart Disease (Father)", "Diabetes (Mother)", "Stroke (Paternal Grandfather)"],
    socialHistory: {
      smokingStatus: "former",
      alcoholUse: "moderate",
      drugUse: "none",
      occupation: "Retired Engineer",
      maritalStatus: "Married",
      children: 4
    },
    insuranceDetails: {
      groupNumber: "GRP-001237",
      policyHolderSSN: "456-78-9012",
      copayAmount: 40.00,
      deductibleRemaining: 3000.00,
      priorAuthorizationRequired: true
    },
    biometricData: {
      dnaProfile: "GCTAGCTAGCTAGCTAGCTAGCTAGCTAGCTA"
    }
  },
  {
    id: "P005",
    firstName: "Lisa",
    lastName: "Anderson",
    dateOfBirth: "1988-09-12",
    gender: "Female",
    bloodType: "O-",
    allergies: ["Peanuts", "Tree Nuts", "Eggs"],
    conditions: ["Celiac Disease", "Anemia"],
    medications: [
      {
        id: "M010",
        name: "Iron Supplement",
        dosage: "65mg",
        frequency: "Once daily",
        route: "Oral",
        startDate: "2024-08-01",
        prescribingPhysician: "Dr. Patricia Moore",
        status: "active"
      },
      {
        id: "M011",
        name: "Vitamin D3",
        dosage: "2000 IU",
        frequency: "Once daily",
        route: "Oral",
        startDate: "2024-08-01",
        prescribingPhysician: "Dr. Patricia Moore",
        status: "active"
      }
    ],
    lastVisit: "2024-10-02",
    nextAppointment: "2024-11-12",
    phone: "(555) 567-8901",
    email: "lisa.anderson@email.com",
    address: "654 Cedar Court, Springfield, IL 62705",
    emergencyContact: {
      name: "Karen Anderson",
      relationship: "Mother",
      phone: "(555) 567-8902"
    },
    insuranceProvider: "Cigna",
    insuranceNumber: "CIG-6284719",
    primaryPhysician: "Dr. Patricia Moore",
    vitalSigns: [
      {
        temperature: 98.3,
        bloodPressure: "105/65",
        heartRate: 70,
        respiratoryRate: 15,
        oxygenSaturation: 98,
        weight: 130,
        height: 64,
        bmi: 22.3,
        recordedDate: "2024-10-02",
        recordedBy: "Nurse Brown"
      }
    ],
    labResults: [
      {
        id: "L005",
        testName: "Hemoglobin",
        result: "11.8",
        unit: "g/dL",
        referenceRange: "12.0-15.5",
        status: "abnormal",
        orderDate: "2024-10-02",
        resultDate: "2024-10-03",
        orderingPhysician: "Dr. Patricia Moore"
      }
    ],
    appointments: [
      {
        id: "A005",
        date: "2024-11-12",
        time: "3:00 PM",
        type: "Follow-up",
        provider: "Dr. Patricia Moore",
        status: "scheduled"
      }
    ],
    mrn: "MRN-001238",
    status: "active",
    lastUpdated: "2024-10-02",
    // Highly Sensitive Data
    ssn: "567-89-0123",
    driverLicense: "D567890123",
    financialInfo: {
      creditCardNumber: "3714-496353-98431",
      creditCardExpiry: "11/30",
      creditCardCVV: "345",
      bankAccountNumber: "5678901234",
      bankRoutingNumber: "021000025",
      outstandingBalance: 675.25,
      paymentHistory: [
        {
          date: "2024-10-02",
          amount: 125.00,
          method: "credit_card",
          transactionId: "TXN-001239",
          status: "completed"
        }
      ]
    },
    sensitiveConditions: ["Eating Disorder", "Panic Disorder"],
    familyHistory: ["Celiac Disease (Mother)", "Anemia (Sister)", "Depression (Father)"],
    socialHistory: {
      smokingStatus: "never",
      alcoholUse: "none",
      drugUse: "none",
      occupation: "Teacher",
      maritalStatus: "Single",
      children: 0
    },
    insuranceDetails: {
      groupNumber: "GRP-001238",
      policyHolderSSN: "567-89-0123",
      copayAmount: 15.00,
      deductibleRemaining: 750.00,
      priorAuthorizationRequired: false
    },
    biometricData: {
      fingerprints: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
      retinalScan: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    }
  }
];

export function getPatientById(id: string): Patient | undefined {
  return mockPatients.find(patient => patient.id === id);
}

export function getAllPatients(): Patient[] {
  return mockPatients;
}


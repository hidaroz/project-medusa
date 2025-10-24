// Highly sensitive employee data that would be valuable to hackers

export interface Employee {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  address: string;
  dateOfBirth: string;
  ssn: string;
  employeeId: string;
  department: string;
  position: string;
  salary: number;
  hireDate: string;
  status: 'active' | 'inactive' | 'terminated';
  // Sensitive HR Data
  performanceReviews: PerformanceReview[];
  disciplinaryActions: DisciplinaryAction[];
  benefits: BenefitsInfo;
  credentials: {
    username: string;
    password: string; // In real system, this would be hashed
    lastLogin: string;
    failedLoginAttempts: number;
    passwordLastChanged: string;
    mfaEnabled: boolean;
    mfaSecret?: string;
    accessLevel: 'admin' | 'physician' | 'nurse' | 'staff';
    permissions: string[];
  };
  medicalInfo: {
    healthInsurance: string;
    emergencyContact: {
      name: string;
      relationship: string;
      phone: string;
    };
    allergies: string[];
    medications: string[];
  };
  financialInfo: {
    bankAccountNumber: string;
    bankRoutingNumber: string;
    directDepositAmount: number;
    taxWithholding: number;
    retirementContribution: number;
  };
  backgroundCheck: {
    criminalHistory: string[];
    creditScore: number;
    drugTestResults: string;
    referenceChecks: ReferenceCheck[];
  };
}

export interface PerformanceReview {
  id: string;
  reviewDate: string;
  reviewer: string;
  rating: number; // 1-5 scale
  comments: string;
  goals: string[];
  salaryIncrease?: number;
}

export interface DisciplinaryAction {
  id: string;
  date: string;
  reason: string;
  action: 'verbal_warning' | 'written_warning' | 'suspension' | 'termination';
  details: string;
  supervisor: string;
}

export interface BenefitsInfo {
  healthInsurance: string;
  dentalInsurance: string;
  visionInsurance: string;
  lifeInsurance: number;
  disabilityInsurance: string;
  retirementPlan: string;
  vacationDays: number;
  sickDays: number;
  personalDays: number;
}

export interface ReferenceCheck {
  name: string;
  relationship: string;
  phone: string;
  comments: string;
  rating: number;
}

export const mockEmployees: Employee[] = [
  {
    id: "E001",
    firstName: "Dr. Emily",
    lastName: "Chen",
    email: "emily.chen@medcare.com",
    phone: "(555) 100-0001",
    address: "100 Doctor Lane, Springfield, IL 62701",
    dateOfBirth: "1980-05-15",
    ssn: "111-11-1111",
    employeeId: "EMP-001",
    department: "Internal Medicine",
    position: "Physician",
    salary: 285000,
    hireDate: "2020-01-15",
    status: "active",
    performanceReviews: [
      {
        id: "PR001",
        reviewDate: "2024-01-15",
        reviewer: "Dr. Sarah Thompson",
        rating: 5,
        comments: "Excellent physician with outstanding patient care. Consistently exceeds expectations.",
        goals: ["Increase patient satisfaction scores", "Complete continuing education requirements"],
        salaryIncrease: 15000
      }
    ],
    disciplinaryActions: [],
    benefits: {
      healthInsurance: "Blue Cross Blue Shield Premium",
      dentalInsurance: "Delta Dental",
      visionInsurance: "VSP",
      lifeInsurance: 500000,
      disabilityInsurance: "Long-term disability coverage",
      retirementPlan: "403(b) with 5% match",
      vacationDays: 25,
      sickDays: 12,
      personalDays: 3
    },
    credentials: {
      username: "echen",
      password: "Password123!",
      lastLogin: "2024-10-15T08:30:00Z",
      failedLoginAttempts: 0,
      passwordLastChanged: "2024-09-01",
      mfaEnabled: true,
      mfaSecret: "JBSWY3DPEHPK3PXP",
      accessLevel: "physician",
      permissions: ["view_patients", "edit_patients", "prescribe_medications", "view_labs", "edit_notes"]
    },
    medicalInfo: {
      healthInsurance: "Blue Cross Blue Shield",
      emergencyContact: {
        name: "David Chen",
        relationship: "Spouse",
        phone: "(555) 100-0002"
      },
      allergies: ["Penicillin"],
      medications: ["Multivitamin"]
    },
    financialInfo: {
      bankAccountNumber: "1111111111",
      bankRoutingNumber: "021000001",
      directDepositAmount: 9500.00,
      taxWithholding: 2850.00,
      retirementContribution: 1425.00
    },
    backgroundCheck: {
      criminalHistory: [],
      creditScore: 780,
      drugTestResults: "Negative",
      referenceChecks: [
        {
          name: "Dr. Michael Smith",
          relationship: "Former Supervisor",
          phone: "(555) 200-0001",
          comments: "Excellent clinical skills and bedside manner",
          rating: 5
        }
      ]
    }
  },
  {
    id: "E002",
    firstName: "Dr. James",
    lastName: "Wilson",
    email: "james.wilson@medcare.com",
    phone: "(555) 100-0003",
    address: "200 Physician Drive, Springfield, IL 62702",
    dateOfBirth: "1975-08-22",
    ssn: "222-22-2222",
    employeeId: "EMP-002",
    department: "Pulmonology",
    position: "Physician",
    salary: 295000,
    hireDate: "2019-03-10",
    status: "active",
    performanceReviews: [
      {
        id: "PR002",
        reviewDate: "2024-01-15",
        reviewer: "Dr. Sarah Thompson",
        rating: 4,
        comments: "Good physician with strong diagnostic skills. Needs improvement in documentation.",
        goals: ["Improve documentation quality", "Reduce patient wait times"],
        salaryIncrease: 10000
      }
    ],
    disciplinaryActions: [
      {
        id: "DA001",
        date: "2023-11-15",
        reason: "Late documentation",
        action: "written_warning",
        details: "Failed to complete patient notes within 24 hours on multiple occasions",
        supervisor: "Dr. Sarah Thompson"
      }
    ],
    benefits: {
      healthInsurance: "Blue Cross Blue Shield Premium",
      dentalInsurance: "Delta Dental",
      visionInsurance: "VSP",
      lifeInsurance: 500000,
      disabilityInsurance: "Long-term disability coverage",
      retirementPlan: "403(b) with 5% match",
      vacationDays: 25,
      sickDays: 12,
      personalDays: 3
    },
    credentials: {
      username: "jwilson",
      password: "SecurePass456!",
      lastLogin: "2024-10-15T07:45:00Z",
      failedLoginAttempts: 1,
      passwordLastChanged: "2024-08-15",
      mfaEnabled: false,
      accessLevel: "physician",
      permissions: ["view_patients", "edit_patients", "prescribe_medications", "view_labs"]
    },
    medicalInfo: {
      healthInsurance: "Blue Cross Blue Shield",
      emergencyContact: {
        name: "Maria Wilson",
        relationship: "Wife",
        phone: "(555) 100-0004"
      },
      allergies: [],
      medications: ["Blood pressure medication"]
    },
    financialInfo: {
      bankAccountNumber: "2222222222",
      bankRoutingNumber: "021000002",
      directDepositAmount: 9833.33,
      taxWithholding: 2950.00,
      retirementContribution: 1475.00
    },
    backgroundCheck: {
      criminalHistory: ["DUI - 2010 (expunged)"],
      creditScore: 720,
      drugTestResults: "Negative",
      referenceChecks: [
        {
          name: "Dr. Lisa Brown",
          relationship: "Former Colleague",
          phone: "(555) 200-0002",
          comments: "Good physician, sometimes disorganized",
          rating: 4
        }
      ]
    }
  },
  {
    id: "E003",
    firstName: "Sarah",
    lastName: "Thompson",
    email: "sarah.thompson@medcare.com",
    phone: "(555) 100-0005",
    address: "300 Administrator Ave, Springfield, IL 62703",
    dateOfBirth: "1970-12-03",
    ssn: "333-33-3333",
    employeeId: "EMP-003",
    department: "Administration",
    position: "Chief Medical Officer",
    salary: 350000,
    hireDate: "2018-01-01",
    status: "active",
    performanceReviews: [
      {
        id: "PR003",
        reviewDate: "2024-01-15",
        reviewer: "Board of Directors",
        rating: 5,
        comments: "Exceptional leadership and strategic vision. Key driver of organizational success.",
        goals: ["Implement new quality metrics", "Reduce physician turnover"],
        salaryIncrease: 25000
      }
    ],
    disciplinaryActions: [],
    benefits: {
      healthInsurance: "Blue Cross Blue Shield Executive",
      dentalInsurance: "Delta Dental Premium",
      visionInsurance: "VSP Premium",
      lifeInsurance: 1000000,
      disabilityInsurance: "Executive disability coverage",
      retirementPlan: "401(k) with 10% match",
      vacationDays: 30,
      sickDays: 15,
      personalDays: 5
    },
    credentials: {
      username: "sthompson",
      password: "AdminPass789!",
      lastLogin: "2024-10-15T06:00:00Z",
      failedLoginAttempts: 0,
      passwordLastChanged: "2024-07-01",
      mfaEnabled: true,
      mfaSecret: "KRSXG5BAIV3E6Q2Z",
      accessLevel: "admin",
      permissions: ["view_all", "edit_all", "admin_access", "financial_data", "employee_data", "system_config"]
    },
    medicalInfo: {
      healthInsurance: "Blue Cross Blue Shield Executive",
      emergencyContact: {
        name: "John Thompson",
        relationship: "Husband",
        phone: "(555) 100-0006"
      },
      allergies: ["Shellfish"],
      medications: ["Cholesterol medication"]
    },
    financialInfo: {
      bankAccountNumber: "3333333333",
      bankRoutingNumber: "021000003",
      directDepositAmount: 11666.67,
      taxWithholding: 3500.00,
      retirementContribution: 3500.00
    },
    backgroundCheck: {
      criminalHistory: [],
      creditScore: 820,
      drugTestResults: "Negative",
      referenceChecks: [
        {
          name: "Dr. Robert Johnson",
          relationship: "Former CMO",
          phone: "(555) 200-0003",
          comments: "Outstanding leader with excellent strategic thinking",
          rating: 5
        }
      ]
    }
  },
  {
    id: "E004",
    firstName: "Nurse",
    lastName: "Smith",
    email: "nurse.smith@medcare.com",
    phone: "(555) 100-0007",
    address: "400 Nursing Blvd, Springfield, IL 62704",
    dateOfBirth: "1985-04-18",
    ssn: "444-44-4444",
    employeeId: "EMP-004",
    department: "Nursing",
    position: "Registered Nurse",
    salary: 75000,
    hireDate: "2021-06-01",
    status: "active",
    performanceReviews: [
      {
        id: "PR004",
        reviewDate: "2024-01-15",
        reviewer: "Nurse Manager",
        rating: 4,
        comments: "Good clinical skills and patient care. Needs improvement in time management.",
        goals: ["Improve efficiency", "Complete BSN degree"],
        salaryIncrease: 3000
      }
    ],
    disciplinaryActions: [],
    benefits: {
      healthInsurance: "Blue Cross Blue Shield Standard",
      dentalInsurance: "Delta Dental",
      visionInsurance: "VSP",
      lifeInsurance: 250000,
      disabilityInsurance: "Short-term disability coverage",
      retirementPlan: "403(b) with 3% match",
      vacationDays: 15,
      sickDays: 10,
      personalDays: 2
    },
    credentials: {
      username: "nsmith",
      password: "NursePass123!",
      lastLogin: "2024-10-15T09:15:00Z",
      failedLoginAttempts: 0,
      passwordLastChanged: "2024-09-15",
      mfaEnabled: false,
      accessLevel: "nurse",
      permissions: ["view_patients", "edit_vitals", "view_medications", "view_schedule"]
    },
    medicalInfo: {
      healthInsurance: "Blue Cross Blue Shield",
      emergencyContact: {
        name: "Mike Smith",
        relationship: "Brother",
        phone: "(555) 100-0008"
      },
      allergies: ["Latex"],
      medications: ["Birth control"]
    },
    financialInfo: {
      bankAccountNumber: "4444444444",
      bankRoutingNumber: "021000004",
      directDepositAmount: 2500.00,
      taxWithholding: 750.00,
      retirementContribution: 225.00
    },
    backgroundCheck: {
      criminalHistory: [],
      creditScore: 650,
      drugTestResults: "Negative",
      referenceChecks: [
        {
          name: "Jane Doe",
          relationship: "Former Supervisor",
          phone: "(555) 200-0004",
          comments: "Reliable nurse with good patient interaction",
          rating: 4
        }
      ]
    }
  }
];

export function getEmployeeById(id: string): Employee | undefined {
  return mockEmployees.find(employee => employee.id === id);
}

export function getAllEmployees(): Employee[] {
  return mockEmployees;
}

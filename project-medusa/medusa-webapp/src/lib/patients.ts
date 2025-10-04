// Mock patient data for the EHR system

export interface Patient {
  id: string;
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  gender: string;
  bloodType: string;
  allergies: string[];
  conditions: string[];
  medications: string[];
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
    medications: ["Metformin 500mg", "Lisinopril 10mg"],
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
    primaryPhysician: "Dr. Emily Chen"
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
    medications: ["Albuterol Inhaler", "Cetirizine 10mg"],
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
    primaryPhysician: "Dr. James Wilson"
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
    medications: ["Sumatriptan 50mg", "Sertraline 25mg"],
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
    primaryPhysician: "Dr. Sarah Thompson"
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
    medications: ["Atorvastatin 40mg", "Aspirin 81mg", "Metoprolol 25mg"],
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
    primaryPhysician: "Dr. Robert Davis"
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
    medications: ["Iron Supplement", "Vitamin D3"],
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
    primaryPhysician: "Dr. Patricia Moore"
  }
];

export function getPatientById(id: string): Patient | undefined {
  return mockPatients.find(patient => patient.id === id);
}

export function getAllPatients(): Patient[] {
  return mockPatients;
}


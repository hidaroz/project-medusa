// Highly sensitive system configuration data that would be extremely valuable to hackers

export interface SystemConfig {
  database: {
    host: string;
    port: number;
    username: string;
    password: string;
    databaseName: string;
    connectionString: string;
    backupLocation: string;
    encryptionKey: string;
  };
  api: {
    baseUrl: string;
    apiKey: string;
    secretKey: string;
    jwtSecret: string;
    encryptionKey: string;
  };
  backup: {
    locations: string[];
    schedule: string;
    retentionDays: number;
    encryptionKey: string;
    cloudProvider: string;
    cloudCredentials: {
      accessKey: string;
      secretKey: string;
      bucketName: string;
    };
  };
  security: {
    firewallRules: FirewallRule[];
    sslCertificates: SSLCertificate[];
    encryptionKeys: EncryptionKey[];
    securityIncidents: SecurityIncident[];
    auditLogs: AuditLog[];
  };
  compliance: {
    hipaaViolations: HIPAAViolation[];
    securityAudits: SecurityAudit[];
    complianceReports: ComplianceReport[];
  };
  network: {
    internalNetworks: string[];
    vpnConfigurations: VPNConfig[];
    networkTopology: NetworkTopology;
  };
}

export interface FirewallRule {
  id: string;
  source: string;
  destination: string;
  port: number;
  protocol: string;
  action: 'allow' | 'deny';
  description: string;
}

export interface SSLCertificate {
  id: string;
  domain: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  privateKey: string;
  certificate: string;
}

export interface EncryptionKey {
  id: string;
  algorithm: string;
  keySize: number;
  key: string;
  created: string;
  expires: string;
  purpose: string;
}

export interface SecurityIncident {
  id: string;
  date: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  description: string;
  affectedSystems: string[];
  resolution: string;
  reportedBy: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  userId: string;
  action: string;
  resource: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  details: string;
}

export interface HIPAAViolation {
  id: string;
  date: string;
  type: string;
  description: string;
  affectedPatients: string[];
  severity: 'minor' | 'moderate' | 'major' | 'critical';
  resolution: string;
  reportedTo: string;
}

export interface SecurityAudit {
  id: string;
  date: string;
  auditor: string;
  findings: string[];
  recommendations: string[];
  complianceScore: number;
  nextAuditDate: string;
}

export interface ComplianceReport {
  id: string;
  type: string;
  period: string;
  findings: string[];
  recommendations: string[];
  status: 'compliant' | 'non-compliant' | 'under-review';
}

export interface VPNConfig {
  id: string;
  name: string;
  server: string;
  username: string;
  password: string;
  sharedSecret: string;
  enabled: boolean;
}

export interface NetworkTopology {
  subnets: string[];
  gateways: string[];
  dnsServers: string[];
  dhcpServers: string[];
  switches: string[];
  routers: string[];
}

export const systemConfig: SystemConfig = {
  database: {
    host: "prod-db-01.medcare.internal",
    port: 5432,
    username: "medcare_admin",
    password: "SuperSecureDBPass123!",
    databaseName: "medcare_production",
    connectionString: "postgresql://medcare_admin:SuperSecureDBPass123!@prod-db-01.medcare.internal:5432/medcare_production",
    backupLocation: "/backup/database/daily/",
    encryptionKey: "DB_ENCRYPTION_KEY_2024_SECURE"
  },
  api: {
    baseUrl: "https://api.medcare.com",
    apiKey: "MC_API_KEY_2024_XYZ789",
    secretKey: "MC_SECRET_KEY_ULTRA_SECURE_2024",
    jwtSecret: "JWT_SECRET_FOR_MEDCARE_2024",
    encryptionKey: "API_ENCRYPTION_KEY_SECURE_2024"
  },
  backup: {
    locations: [
      "/backup/database/",
      "/backup/files/",
      "/backup/configs/",
      "s3://medcare-backups-prod/",
      "gs://medcare-backups-prod/"
    ],
    schedule: "0 2 * * *",
    retentionDays: 365,
    encryptionKey: "BACKUP_ENCRYPTION_KEY_2024",
    cloudProvider: "AWS",
    cloudCredentials: {
      accessKey: "AKIAIOSFODNN7EXAMPLE",
      secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      bucketName: "medcare-backups-prod"
    }
  },
  security: {
    firewallRules: [
      {
        id: "FW001",
        source: "0.0.0.0/0",
        destination: "10.0.0.0/8",
        port: 22,
        protocol: "TCP",
        action: "allow",
        description: "SSH access from anywhere"
      },
      {
        id: "FW002",
        source: "0.0.0.0/0",
        destination: "10.0.0.0/8",
        port: 3389,
        protocol: "TCP",
        action: "allow",
        description: "RDP access from anywhere"
      }
    ],
    sslCertificates: [
      {
        id: "SSL001",
        domain: "medcare.com",
        issuer: "Let's Encrypt",
        validFrom: "2024-01-01",
        validTo: "2024-12-31",
        privateKey: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----",
        certificate: "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKoK/Ovj8FQzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV...\n-----END CERTIFICATE-----"
      }
    ],
    encryptionKeys: [
      {
        id: "KEY001",
        algorithm: "AES-256",
        keySize: 256,
        key: "AES256_ENCRYPTION_KEY_FOR_PATIENT_DATA_2024",
        created: "2024-01-01",
        expires: "2025-01-01",
        purpose: "Patient data encryption"
      }
    ],
    securityIncidents: [
      {
        id: "INC001",
        date: "2024-09-15",
        severity: "high",
        type: "Unauthorized access attempt",
        description: "Multiple failed login attempts from suspicious IP",
        affectedSystems: ["Web Server", "Database"],
        resolution: "IP blocked, additional monitoring enabled",
        reportedBy: "Security Team"
      }
    ],
    auditLogs: [
      {
        id: "AUDIT001",
        timestamp: "2024-10-15T10:30:00Z",
        userId: "echen",
        action: "VIEW_PATIENT_RECORD",
        resource: "Patient P001",
        ipAddress: "192.168.1.100",
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        success: true,
        details: "Viewed patient Sarah Johnson's complete medical record"
      }
    ]
  },
  compliance: {
    hipaaViolations: [
      {
        id: "HIPAA001",
        date: "2024-08-20",
        type: "Unauthorized disclosure",
        description: "Patient data sent to wrong email address",
        affectedPatients: ["P001", "P002"],
        severity: "moderate",
        resolution: "Email system updated with additional validation",
        reportedTo: "HHS OCR"
      }
    ],
    securityAudits: [
      {
        id: "AUDIT001",
        date: "2024-06-15",
        auditor: "External Security Firm",
        findings: [
          "Weak password policies",
          "Outdated SSL certificates",
          "Insufficient network segmentation"
        ],
        recommendations: [
          "Implement stronger password requirements",
          "Update SSL certificates",
          "Improve network segmentation"
        ],
        complianceScore: 75,
        nextAuditDate: "2024-12-15"
      }
    ],
    complianceReports: [
      {
        id: "COMP001",
        type: "HIPAA Compliance",
        period: "Q3 2024",
        findings: [
          "Minor violations in email handling",
          "Good overall compliance posture"
        ],
        recommendations: [
          "Improve email validation",
          "Continue current security practices"
        ],
        status: "compliant"
      }
    ]
  },
  network: {
    internalNetworks: [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ],
    vpnConfigurations: [
      {
        id: "VPN001",
        name: "Employee VPN",
        server: "vpn.medcare.com",
        username: "vpn_user",
        password: "VPN_PASSWORD_2024",
        sharedSecret: "VPN_SHARED_SECRET_KEY",
        enabled: true
      }
    ],
    networkTopology: {
      subnets: ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"],
      gateways: ["10.0.1.1", "10.0.2.1", "10.0.3.1"],
      dnsServers: ["8.8.8.8", "8.8.4.4", "10.0.1.10"],
      dhcpServers: ["10.0.1.20", "10.0.2.20"],
      switches: ["SW-001", "SW-002", "SW-003"],
      routers: ["RTR-001", "RTR-002"]
    }
  }
};

export function getSystemConfig(): SystemConfig {
  return systemConfig;
}

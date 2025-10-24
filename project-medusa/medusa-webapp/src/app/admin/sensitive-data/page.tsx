'use client';

import { useState, useEffect } from 'react';
import Layout from '@/components/Layout';
import { getAllPatients, getAllEmployees, getSystemConfig, Patient, Employee, SystemConfig } from '@/lib/api';

export default function SensitiveDataPage() {
  const [activeTab, setActiveTab] = useState<'patients' | 'employees' | 'system'>('patients');
  const [selectedPatient, setSelectedPatient] = useState<string | null>(null);
  const [selectedEmployee, setSelectedEmployee] = useState<string | null>(null);
  const [patients, setPatients] = useState<Patient[]>([]);
  const [employees, setEmployees] = useState<Employee[]>([]);
  const [systemConfig, setSystemConfig] = useState<SystemConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const [patientsData, employeesData] = await Promise.all([
          getAllPatients(),
          getAllEmployees()
        ]);
        setPatients(patientsData);
        setEmployees(employeesData);
        setSystemConfig(getSystemConfig());
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch data');
        console.error('Error fetching data:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const getTotalSensitiveDataValue = () => {
    // Calculate total value of sensitive data
    const patientDataValue = patients.length * 1500; // $1500 per patient record
    const employeeDataValue = employees.length * 800; // $800 per employee record
    const systemDataValue = 50000; // $50k for system config
    return patientDataValue + employeeDataValue + systemDataValue;
  };

  const getRiskLevel = () => {
    const totalValue = getTotalSensitiveDataValue();
    if (totalValue > 100000) return { level: 'CRITICAL', color: 'text-red-500' };
    if (totalValue > 50000) return { level: 'HIGH', color: 'text-orange-500' };
    if (totalValue > 25000) return { level: 'MEDIUM', color: 'text-yellow-500' };
    return { level: 'LOW', color: 'text-green-500' };
  };

  const riskLevel = getRiskLevel();

  if (loading) {
    return (
      <Layout>
        <div className="p-8">
          <div className="flex items-center justify-center h-64">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
              <p className="text-slate-400">Loading sensitive data...</p>
            </div>
          </div>
        </div>
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout>
        <div className="p-8">
          <div className="flex items-center justify-center h-64">
            <div className="text-center">
              <div className="w-12 h-12 bg-red-600/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">Error Loading Data</h3>
              <p className="text-slate-400 mb-4">{error}</p>
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
              >
                Retry
              </button>
            </div>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="p-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">Sensitive Data Dashboard</h2>
          <p className="text-slate-400">⚠️ HIGHLY CONFIDENTIAL - Contains extremely sensitive information</p>
        </div>

        {/* Risk Assessment */}
        <div className="bg-red-900/30 border-2 border-red-600 rounded-lg p-6 mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-xl font-bold text-red-400 mb-2">🚨 CRITICAL SECURITY RISK</h3>
              <p className="text-red-300">
                This system contains highly valuable data that would be extremely attractive to hackers for ransom attacks.
              </p>
            </div>
            <div className="text-right">
              <div className="text-3xl font-bold text-white">${getTotalSensitiveDataValue().toLocaleString()}</div>
              <div className="text-sm text-slate-400">Total Data Value</div>
              <div className={`text-lg font-semibold ${riskLevel.color}`}>
                {riskLevel.level} RISK
              </div>
            </div>
          </div>
        </div>

        {/* Data Categories */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">Patient Records</p>
                <p className="text-3xl font-bold text-white">{patients.length}</p>
                <p className="text-sm text-red-400">SSN, Credit Cards, Medical History</p>
              </div>
              <div className="w-12 h-12 bg-red-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">Employee Records</p>
                <p className="text-3xl font-bold text-white">{employees.length}</p>
                <p className="text-sm text-red-400">Salaries, SSN, Performance Reviews</p>
              </div>
              <div className="w-12 h-12 bg-orange-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">System Config</p>
                <p className="text-3xl font-bold text-white">1</p>
                <p className="text-sm text-red-400">Database Passwords, API Keys</p>
              </div>
              <div className="w-12 h-12 bg-purple-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <div className="flex space-x-4 mb-6">
            <button
              onClick={() => setActiveTab('patients')}
              className={`px-4 py-2 rounded-lg font-medium transition ${
                activeTab === 'patients'
                  ? 'bg-red-600 text-white'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              Patient Data
            </button>
            <button
              onClick={() => setActiveTab('employees')}
              className={`px-4 py-2 rounded-lg font-medium transition ${
                activeTab === 'employees'
                  ? 'bg-orange-600 text-white'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              Employee Data
            </button>
            <button
              onClick={() => setActiveTab('system')}
              className={`px-4 py-2 rounded-lg font-medium transition ${
                activeTab === 'system'
                  ? 'bg-purple-600 text-white'
                  : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
              }`}
            >
              System Config
            </button>
          </div>

          {/* Patient Data Tab */}
          {activeTab === 'patients' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Patient Records</h3>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {patients.map((patient) => (
                    <div
                      key={patient.id}
                      onClick={() => setSelectedPatient(patient.id)}
                      className={`p-3 rounded-lg cursor-pointer transition ${
                        selectedPatient === patient.id
                          ? 'bg-red-600/20 border border-red-600/50'
                          : 'bg-slate-900 hover:bg-slate-700'
                      }`}
                    >
                      <div className="text-sm font-medium text-white">{patient.firstName} {patient.lastName}</div>
                      <div className="text-xs text-slate-400">SSN: {patient.ssn}</div>
                      <div className="text-xs text-red-400">Credit Card: {patient.financialInfo.creditCardNumber}</div>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                {selectedPatient && (
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-4">Sensitive Details</h3>
                    {(() => {
                      const patient = patients.find(p => p.id === selectedPatient);
                      if (!patient) return null;
                      return (
                        <div className="bg-slate-900 rounded-lg p-4 space-y-4">
                          <div>
                            <h4 className="text-sm font-medium text-red-400 mb-2">Financial Information</h4>
                            <div className="text-xs text-slate-300 space-y-1">
                              <div>Credit Card: {patient.financialInfo.creditCardNumber}</div>
                              <div>Expiry: {patient.financialInfo.creditCardExpiry}</div>
                              <div>CVV: {patient.financialInfo.creditCardCVV}</div>
                              <div>Bank Account: {patient.financialInfo.bankAccountNumber}</div>
                              <div>Routing: {patient.financialInfo.bankRoutingNumber}</div>
                              <div>Balance: ${patient.financialInfo.outstandingBalance}</div>
                            </div>
                          </div>
                          <div>
                            <h4 className="text-sm font-medium text-red-400 mb-2">Sensitive Conditions</h4>
                            <div className="text-xs text-slate-300">
                              {patient.sensitiveConditions.join(', ')}
                            </div>
                          </div>
                          <div>
                            <h4 className="text-sm font-medium text-red-400 mb-2">Biometric Data</h4>
                            <div className="text-xs text-slate-300 space-y-1">
                              {patient.biometricData.fingerprints && <div>Fingerprints: {patient.biometricData.fingerprints.substring(0, 50)}...</div>}
                              {patient.biometricData.retinalScan && <div>Retinal Scan: {patient.biometricData.retinalScan.substring(0, 50)}...</div>}
                              {patient.biometricData.dnaProfile && <div>DNA Profile: {patient.biometricData.dnaProfile}</div>}
                            </div>
                          </div>
                        </div>
                      );
                    })()}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Employee Data Tab */}
          {activeTab === 'employees' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-4">Employee Records</h3>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {employees.map((employee) => (
                    <div
                      key={employee.id}
                      onClick={() => setSelectedEmployee(employee.id)}
                      className={`p-3 rounded-lg cursor-pointer transition ${
                        selectedEmployee === employee.id
                          ? 'bg-orange-600/20 border border-orange-600/50'
                          : 'bg-slate-900 hover:bg-slate-700'
                      }`}
                    >
                      <div className="text-sm font-medium text-white">{employee.firstName} {employee.lastName}</div>
                      <div className="text-xs text-slate-400">SSN: {employee.ssn}</div>
                      <div className="text-xs text-orange-400">Salary: ${employee.salary.toLocaleString()}</div>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                {selectedEmployee && (
                  <div>
                    <h3 className="text-lg font-semibold text-white mb-4">Sensitive Details</h3>
                    {(() => {
                      const employee = employees.find(e => e.id === selectedEmployee);
                      if (!employee) return null;
                      return (
                        <div className="bg-slate-900 rounded-lg p-4 space-y-4">
                          <div>
                            <h4 className="text-sm font-medium text-orange-400 mb-2">Credentials</h4>
                            <div className="text-xs text-slate-300 space-y-1">
                              <div>Username: {employee.credentials.username}</div>
                              <div>Password: {employee.credentials.password}</div>
                              <div>MFA Secret: {employee.credentials.mfaSecret}</div>
                              <div>Access Level: {employee.credentials.accessLevel}</div>
                            </div>
                          </div>
                          <div>
                            <h4 className="text-sm font-medium text-orange-400 mb-2">Financial Information</h4>
                            <div className="text-xs text-slate-300 space-y-1">
                              <div>Bank Account: {employee.financialInfo.bankAccountNumber}</div>
                              <div>Routing: {employee.financialInfo.bankRoutingNumber}</div>
                              <div>Direct Deposit: ${employee.financialInfo.directDepositAmount}</div>
                            </div>
                          </div>
                          <div>
                            <h4 className="text-sm font-medium text-orange-400 mb-2">Background Check</h4>
                            <div className="text-xs text-slate-300 space-y-1">
                              <div>Credit Score: {employee.backgroundCheck.creditScore}</div>
                              <div>Criminal History: {employee.backgroundCheck.criminalHistory.join(', ') || 'None'}</div>
                              <div>Drug Test: {employee.backgroundCheck.drugTestResults}</div>
                            </div>
                          </div>
                        </div>
                      );
                    })()}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* System Config Tab */}
          {activeTab === 'system' && systemConfig && (
            <div className="space-y-6">
              <div className="bg-slate-900 rounded-lg p-4">
                <h4 className="text-sm font-medium text-purple-400 mb-2">Database Configuration</h4>
                <div className="text-xs text-slate-300 space-y-1">
                  <div>Host: {systemConfig.database.host}</div>
                  <div>Username: {systemConfig.database.username}</div>
                  <div>Password: {systemConfig.database.password}</div>
                  <div>Connection String: {systemConfig.database.connectionString}</div>
                  <div>Encryption Key: {systemConfig.database.encryptionKey}</div>
                </div>
              </div>
              <div className="bg-slate-900 rounded-lg p-4">
                <h4 className="text-sm font-medium text-purple-400 mb-2">API Configuration</h4>
                <div className="text-xs text-slate-300 space-y-1">
                  <div>API Key: {systemConfig.api.apiKey}</div>
                  <div>Secret Key: {systemConfig.api.secretKey}</div>
                  <div>JWT Secret: {systemConfig.api.jwtSecret}</div>
                  <div>Encryption Key: {systemConfig.api.encryptionKey}</div>
                </div>
              </div>
              <div className="bg-slate-900 rounded-lg p-4">
                <h4 className="text-sm font-medium text-purple-400 mb-2">Cloud Credentials</h4>
                <div className="text-xs text-slate-300 space-y-1">
                  <div>Access Key: {systemConfig.backup.cloudCredentials.accessKey}</div>
                  <div>Secret Key: {systemConfig.backup.cloudCredentials.secretKey}</div>
                  <div>Bucket: {systemConfig.backup.cloudCredentials.bucketName}</div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}

'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { getPatientById, Patient } from '@/lib/api';
import Layout from '@/components/Layout';

export default function PatientDetailPage({ params }: { params: { id: string } }) {
  const [patient, setPatient] = useState<Patient | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchPatient = async () => {
      try {
        setLoading(true);
        const data = await getPatientById(params.id);
        setPatient(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch patient');
        console.error('Error fetching patient:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchPatient();
  }, [params.id]);

  if (loading) {
    return (
      <Layout>
        <div className="p-8">
          <div className="flex items-center justify-center h-64">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
              <p className="text-slate-400">Loading patient data...</p>
            </div>
          </div>
        </div>
      </Layout>
    );
  }

  if (error || !patient) {
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
              <h1 className="text-2xl font-bold text-white mb-2">
                {error ? 'Error Loading Patient' : 'Patient Not Found'}
              </h1>
              <p className="text-slate-400 mb-4">
                {error || 'The requested patient could not be found.'}
              </p>
              <Link
                href="/dashboard"
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
              >
                Return to Dashboard
              </Link>
            </div>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="p-8">
        {/* Patient Header */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center">
              <div className="w-16 h-16 bg-blue-600 rounded-full flex items-center justify-center mr-4">
                <span className="text-white text-2xl font-bold">
                  {patient.firstName[0]}{patient.lastName[0]}
                </span>
              </div>
              <div>
                <h2 className="text-2xl font-bold text-white mb-1">
                  {patient.firstName} {patient.lastName}
                </h2>
                <div className="flex items-center space-x-4 text-sm text-slate-400">
                  <span>Patient ID: {patient.id}</span>
                  <span>MRN: {patient.mrn}</span>
                  <span className={`px-2 py-1 rounded-full text-xs ${
                    patient.status === 'active'
                      ? 'bg-green-600/20 text-green-400 border border-green-600/50'
                      : patient.status === 'inactive'
                      ? 'bg-yellow-600/20 text-yellow-400 border border-yellow-600/50'
                      : 'bg-red-600/20 text-red-400 border border-red-600/50'
                  }`}>
                    {patient.status.toUpperCase()}
                  </span>
                </div>
              </div>
            </div>
            <div className="text-right">
              <p className="text-sm text-slate-400 mb-1">Primary Physician</p>
              <p className="text-white font-medium">{patient.primaryPhysician}</p>
            </div>
          </div>
        </div>

        {/* Critical Allergy Alert */}
        {patient.allergies.length > 0 && (
          <div className="bg-red-900/30 border-2 border-red-600 rounded-lg p-4 mb-6">
            <div className="flex items-start">
              <div className="flex-shrink-0">
                <svg className="h-6 w-6 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div className="ml-3 flex-1">
                <h3 className="text-lg font-bold text-red-400 mb-2">⚠️ CRITICAL ALLERGY ALERT</h3>
                <div className="flex flex-wrap gap-2">
                  {patient.allergies.map((allergy, index) => (
                    <span key={index} className="px-3 py-1 bg-red-600 text-white font-semibold rounded-lg">
                      {allergy}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Patient Information Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          {/* Demographics */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <svg className="w-5 h-5 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
              </svg>
              Demographics
            </h3>
            <div className="space-y-3">
              <InfoRow label="Date of Birth" value={patient.dateOfBirth} />
              <InfoRow label="Gender" value={patient.gender} />
              <InfoRow label="Blood Type" value={patient.bloodType} />
              <InfoRow label="Phone" value={patient.phone} />
              <InfoRow label="Email" value={patient.email} />
              <InfoRow label="Address" value={patient.address} />
            </div>
          </div>

          {/* Insurance Information */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <svg className="w-5 h-5 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
              </svg>
              Insurance & Emergency Contact
            </h3>
            <div className="space-y-3">
              <InfoRow label="Insurance Provider" value={patient.insuranceProvider} />
              <InfoRow label="Insurance Number" value={patient.insuranceNumber} />
              <div className="pt-3 border-t border-slate-700">
                <p className="text-slate-400 text-sm mb-2">Emergency Contact</p>
                <InfoRow label="Name" value={patient.emergencyContact.name} />
                <InfoRow label="Relationship" value={patient.emergencyContact.relationship} />
                <InfoRow label="Phone" value={patient.emergencyContact.phone} />
              </div>
            </div>
          </div>
        </div>

        {/* Vital Signs */}
        {patient.vitalSigns.length > 0 && (
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <svg className="w-5 h-5 mr-2 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              Vital Signs
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {patient.vitalSigns[0] && (
                <>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">{patient.vitalSigns[0].temperature}°F</div>
                    <div className="text-xs text-slate-400">Temperature</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">{patient.vitalSigns[0].bloodPressure}</div>
                    <div className="text-xs text-slate-400">Blood Pressure</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">{patient.vitalSigns[0].heartRate} bpm</div>
                    <div className="text-xs text-slate-400">Heart Rate</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">{patient.vitalSigns[0].oxygenSaturation}%</div>
                    <div className="text-xs text-slate-400">O2 Sat</div>
                  </div>
                </>
              )}
            </div>
            <div className="mt-4 text-xs text-slate-500">
              Last recorded: {patient.vitalSigns[0]?.recordedDate} by {patient.vitalSigns[0]?.recordedBy}
            </div>
          </div>
        )}

        {/* Lab Results */}
        {patient.labResults.length > 0 && (
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <svg className="w-5 h-5 mr-2 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
              </svg>
              Lab Results
            </h3>
            <div className="space-y-3">
              {patient.labResults.map((lab) => (
                <div key={lab.id} className="flex items-center justify-between p-3 bg-slate-900 rounded-lg">
                  <div className="flex-1">
                    <div className="font-medium text-white">{lab.testName}</div>
                    <div className="text-sm text-slate-300">
                      Result: {lab.result} {lab.unit && `(${lab.unit})`}
                      {lab.referenceRange && ` • Range: ${lab.referenceRange}`}
                    </div>
                    <div className="text-xs text-slate-500 mt-1">
                      Ordered: {lab.orderDate} • Result: {lab.resultDate} • {lab.orderingPhysician}
                    </div>
                  </div>
                  <span className={`px-3 py-1 text-xs rounded-full font-medium ${
                    lab.status === 'normal'
                      ? 'bg-green-600/20 text-green-400 border border-green-600/50'
                      : lab.status === 'abnormal'
                      ? 'bg-yellow-600/20 text-yellow-400 border border-yellow-600/50'
                      : 'bg-red-600/20 text-red-400 border border-red-600/50'
                  }`}>
                    {lab.status.toUpperCase()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Medical Information */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Current Medications */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <svg className="w-5 h-5 mr-2 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
              </svg>
              Current Medications
            </h3>
            <ul className="space-y-3">
              {patient.medications.map((med) => (
                <li key={med.id} className="text-slate-300 text-sm">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="font-medium text-white">{med.name} {med.dosage}</div>
                      <div className="text-xs text-slate-400 mt-1">
                        {med.frequency} • {med.route}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">
                        Started: {med.startDate} • Prescribed by: {med.prescribingPhysician}
                      </div>
                    </div>
                    <span className={`px-2 py-1 text-xs rounded-full ${
                      med.status === 'active'
                        ? 'bg-green-600/20 text-green-400 border border-green-600/50'
                        : med.status === 'discontinued'
                        ? 'bg-red-600/20 text-red-400 border border-red-600/50'
                        : 'bg-gray-600/20 text-gray-400 border border-gray-600/50'
                    }`}>
                      {med.status}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          </div>

          {/* Medical Conditions */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <svg className="w-5 h-5 mr-2 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
              Medical Conditions
            </h3>
            <ul className="space-y-2">
              {patient.conditions.map((condition, index) => (
                <li key={index} className="text-slate-300 text-sm flex items-start">
                  <span className="text-yellow-500 mr-2">•</span>
                  {condition}
                </li>
              ))}
            </ul>
          </div>

          {/* Appointments */}
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
              <svg className="w-5 h-5 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
              Appointments
            </h3>
            <div className="space-y-3">
              <div>
                <p className="text-slate-400 text-sm">Last Visit</p>
                <p className="text-white font-medium">{patient.lastVisit}</p>
              </div>
              <div>
                <p className="text-slate-400 text-sm">Next Appointment</p>
                <p className="text-white font-medium">{patient.nextAppointment}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between items-start">
      <span className="text-slate-400 text-sm">{label}:</span>
      <span className="text-white text-sm text-right">{value}</span>
    </div>
  );
}


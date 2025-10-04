import Link from 'next/link';
import { getPatientById, getAllPatients } from '@/lib/patients';

export async function generateStaticParams() {
  const patients = getAllPatients();
  return patients.map((patient) => ({
    id: patient.id,
  }));
}

export default function PatientDetailPage({ params }: { params: { id: string } }) {
  const patient = getPatientById(params.id);

  if (!patient) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-white mb-2">Patient Not Found</h1>
          <Link href="/dashboard" className="text-blue-400 hover:text-blue-300">
            Return to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <div className="flex items-center justify-center w-10 h-10 bg-blue-600 rounded-lg mr-3">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <h1 className="text-xl font-bold text-white">MedCare EHR</h1>
            </div>
            <div className="flex items-center space-x-4">
              <Link 
                href="/dashboard"
                className="px-4 py-2 text-sm bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition"
              >
                ← Back to Dashboard
              </Link>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
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
                <p className="text-slate-400">Patient ID: {patient.id}</p>
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
            <ul className="space-y-2">
              {patient.medications.map((med, index) => (
                <li key={index} className="text-slate-300 text-sm flex items-start">
                  <span className="text-green-500 mr-2">•</span>
                  {med}
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
      </main>
    </div>
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


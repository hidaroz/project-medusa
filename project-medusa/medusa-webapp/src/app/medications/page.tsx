'use client';

import { useState } from 'react';
import Link from 'next/link';
import { getAllPatients } from '@/lib/patients';
import Layout from '@/components/Layout';

export default function MedicationsPage() {
  const [filter, setFilter] = useState<'all' | 'active' | 'discontinued' | 'completed'>('all');
  const [searchTerm, setSearchTerm] = useState('');
  
  const patients = getAllPatients();
  
  // Flatten all medications from all patients
  const allMedications = patients.flatMap(patient => 
    patient.medications.map(med => ({
      ...med,
      patientId: patient.id,
      patientName: `${patient.firstName} ${patient.lastName}`,
      patientAllergies: patient.allergies
    }))
  );

  const filteredMedications = allMedications.filter(med => {
    const statusMatch = filter === 'all' || med.status === filter;
    const searchMatch = searchTerm === '' || 
      med.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      med.patientName.toLowerCase().includes(searchTerm.toLowerCase());
    return statusMatch && searchMatch;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-green-600/20 text-green-400 border border-green-600/50';
      case 'discontinued': return 'bg-red-600/20 text-red-400 border border-red-600/50';
      case 'completed': return 'bg-blue-600/20 text-blue-400 border border-blue-600/50';
      default: return 'bg-gray-600/20 text-gray-400 border border-gray-600/50';
    }
  };

  const getRouteColor = (route: string) => {
    switch (route.toLowerCase()) {
      case 'oral': return 'bg-blue-600/20 text-blue-400';
      case 'inhalation': return 'bg-purple-600/20 text-purple-400';
      case 'injection': return 'bg-red-600/20 text-red-400';
      case 'topical': return 'bg-green-600/20 text-green-400';
      default: return 'bg-gray-600/20 text-gray-400';
    }
  };

  return (
    <Layout>
      <div className="p-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">Medication Management</h2>
          <p className="text-slate-400">Manage patient medications and prescriptions</p>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">Total Medications</p>
                <p className="text-3xl font-bold text-white">{allMedications.length}</p>
              </div>
              <div className="w-12 h-12 bg-blue-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">Active Medications</p>
                <p className="text-3xl font-bold text-white">
                  {allMedications.filter(m => m.status === 'active').length}
                </p>
              </div>
              <div className="w-12 h-12 bg-green-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">Discontinued</p>
                <p className="text-3xl font-bold text-white">
                  {allMedications.filter(m => m.status === 'discontinued').length}
                </p>
              </div>
              <div className="w-12 h-12 bg-red-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">Unique Medications</p>
                <p className="text-3xl font-bold text-white">
                  {new Set(allMedications.map(m => m.name)).size}
                </p>
              </div>
              <div className="w-12 h-12 bg-purple-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Filters and Search */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Medication Management</h3>
            <div className="flex items-center space-x-3">
              <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm transition">
                New Prescription
              </button>
              <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm transition">
                Medication Review
              </button>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <div className="flex-1">
              <label className="block text-sm text-slate-400 mb-2">Search Medications</label>
              <input
                type="text"
                placeholder="Search by medication name or patient..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-white text-sm placeholder-slate-500"
              />
            </div>
            <div className="flex-1">
              <label className="block text-sm text-slate-400 mb-2">Filter by Status</label>
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value as any)}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-white text-sm"
              >
                <option value="all">All Medications</option>
                <option value="active">Active</option>
                <option value="discontinued">Discontinued</option>
                <option value="completed">Completed</option>
              </select>
            </div>
          </div>
        </div>

        {/* Medications List */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-700">
            <h3 className="text-lg font-semibold text-white">Medications</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-900">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Patient</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Medication</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Dosage & Frequency</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Route</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Prescribing Physician</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Start Date</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {filteredMedications.map((medication) => (
                  <tr key={medication.id} className="hover:bg-slate-750 transition">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="w-10 h-10 bg-blue-600 rounded-full flex items-center justify-center mr-4">
                          <span className="text-white text-sm font-medium">
                            {medication.patientName.split(' ').map(n => n[0]).join('')}
                          </span>
                        </div>
                        <div>
                          <div className="text-sm font-medium text-white">{medication.patientName}</div>
                          <div className="text-sm text-slate-400">ID: {medication.patientId}</div>
                          {medication.patientAllergies.length > 0 && (
                            <div className="text-xs text-red-400">⚠️ Allergies</div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-white">{medication.name}</div>
                      <div className="text-sm text-slate-400">{medication.dosage}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      {medication.frequency}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs rounded-full ${getRouteColor(medication.route)}`}>
                        {medication.route}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      {medication.prescribingPhysician}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      {medication.startDate}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(medication.status)}`}>
                        {medication.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <div className="flex items-center space-x-2">
                        <Link
                          href={`/patient/${medication.patientId}`}
                          className="text-blue-400 hover:text-blue-300 font-medium transition"
                        >
                          View Patient
                        </Link>
                        <button className="text-green-400 hover:text-green-300 font-medium transition">
                          Modify
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {filteredMedications.length === 0 && (
          <div className="text-center py-12">
            <div className="text-slate-400 mb-4">No medications found matching your criteria</div>
            <button
              onClick={() => {
                setSearchTerm('');
                setFilter('all');
              }}
              className="text-blue-400 hover:text-blue-300 font-medium"
            >
              Clear filters
            </button>
          </div>
        )}
      </div>
    </Layout>
  );
}

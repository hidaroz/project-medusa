'use client';

import { useState } from 'react';
import Link from 'next/link';
import { getAllPatients } from '@/lib/patients';
import Layout from '@/components/Layout';

export default function PatientSearchPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState(getAllPatients());
  const allPatients = getAllPatients();

  const handleSearch = (term: string) => {
    setSearchTerm(term);
    if (term.trim() === '') {
      setSearchResults(allPatients);
      return;
    }

    const filtered = allPatients.filter(patient => 
      patient.firstName.toLowerCase().includes(term.toLowerCase()) ||
      patient.lastName.toLowerCase().includes(term.toLowerCase()) ||
      patient.id.toLowerCase().includes(term.toLowerCase()) ||
      patient.mrn.toLowerCase().includes(term.toLowerCase()) ||
      patient.phone.includes(term) ||
      patient.email.toLowerCase().includes(term.toLowerCase())
    );
    setSearchResults(filtered);
  };

  return (
    <Layout>
      <div className="p-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">Patient Search</h2>
          <p className="text-slate-400">Search for patients by name, ID, MRN, phone, or email</p>
        </div>

        {/* Search Bar */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <svg className="h-5 w-5 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            <input
              type="text"
              className="w-full pl-10 pr-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Search patients..."
              value={searchTerm}
              onChange={(e) => handleSearch(e.target.value)}
            />
          </div>
          <div className="mt-4 text-sm text-slate-400">
            Found {searchResults.length} patient{searchResults.length !== 1 ? 's' : ''}
          </div>
        </div>

        {/* Search Results */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-700">
            <h3 className="text-lg font-semibold text-white">Search Results</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-900">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Patient</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">ID/MRN</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Contact</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Primary Physician</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {searchResults.map((patient) => (
                  <tr key={patient.id} className="hover:bg-slate-750 transition">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="w-10 h-10 bg-blue-600 rounded-full flex items-center justify-center mr-4">
                          <span className="text-white text-sm font-medium">
                            {patient.firstName[0]}{patient.lastName[0]}
                          </span>
                        </div>
                        <div>
                          <div className="text-sm font-medium text-white">
                            {patient.firstName} {patient.lastName}
                          </div>
                          <div className="text-sm text-slate-400">
                            DOB: {patient.dateOfBirth} • {patient.gender}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      <div>ID: {patient.id}</div>
                      <div className="text-xs text-slate-500">MRN: {patient.mrn}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      <div>{patient.phone}</div>
                      <div className="text-xs text-slate-500">{patient.email}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      {patient.primaryPhysician}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        patient.status === 'active' 
                          ? 'bg-green-600/20 text-green-400 border border-green-600/50'
                          : patient.status === 'inactive'
                          ? 'bg-yellow-600/20 text-yellow-400 border border-yellow-600/50'
                          : 'bg-red-600/20 text-red-400 border border-red-600/50'
                      }`}>
                        {patient.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <Link
                        href={`/patient/${patient.id}`}
                        className="text-blue-400 hover:text-blue-300 font-medium transition"
                      >
                        View Record →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {searchResults.length === 0 && searchTerm && (
          <div className="text-center py-12">
            <div className="text-slate-400 mb-4">No patients found matching &quot;{searchTerm}&quot;</div>
            <button
              onClick={() => handleSearch('')}
              className="text-blue-400 hover:text-blue-300 font-medium"
            >
              Clear search
            </button>
          </div>
        )}
      </div>
    </Layout>
  );
}

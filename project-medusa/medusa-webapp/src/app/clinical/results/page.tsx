'use client';

import { useState } from 'react';
import Layout from '@/components/Layout';

interface ClinicalResult {
  id: string;
  patientId: string;
  patientName: string;
  resultType: 'Lab' | 'Imaging' | 'Pathology' | 'Cardiology';
  testName: string;
  result: string;
  unit?: string;
  referenceRange?: string;
  status: 'Normal' | 'Abnormal' | 'Critical';
  orderingPhysician: string;
  resultDate: string;
  resultTime: string;
  notes?: string;
}

const mockResults: ClinicalResult[] = [
  {
    id: 'R001',
    patientId: 'P001',
    patientName: 'Sarah Johnson',
    resultType: 'Lab',
    testName: 'Hemoglobin A1C',
    result: '7.2',
    unit: '%',
    referenceRange: '<7.0',
    status: 'Abnormal',
    orderingPhysician: 'Dr. Emily Chen',
    resultDate: '2024-10-16',
    resultTime: '8:30 AM',
    notes: 'Elevated A1C indicates suboptimal diabetes control'
  },
  {
    id: 'R002',
    patientId: 'P002',
    patientName: 'Robert Martinez',
    resultType: 'Imaging',
    testName: 'Chest X-Ray',
    result: 'Clear lung fields, no acute findings',
    status: 'Normal',
    orderingPhysician: 'Dr. James Wilson',
    resultDate: '2024-10-15',
    resultTime: '3:45 PM',
    notes: 'No evidence of pneumonia or other acute pathology'
  },
  {
    id: 'R003',
    patientId: 'P004',
    patientName: 'James Williams',
    resultType: 'Cardiology',
    testName: 'Echocardiogram',
    result: 'EF 55%, mild mitral regurgitation',
    status: 'Normal',
    orderingPhysician: 'Dr. Robert Davis',
    resultDate: '2024-10-14',
    resultTime: '11:20 AM',
    notes: 'Normal left ventricular function'
  },
  {
    id: 'R004',
    patientId: 'P005',
    patientName: 'Lisa Anderson',
    resultType: 'Lab',
    testName: 'Hemoglobin',
    result: '11.8',
    unit: 'g/dL',
    referenceRange: '12.0-15.5',
    status: 'Abnormal',
    orderingPhysician: 'Dr. Patricia Moore',
    resultDate: '2024-10-13',
    resultTime: '2:15 PM',
    notes: 'Mild anemia, consistent with iron deficiency'
  }
];

export default function ClinicalResultsPage() {
  const [selectedResult, setSelectedResult] = useState<ClinicalResult | null>(null);
  const [filter, setFilter] = useState<'all' | 'normal' | 'abnormal' | 'critical'>('all');
  const [typeFilter, setTypeFilter] = useState<'all' | 'lab' | 'imaging' | 'pathology' | 'cardiology'>('all');

  const filteredResults = mockResults.filter(result => {
    const statusMatch = filter === 'all' || result.status.toLowerCase() === filter;
    const typeMatch = typeFilter === 'all' || result.resultType.toLowerCase() === typeFilter;
    return statusMatch && typeMatch;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Normal': return 'bg-green-600/20 text-green-400 border border-green-600/50';
      case 'Abnormal': return 'bg-yellow-600/20 text-yellow-400 border border-yellow-600/50';
      case 'Critical': return 'bg-red-600/20 text-red-400 border border-red-600/50';
      default: return 'bg-gray-600/20 text-gray-400 border border-gray-600/50';
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'Lab': return 'bg-blue-600/20 text-blue-400';
      case 'Imaging': return 'bg-purple-600/20 text-purple-400';
      case 'Pathology': return 'bg-orange-600/20 text-orange-400';
      case 'Cardiology': return 'bg-red-600/20 text-red-400';
      default: return 'bg-gray-600/20 text-gray-400';
    }
  };

  return (
    <Layout>
      <div className="p-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">Clinical Results</h2>
          <p className="text-slate-400">View and interpret clinical test results</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Results List */}
          <div className="lg:col-span-1">
            <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">Results</h3>
                <button className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm transition">
                  New Result
                </button>
              </div>

              {/* Filters */}
              <div className="space-y-3 mb-4">
                <select
                  value={filter}
                  onChange={(e) => setFilter(e.target.value as any)}
                  className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-white text-sm"
                >
                  <option value="all">All Status</option>
                  <option value="normal">Normal</option>
                  <option value="abnormal">Abnormal</option>
                  <option value="critical">Critical</option>
                </select>
                
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value as any)}
                  className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-white text-sm"
                >
                  <option value="all">All Types</option>
                  <option value="lab">Lab</option>
                  <option value="imaging">Imaging</option>
                  <option value="pathology">Pathology</option>
                  <option value="cardiology">Cardiology</option>
                </select>
              </div>

              {/* Results List */}
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {filteredResults.map((result) => (
                  <div
                    key={result.id}
                    onClick={() => setSelectedResult(result)}
                    className={`p-3 rounded-lg cursor-pointer transition ${
                      selectedResult?.id === result.id
                        ? 'bg-blue-600/20 border border-blue-600/50'
                        : 'bg-slate-900 hover:bg-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1">
                        <div className="text-sm font-medium text-white">{result.patientName}</div>
                        <div className="text-xs text-slate-400">{result.testName}</div>
                        <div className="text-xs text-slate-500">{result.resultDate} {result.resultTime}</div>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className={`px-2 py-1 text-xs rounded-full ${getTypeColor(result.resultType)}`}>
                        {result.resultType}
                      </span>
                      <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(result.status)}`}>
                        {result.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Result Detail */}
          <div className="lg:col-span-2">
            {selectedResult ? (
              <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
                <div className="flex items-start justify-between mb-6">
                  <div>
                    <h3 className="text-xl font-bold text-white mb-2">{selectedResult.patientName}</h3>
                    <div className="flex items-center space-x-4 text-sm text-slate-400">
                      <span>{selectedResult.resultType}</span>
                      <span>•</span>
                      <span>{selectedResult.resultDate} {selectedResult.resultTime}</span>
                      <span>•</span>
                      <span>{selectedResult.orderingPhysician}</span>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`px-3 py-1 text-sm rounded-full ${getTypeColor(selectedResult.resultType)}`}>
                      {selectedResult.resultType}
                    </span>
                    <span className={`px-3 py-1 text-sm rounded-full ${getStatusColor(selectedResult.status)}`}>
                      {selectedResult.status}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-6 mb-6">
                  <div className="bg-slate-900 rounded-lg p-4">
                    <h4 className="text-sm font-medium text-slate-300 mb-3">Test Information</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Test Name:</span>
                        <span className="text-white font-medium">{selectedResult.testName}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Result:</span>
                        <span className="text-white font-medium">
                          {selectedResult.result} {selectedResult.unit && `(${selectedResult.unit})`}
                        </span>
                      </div>
                      {selectedResult.referenceRange && (
                        <div className="flex justify-between">
                          <span className="text-slate-400">Reference Range:</span>
                          <span className="text-white">{selectedResult.referenceRange}</span>
                        </div>
                      )}
                      <div className="flex justify-between">
                        <span className="text-slate-400">Ordering Physician:</span>
                        <span className="text-white">{selectedResult.orderingPhysician}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-slate-900 rounded-lg p-4">
                    <h4 className="text-sm font-medium text-slate-300 mb-3">Result Details</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Result ID:</span>
                        <span className="text-white">{selectedResult.id}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Patient ID:</span>
                        <span className="text-white">{selectedResult.patientId}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Result Date:</span>
                        <span className="text-white">{selectedResult.resultDate}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Result Time:</span>
                        <span className="text-white">{selectedResult.resultTime}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {selectedResult.notes && (
                  <div className="bg-slate-900 rounded-lg p-4 mb-6">
                    <h4 className="text-sm font-medium text-slate-300 mb-3">Clinical Notes</h4>
                    <div className="text-slate-300 text-sm leading-relaxed">
                      {selectedResult.notes}
                    </div>
                  </div>
                )}

                <div className="flex items-center space-x-3">
                  <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm transition">
                    Add Note
                  </button>
                  <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm transition">
                    Print Result
                  </button>
                  <button className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg text-sm transition">
                    Send to Provider
                  </button>
                </div>
              </div>
            ) : (
              <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 flex items-center justify-center h-64">
                <div className="text-center">
                  <svg className="w-12 h-12 text-slate-500 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                  </svg>
                  <p className="text-slate-400">Select a result to view details</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}

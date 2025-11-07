'use client';

import { useState } from 'react';
import Layout from '@/components/Layout';

interface Report {
  id: string;
  name: string;
  description: string;
  category: 'Patient' | 'Clinical' | 'Administrative' | 'Financial';
  lastGenerated: string;
  frequency: 'Daily' | 'Weekly' | 'Monthly' | 'On-Demand';
  status: 'Available' | 'Generating' | 'Error';
}

const mockReports: Report[] = [
  {
    id: 'R001',
    name: 'Patient Demographics Report',
    description: 'Summary of patient demographics and statistics',
    category: 'Patient',
    lastGenerated: '2024-10-15',
    frequency: 'Monthly',
    status: 'Available'
  },
  {
    id: 'R002',
    name: 'Medication Compliance Report',
    description: 'Patient medication adherence and compliance metrics',
    category: 'Clinical',
    lastGenerated: '2024-10-14',
    frequency: 'Weekly',
    status: 'Available'
  },
  {
    id: 'R003',
    name: 'Appointment Summary Report',
    description: 'Daily appointment statistics and provider utilization',
    category: 'Administrative',
    lastGenerated: '2024-10-15',
    frequency: 'Daily',
    status: 'Available'
  },
  {
    id: 'R004',
    name: 'Lab Results Summary',
    description: 'Abnormal lab results and critical values report',
    category: 'Clinical',
    lastGenerated: '2024-10-13',
    frequency: 'Daily',
    status: 'Available'
  },
  {
    id: 'R005',
    name: 'Revenue Report',
    description: 'Monthly revenue and billing summary',
    category: 'Financial',
    lastGenerated: '2024-09-30',
    frequency: 'Monthly',
    status: 'Available'
  },
  {
    id: 'R006',
    name: 'Quality Metrics Report',
    description: 'Healthcare quality indicators and performance metrics',
    category: 'Clinical',
    lastGenerated: '2024-10-10',
    frequency: 'Monthly',
    status: 'Generating'
  }
];

export default function ReportsPage() {
  const [selectedCategory, setSelectedCategory] = useState<'all' | 'patient' | 'clinical' | 'administrative' | 'financial'>('all');
  const [selectedFrequency, setSelectedFrequency] = useState<'all' | 'daily' | 'weekly' | 'monthly' | 'on-demand'>('all');

  const filteredReports = mockReports.filter(report => {
    const categoryMatch = selectedCategory === 'all' || report.category.toLowerCase() === selectedCategory;
    const frequencyMatch = selectedFrequency === 'all' || report.frequency.toLowerCase().replace('-', '') === selectedFrequency;
    return categoryMatch && frequencyMatch;
  });

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Patient': return 'bg-blue-600/20 text-blue-400 border border-blue-600/50';
      case 'Clinical': return 'bg-green-600/20 text-green-400 border border-green-600/50';
      case 'Administrative': return 'bg-purple-600/20 text-purple-400 border border-purple-600/50';
      case 'Financial': return 'bg-orange-600/20 text-orange-400 border border-orange-600/50';
      default: return 'bg-gray-600/20 text-gray-400 border border-gray-600/50';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Available': return 'bg-green-600/20 text-green-400 border border-green-600/50';
      case 'Generating': return 'bg-yellow-600/20 text-yellow-400 border border-yellow-600/50';
      case 'Error': return 'bg-red-600/20 text-red-400 border border-red-600/50';
      default: return 'bg-gray-600/20 text-gray-400 border border-gray-600/50';
    }
  };

  const getFrequencyColor = (frequency: string) => {
    switch (frequency) {
      case 'Daily': return 'bg-blue-600/20 text-blue-400';
      case 'Weekly': return 'bg-green-600/20 text-green-400';
      case 'Monthly': return 'bg-purple-600/20 text-purple-400';
      case 'On-Demand': return 'bg-orange-600/20 text-orange-400';
      default: return 'bg-gray-600/20 text-gray-400';
    }
  };

  return (
    <Layout>
      <div className="p-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">Reports & Analytics</h2>
          <p className="text-slate-400">Generate and view clinical and administrative reports</p>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">Total Reports</p>
                <p className="text-3xl font-bold text-white">{mockReports.length}</p>
              </div>
              <div className="w-12 h-12 bg-blue-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">Available</p>
                <p className="text-3xl font-bold text-white">
                  {mockReports.filter(r => r.status === 'Available').length}
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
                <p className="text-slate-400 text-sm mb-1">Generating</p>
                <p className="text-3xl font-bold text-white">
                  {mockReports.filter(r => r.status === 'Generating').length}
                </p>
              </div>
              <div className="w-12 h-12 bg-yellow-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">Categories</p>
                <p className="text-3xl font-bold text-white">
                  {new Set(mockReports.map(r => r.category)).size}
                </p>
              </div>
              <div className="w-12 h-12 bg-purple-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Report Management</h3>
            <div className="flex items-center space-x-3">
              <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm transition">
                Generate Custom Report
              </button>
              <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm transition">
                Schedule Report
              </button>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <div className="flex-1">
              <label className="block text-sm text-slate-400 mb-2">Category</label>
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value as 'all' | 'patient' | 'clinical' | 'administrative' | 'financial')}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-white text-sm"
              >
                <option value="all">All Categories</option>
                <option value="patient">Patient</option>
                <option value="clinical">Clinical</option>
                <option value="administrative">Administrative</option>
                <option value="financial">Financial</option>
              </select>
            </div>
            <div className="flex-1">
              <label className="block text-sm text-slate-400 mb-2">Frequency</label>
              <select
                value={selectedFrequency}
                onChange={(e) => setSelectedFrequency(e.target.value as 'all' | 'daily' | 'weekly' | 'monthly')}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-white text-sm"
              >
                <option value="all">All Frequencies</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
                <option value="on-demand">On-Demand</option>
              </select>
            </div>
          </div>
        </div>

        {/* Reports Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredReports.map((report) => (
            <div key={report.id} className="bg-slate-800 border border-slate-700 rounded-lg p-6">
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-white mb-2">{report.name}</h3>
                  <p className="text-sm text-slate-400 mb-3">{report.description}</p>
                </div>
                <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(report.status)}`}>
                  {report.status}
                </span>
              </div>

              <div className="space-y-3 mb-6">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Category:</span>
                  <span className={`px-2 py-1 text-xs rounded-full ${getCategoryColor(report.category)}`}>
                    {report.category}
                  </span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Frequency:</span>
                  <span className={`px-2 py-1 text-xs rounded-full ${getFrequencyColor(report.frequency)}`}>
                    {report.frequency}
                  </span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Last Generated:</span>
                  <span className="text-white">{report.lastGenerated}</span>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                {report.status === 'Available' && (
                  <button className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-3 py-2 rounded-lg text-sm transition">
                    View Report
                  </button>
                )}
                {report.status === 'Generating' && (
                  <button className="flex-1 bg-yellow-600 hover:bg-yellow-700 text-white px-3 py-2 rounded-lg text-sm transition" disabled>
                    Generating...
                  </button>
                )}
                {report.status === 'Error' && (
                  <button className="flex-1 bg-red-600 hover:bg-red-700 text-white px-3 py-2 rounded-lg text-sm transition">
                    Retry
                  </button>
                )}
                <button className="bg-slate-700 hover:bg-slate-600 text-white px-3 py-2 rounded-lg text-sm transition">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                </button>
              </div>
            </div>
          ))}
        </div>

        {filteredReports.length === 0 && (
          <div className="text-center py-12">
            <div className="text-slate-400 mb-4">No reports found matching your criteria</div>
            <button
              onClick={() => {
                setSelectedCategory('all');
                setSelectedFrequency('all');
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

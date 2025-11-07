'use client';

import { useState } from 'react';
import Link from 'next/link';
import Layout from '@/components/Layout';

interface Appointment {
  id: string;
  patientId: string;
  patientName: string;
  provider: string;
  date: string;
  time: string;
  type: string;
  status: 'Scheduled' | 'Completed' | 'Cancelled' | 'No Show';
  duration: number; // in minutes
  notes?: string;
}

const mockAppointments: Appointment[] = [
  {
    id: 'A001',
    patientId: 'P001',
    patientName: 'Sarah Johnson',
    provider: 'Dr. Emily Chen',
    date: '2024-10-20',
    time: '10:00 AM',
    type: 'Follow-up',
    status: 'Scheduled',
    duration: 30,
    notes: 'Diabetes management follow-up'
  },
  {
    id: 'A002',
    patientId: 'P002',
    patientName: 'Robert Martinez',
    provider: 'Dr. James Wilson',
    date: '2024-11-05',
    time: '2:00 PM',
    type: 'Follow-up',
    status: 'Scheduled',
    duration: 30,
    notes: 'Asthma management review'
  },
  {
    id: 'A003',
    patientId: 'P003',
    patientName: 'Emily Chen',
    provider: 'Dr. Sarah Thompson',
    date: '2024-10-15',
    time: '11:00 AM',
    type: 'Follow-up',
    status: 'Completed',
    duration: 30,
    notes: 'Migraine management'
  },
  {
    id: 'A004',
    patientId: 'P004',
    patientName: 'James Williams',
    provider: 'Dr. Robert Davis',
    date: '2024-10-25',
    time: '9:00 AM',
    type: 'Cardiology Follow-up',
    status: 'Scheduled',
    duration: 45,
    notes: 'Cardiac evaluation'
  },
  {
    id: 'A005',
    patientId: 'P005',
    patientName: 'Lisa Anderson',
    provider: 'Dr. Patricia Moore',
    date: '2024-11-12',
    time: '3:00 PM',
    type: 'Follow-up',
    status: 'Scheduled',
    duration: 30,
    notes: 'Anemia management'
  }
];

export default function AppointmentsPage() {
  const [selectedDate, setSelectedDate] = useState(new Date().toISOString().split('T')[0]);
  const [filter, setFilter] = useState<'all' | 'scheduled' | 'completed' | 'cancelled' | 'no-show'>('all');

  const filteredAppointments = mockAppointments.filter(appointment => 
    filter === 'all' || appointment.status.toLowerCase().replace(' ', '-') === filter
  );

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Scheduled': return 'bg-blue-600/20 text-blue-400 border border-blue-600/50';
      case 'Completed': return 'bg-green-600/20 text-green-400 border border-green-600/50';
      case 'Cancelled': return 'bg-red-600/20 text-red-400 border border-red-600/50';
      case 'No Show': return 'bg-yellow-600/20 text-yellow-400 border border-yellow-600/50';
      default: return 'bg-gray-600/20 text-gray-400 border border-gray-600/50';
    }
  };

  const getTypeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case 'follow-up': return 'bg-blue-600/20 text-blue-400';
      case 'consultation': return 'bg-purple-600/20 text-purple-400';
      case 'procedure': return 'bg-orange-600/20 text-orange-400';
      case 'cardiology follow-up': return 'bg-red-600/20 text-red-400';
      default: return 'bg-gray-600/20 text-gray-400';
    }
  };

  return (
    <Layout>
      <div className="p-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">Appointments</h2>
          <p className="text-slate-400">Manage patient appointments and scheduling</p>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">Today&apos;s Appointments</p>
                <p className="text-3xl font-bold text-white">
                  {mockAppointments.filter(a => a.date === new Date().toISOString().split('T')[0]).length}
                </p>
              </div>
              <div className="w-12 h-12 bg-blue-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">Scheduled</p>
                <p className="text-3xl font-bold text-white">
                  {mockAppointments.filter(a => a.status === 'Scheduled').length}
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
                <p className="text-slate-400 text-sm mb-1">Completed</p>
                <p className="text-3xl font-bold text-white">
                  {mockAppointments.filter(a => a.status === 'Completed').length}
                </p>
              </div>
              <div className="w-12 h-12 bg-purple-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-1">No Shows</p>
                <p className="text-3xl font-bold text-white">
                  {mockAppointments.filter(a => a.status === 'No Show').length}
                </p>
              </div>
              <div className="w-12 h-12 bg-red-600/20 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
            </div>
          </div>
        </div>

        {/* Filters and Actions */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white">Appointment Management</h3>
            <div className="flex items-center space-x-3">
              <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm transition">
                Schedule New
              </button>
              <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm transition">
                Bulk Actions
              </button>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <div className="flex-1">
              <label className="block text-sm text-slate-400 mb-2">Filter by Status</label>
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value as 'all' | 'scheduled' | 'completed' | 'cancelled')}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-white text-sm"
              >
                <option value="all">All Appointments</option>
                <option value="scheduled">Scheduled</option>
                <option value="completed">Completed</option>
                <option value="cancelled">Cancelled</option>
                <option value="no-show">No Show</option>
              </select>
            </div>
            <div className="flex-1">
              <label className="block text-sm text-slate-400 mb-2">Date</label>
              <input
                type="date"
                value={selectedDate}
                onChange={(e) => setSelectedDate(e.target.value)}
                className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-white text-sm"
              />
            </div>
          </div>
        </div>

        {/* Appointments List */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-700">
            <h3 className="text-lg font-semibold text-white">Appointments</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-900">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Patient</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Provider</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Date & Time</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Duration</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {filteredAppointments.map((appointment) => (
                  <tr key={appointment.id} className="hover:bg-slate-750 transition">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="w-10 h-10 bg-blue-600 rounded-full flex items-center justify-center mr-4">
                          <span className="text-white text-sm font-medium">
                            {appointment.patientName.split(' ').map(n => n[0]).join('')}
                          </span>
                        </div>
                        <div>
                          <div className="text-sm font-medium text-white">{appointment.patientName}</div>
                          <div className="text-sm text-slate-400">ID: {appointment.patientId}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      {appointment.provider}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      <div>{appointment.date}</div>
                      <div className="text-xs text-slate-500">{appointment.time}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs rounded-full ${getTypeColor(appointment.type)}`}>
                        {appointment.type}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                      {appointment.duration} min
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(appointment.status)}`}>
                        {appointment.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <div className="flex items-center space-x-2">
                        <Link
                          href={`/patient/${appointment.patientId}`}
                          className="text-blue-400 hover:text-blue-300 font-medium transition"
                        >
                          View Patient
                        </Link>
                        <button className="text-green-400 hover:text-green-300 font-medium transition">
                          Complete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Layout>
  );
}

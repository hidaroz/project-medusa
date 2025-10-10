'use client';

import { useState } from 'react';
import Layout from '@/components/Layout';

interface ClinicalOrder {
  id: string;
  patientId: string;
  patientName: string;
  orderType: 'Lab' | 'Imaging' | 'Medication' | 'Procedure' | 'Consultation';
  orderName: string;
  orderingPhysician: string;
  orderDate: string;
  orderTime: string;
  status: 'Pending' | 'In Progress' | 'Completed' | 'Cancelled';
  priority: 'Routine' | 'Urgent' | 'Stat';
  notes?: string;
}

const mockOrders: ClinicalOrder[] = [
  {
    id: 'O001',
    patientId: 'P001',
    patientName: 'Sarah Johnson',
    orderType: 'Lab',
    orderName: 'Hemoglobin A1C',
    orderingPhysician: 'Dr. Emily Chen',
    orderDate: '2024-10-15',
    orderTime: '10:30 AM',
    status: 'Completed',
    priority: 'Routine',
    notes: 'Follow-up for diabetes management'
  },
  {
    id: 'O002',
    patientId: 'P002',
    patientName: 'Robert Martinez',
    orderType: 'Imaging',
    orderName: 'Chest X-Ray',
    orderingPhysician: 'Dr. James Wilson',
    orderDate: '2024-10-14',
    orderTime: '2:15 PM',
    status: 'In Progress',
    priority: 'Urgent',
    notes: 'Evaluate for pneumonia'
  },
  {
    id: 'O003',
    patientId: 'P004',
    patientName: 'James Williams',
    orderType: 'Procedure',
    orderName: 'Cardiac Catheterization',
    orderingPhysician: 'Dr. Robert Davis',
    orderDate: '2024-10-13',
    orderTime: '9:45 AM',
    status: 'Completed',
    priority: 'Routine',
    notes: 'Evaluate coronary artery disease'
  },
  {
    id: 'O004',
    patientId: 'P005',
    patientName: 'Lisa Anderson',
    orderType: 'Lab',
    orderName: 'Complete Blood Count',
    orderingPhysician: 'Dr. Patricia Moore',
    orderDate: '2024-10-12',
    orderTime: '11:20 AM',
    status: 'Pending',
    priority: 'Routine',
    notes: 'Monitor anemia'
  }
];

export default function ClinicalOrdersPage() {
  const [selectedOrder, setSelectedOrder] = useState<ClinicalOrder | null>(null);
  const [filter, setFilter] = useState<'all' | 'pending' | 'in-progress' | 'completed' | 'cancelled'>('all');
  const [typeFilter, setTypeFilter] = useState<'all' | 'lab' | 'imaging' | 'medication' | 'procedure' | 'consultation'>('all');

  const filteredOrders = mockOrders.filter(order => {
    const statusMatch = filter === 'all' || order.status.toLowerCase().replace(' ', '-') === filter;
    const typeMatch = typeFilter === 'all' || order.orderType.toLowerCase() === typeFilter;
    return statusMatch && typeMatch;
  });

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'Stat': return 'bg-red-600/20 text-red-400 border border-red-600/50';
      case 'Urgent': return 'bg-yellow-600/20 text-yellow-400 border border-yellow-600/50';
      default: return 'bg-green-600/20 text-green-400 border border-green-600/50';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Completed': return 'bg-green-600/20 text-green-400 border border-green-600/50';
      case 'In Progress': return 'bg-blue-600/20 text-blue-400 border border-blue-600/50';
      case 'Pending': return 'bg-yellow-600/20 text-yellow-400 border border-yellow-600/50';
      case 'Cancelled': return 'bg-red-600/20 text-red-400 border border-red-600/50';
      default: return 'bg-gray-600/20 text-gray-400 border border-gray-600/50';
    }
  };

  return (
    <Layout>
      <div className="p-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">Clinical Orders</h2>
          <p className="text-slate-400">Manage and track clinical orders</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Orders List */}
          <div className="lg:col-span-1">
            <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">Orders</h3>
                <button className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm transition">
                  New Order
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
                  <option value="pending">Pending</option>
                  <option value="in-progress">In Progress</option>
                  <option value="completed">Completed</option>
                  <option value="cancelled">Cancelled</option>
                </select>
                
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value as any)}
                  className="w-full bg-slate-900 border border-slate-600 rounded-lg px-3 py-2 text-white text-sm"
                >
                  <option value="all">All Types</option>
                  <option value="lab">Lab</option>
                  <option value="imaging">Imaging</option>
                  <option value="medication">Medication</option>
                  <option value="procedure">Procedure</option>
                  <option value="consultation">Consultation</option>
                </select>
              </div>

              {/* Orders List */}
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {filteredOrders.map((order) => (
                  <div
                    key={order.id}
                    onClick={() => setSelectedOrder(order)}
                    className={`p-3 rounded-lg cursor-pointer transition ${
                      selectedOrder?.id === order.id
                        ? 'bg-blue-600/20 border border-blue-600/50'
                        : 'bg-slate-900 hover:bg-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1">
                        <div className="text-sm font-medium text-white">{order.patientName}</div>
                        <div className="text-xs text-slate-400">{order.orderName}</div>
                        <div className="text-xs text-slate-500">{order.orderDate} {order.orderTime}</div>
                      </div>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(order.status)}`}>
                        {order.status}
                      </span>
                      <span className={`px-2 py-1 text-xs rounded-full ${getPriorityColor(order.priority)}`}>
                        {order.priority}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Order Detail */}
          <div className="lg:col-span-2">
            {selectedOrder ? (
              <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
                <div className="flex items-start justify-between mb-6">
                  <div>
                    <h3 className="text-xl font-bold text-white mb-2">{selectedOrder.patientName}</h3>
                    <div className="flex items-center space-x-4 text-sm text-slate-400">
                      <span>{selectedOrder.orderType}</span>
                      <span>•</span>
                      <span>{selectedOrder.orderDate} {selectedOrder.orderTime}</span>
                      <span>•</span>
                      <span>{selectedOrder.orderingPhysician}</span>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`px-3 py-1 text-sm rounded-full ${getStatusColor(selectedOrder.status)}`}>
                      {selectedOrder.status}
                    </span>
                    <span className={`px-3 py-1 text-sm rounded-full ${getPriorityColor(selectedOrder.priority)}`}>
                      {selectedOrder.priority}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-6 mb-6">
                  <div className="bg-slate-900 rounded-lg p-4">
                    <h4 className="text-sm font-medium text-slate-300 mb-2">Order Details</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Order ID:</span>
                        <span className="text-white">{selectedOrder.id}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Patient ID:</span>
                        <span className="text-white">{selectedOrder.patientId}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Order Type:</span>
                        <span className="text-white">{selectedOrder.orderType}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Ordering Physician:</span>
                        <span className="text-white">{selectedOrder.orderingPhysician}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-slate-900 rounded-lg p-4">
                    <h4 className="text-sm font-medium text-slate-300 mb-2">Order Information</h4>
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="text-slate-400">Order Name:</span>
                        <div className="text-white font-medium">{selectedOrder.orderName}</div>
                      </div>
                      {selectedOrder.notes && (
                        <div>
                          <span className="text-slate-400">Notes:</span>
                          <div className="text-white">{selectedOrder.notes}</div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm transition">
                    Update Status
                  </button>
                  <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm transition">
                    Complete Order
                  </button>
                  <button className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm transition">
                    Cancel Order
                  </button>
                </div>
              </div>
            ) : (
              <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 flex items-center justify-center h-64">
                <div className="text-center">
                  <svg className="w-12 h-12 text-slate-500 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
                  </svg>
                  <p className="text-slate-400">Select an order to view details</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}

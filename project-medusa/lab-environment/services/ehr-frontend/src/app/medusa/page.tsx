'use client';

import { useState, useEffect, useCallback } from 'react';

interface Operation {
  id: number;
  timestamp: string;
  source: string;
  level: string;
  message: string;
}

interface CurrentOperation {
  type: string;
  objective: string;
  started_at: string;
}

interface Status {
  status: string;
  current_operation: CurrentOperation | null;
  metrics: {
    operations_completed: number;
    data_found: number;
    time_started: string | null;
    time_completed: string | null;
  };
}

export default function MedusaDashboardPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [operations, setOperations] = useState<Operation[]>([]);
  const [objective, setObjective] = useState('');
  const [operationType, setOperationType] = useState('assess');
  const [loading, setLoading] = useState(false);
  
  const API_URL = process.env.NEXT_PUBLIC_MEDUSA_API_URL || 'http://localhost:5001';

  const fetchStatus = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/status`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setStatus(data);
    } catch (error) {
      console.error('Failed to fetch status:', error);
      // Set a default status to show connection issue
      setStatus((prevStatus) => {
        // Only set error status if we don't have a status yet
        if (!prevStatus) {
          return {
            status: 'error',
            current_operation: null,
            metrics: {
              operations_completed: 0,
              data_found: 0,
              time_started: null,
              time_completed: null,
            },
          };
        }
        return prevStatus;
      });
    }
  }, [API_URL]);

  const fetchOperations = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/logs?limit=50`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setOperations(data.logs || []);
    } catch (error) {
      console.error('Failed to fetch operations:', error);
      // Don't clear operations if we can't fetch, just show existing ones
    }
  }, [API_URL]);

  useEffect(() => {
    fetchStatus();
    fetchOperations();
    
    // Poll for updates every 2 seconds
    const interval = setInterval(() => {
      fetchStatus();
      fetchOperations();
    }, 2000);

    return () => clearInterval(interval);
  }, [fetchStatus, fetchOperations]);

  const startOperation = async () => {
    if (!objective.trim() && operationType !== 'assess') {
      alert('Please enter an objective');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/operations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: operationType,
          objective: objective || 'Security assessment',
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      const data = await response.json();
      alert(`Operation started: ${data.operation_id}`);
      setObjective('');
      // Refresh status
      fetchStatus();
      fetchOperations();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to start operation';
      alert(`Error: ${errorMessage}\n\nMake sure the Medusa API server is running on ${API_URL}`);
      console.error('Operation start error:', error);
    } finally {
      setLoading(false);
    }
  };

  const stopOperation = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/operations/stop`, {
        method: 'POST',
      });
      const data = await response.json();
      alert(data.message);
    } catch (error) {
      alert('Failed to stop operation');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'bg-yellow-500';
      case 'completed':
        return 'bg-green-500';
      case 'error':
        return 'bg-red-500';
      default:
        return 'bg-gray-500';
    }
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'error':
        return 'text-red-400';
      case 'success':
        return 'text-green-400';
      case 'warning':
        return 'text-yellow-400';
      default:
        return 'text-blue-400';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-2">Medusa Operations Dashboard</h1>
          <p className="text-slate-400">AI Adversary Simulation Control Center</p>
        </div>

        {/* Status Card */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-semibold">System Status</h2>
            <div className="flex items-center gap-3">
              <div className={`w-4 h-4 rounded-full ${getStatusColor(status?.status || 'idle')}`}></div>
              {status?.status === 'error' && (
                <span className="text-xs text-red-400">
                  API Server: {API_URL}
                </span>
              )}
            </div>
          </div>
          {status?.status === 'error' && (
            <div className="mb-4 p-3 bg-red-900/20 border border-red-700 rounded-lg">
              <p className="text-red-400 text-sm font-semibold mb-1">⚠️ Cannot connect to API server</p>
              <p className="text-red-300 text-xs">
                Please start the Medusa API server: <code className="bg-slate-900 px-2 py-1 rounded">cd medusa-cli && python api_server.py</code>
              </p>
            </div>
          )}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <p className="text-slate-400 text-sm mb-1">Current Status</p>
              <p className="text-xl font-semibold capitalize">{status?.status || 'Unknown'}</p>
            </div>
            <div>
              <p className="text-slate-400 text-sm mb-1">Operations Completed</p>
              <p className="text-xl font-semibold">{status?.metrics.operations_completed || 0}</p>
            </div>
            <div>
              <p className="text-slate-400 text-sm mb-1">Data Found</p>
              <p className="text-xl font-semibold">{status?.metrics.data_found || 0}</p>
            </div>
          </div>
          {status?.current_operation && (
            <div className="mt-4 pt-4 border-t border-slate-700">
              <p className="text-slate-400 text-sm mb-1">Current Operation</p>
              <p className="font-semibold">{status.current_operation.type}: {status.current_operation.objective}</p>
              <p className="text-sm text-slate-400">Started: {new Date(status.current_operation.started_at).toLocaleString()}</p>
            </div>
          )}
        </div>

        {/* Control Panel */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
          <h2 className="text-2xl font-semibold mb-4">Operation Control</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Operation Type
              </label>
              <select
                value={operationType}
                onChange={(e) => setOperationType(e.target.value)}
                className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="assess">Security Assessment</option>
                <option value="find">Find Data</option>
                <option value="deploy">Deploy Agent</option>
              </select>
            </div>
            {(operationType === 'find' || operationType === 'deploy') && (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Objective
                </label>
                <input
                  type="text"
                  value={objective}
                  onChange={(e) => setObjective(e.target.value)}
                  placeholder={operationType === 'find' ? 'e.g., medical records, passwords' : 'e.g., Locate patient database'}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            )}
            <div className="flex gap-4">
              <button
                onClick={startOperation}
                disabled={loading || status?.status === 'running'}
                className="flex-1 px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed rounded-lg font-semibold transition"
              >
                {loading ? 'Starting...' : 'Start Operation'}
              </button>
              <button
                onClick={stopOperation}
                disabled={loading || status?.status !== 'running'}
                className="flex-1 px-6 py-3 bg-red-600 hover:bg-red-700 disabled:bg-slate-600 disabled:cursor-not-allowed rounded-lg font-semibold transition"
              >
                Stop Operation
              </button>
            </div>
          </div>
        </div>

        {/* Operations Log */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h2 className="text-2xl font-semibold mb-4">Operations Log</h2>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {operations.length === 0 ? (
              <p className="text-slate-400 text-center py-8">No operations yet</p>
            ) : (
              operations.map((op) => (
                <div
                  key={op.id}
                  className="bg-slate-900 border border-slate-700 rounded-lg p-4"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-sm font-semibold ${getLevelColor(op.level)}`}>
                          [{op.level.toUpperCase()}]
                        </span>
                        <span className="text-sm text-slate-400">{op.source}</span>
                        <span className="text-xs text-slate-500">
                          {new Date(op.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <p className="text-slate-200">{op.message}</p>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}


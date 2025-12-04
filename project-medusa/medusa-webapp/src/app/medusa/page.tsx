'use client';

import { useState, useEffect } from 'react';
import { StructuredLogView, RawLogView } from './components';
import DiscoveredDataView from './discovered-data';
import LearningDashboard from './learning-dashboard';
import LearningInsights from './learning-insights';

export interface Operation {
  id: number;
  timestamp: string;
  source: string;
  level: string;
  message: string;
}

export interface CurrentOperation {
  type?: string;
  objective?: string;
  id?: number;
  timestamp?: string;
}

export interface Status {
  status: string;
  current_operation: CurrentOperation | null;
  metrics: {
    operations_completed: number;
    data_found: number;
    time_started: string | null;
    time_completed: string | null;
  };
}

export interface LearningMetrics {
  technique_success_rates: Record<string, number>;
  improvement_trend: string;
  total_operations: number;
  avg_vulnerabilities_per_run: number;
  avg_time_to_first_vuln: number;
  learned_techniques: Array<{
    technique_id: string;
    success_rate: number;
    success_count: number;
  }>;
  best_attack_paths: Array<{
    path_id: string;
    sequence: string[];
    success_rate: number;
    avg_time: number;
    vulnerabilities_found: number;
  }>;
}

export default function MedusaDashboardPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [operations, setOperations] = useState<Operation[]>([]);
  const [objective, setObjective] = useState('');
  const [loading, setLoading] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [llmConfig, setLlmConfig] = useState<LLMConfig | null>(null);
  const [settingsLoading, setSettingsLoading] = useState(false);
  const [logView, setLogView] = useState<'structured' | 'raw'>('structured');
  const [lastOperationObjective, setLastOperationObjective] = useState<string>('');

  // Determine API base URL:
  // - Prefer NEXT_PUBLIC_MEDUSA_API_URL when set (build-time config)
  // - Otherwise, when running in the browser, use the current origin + /api
  // - Fallback to localhost:5001 only for local development without proxy
  const API_URL =
    process.env.NEXT_PUBLIC_MEDUSA_API_URL ||
    (typeof window !== 'undefined'
      ? `${window.location.origin.replace(/\/$/, '')}/api`
      : 'http://localhost:5001');

  useEffect(() => {
    fetchStatus();
    fetchOperations();
    fetchLLMConfig();

    // Poll for updates every 2 seconds
    const interval = setInterval(() => {
      fetchStatus();
      fetchOperations();
    }, 2000);

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchLLMConfig = async () => {
    try {
      const response = await fetch(`${API_URL}/api/config/llm`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setLlmConfig(data);
    } catch (error) {
      console.error('Failed to fetch LLM config:', error);
      setLlmConfig({
        provider: 'auto',
        api_key_configured: false,
        cloud_model: 'gemini-pro',
        local_model: 'mistral:7b-instruct'
      });
    }
  };

  const saveLLMConfig = async (config: LLMConfig) => {
    setSettingsLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/config/llm`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(config),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      await response.json();
      alert('LLM configuration saved successfully!');
      setShowSettings(false);
      fetchLLMConfig();
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to save configuration';
      alert(`Error: ${errorMessage}`);
      console.error('Config save error:', error);
    } finally {
      setSettingsLoading(false);
    }
  };

  const fetchLearningMetrics = async () => {
    try {
      const response = await fetch(`${API_URL}/api/learning/metrics`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setLearningMetrics(data);
    } catch (error) {
      console.error('Failed to fetch learning metrics:', error);
      // Don't show error, just leave metrics as null
    }
  };

  const fetchStatus = async () => {
    try {
      const response = await fetch(`${API_URL}/api/status`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setStatus(data);
    } catch (error) {
      console.error('Failed to fetch status:', error);
      // Only set error status if we don't have any status yet (true connection error)
      // If we have a status but it's "error", that's an operation error, not connection error
      if (!status) {
        setStatus({
          status: 'connection_error', // Special status for connection issues
          current_operation: null,
          metrics: {
            operations_completed: 0,
            data_found: 0,
            time_started: null,
            time_completed: null,
          },
        });
      }
    }
  };

  const fetchOperations = async () => {
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
  };

  const startOperation = async () => {
    if (!objective.trim()) {
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
          type: 'find',
          objective: objective || 'Find data',
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      const data = await response.json();
      alert(`Operation started: ${data.operation_id}`);
      // Store objective for filtering discovered data
      setLastOperationObjective(objective);
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

  const handleReset = async () => {
    if (!confirm('Are you sure you want to reset all operation history and discovered data?\n\nThis will clear:\n- Operation history (trends)\n- Discovered data\n- Operations log\n- Metrics\n\nOptionally clear persistent learning feedback?')) {
      return;
    }

    const clearFeedback = confirm('Also clear persistent learning feedback?\n\nThis will reset technique success rates and learning data stored in ~/.medusa/feedback.json');

    setLoading(true);
    try {
      const response = await fetch(`${API_URL}/api/reset`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          clear_feedback: clearFeedback
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      const data = await response.json();
      alert(`✅ ${data.message}${data.feedback_cleared ? '\n\nPersistent feedback data also cleared.' : '\n\nNote: Persistent feedback data was preserved.'}`);

      // Refresh all data
      fetchStatus();
      fetchOperations();
      fetchLearningMetrics();
      // Note: fetchDiscoveredData and fetchLearningTrends are called by their respective components
      window.location.reload(); // Reload to refresh all components
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to reset data';
      alert(`Error resetting data: ${errorMessage}`);
      console.error('Error resetting data:', error);
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
        return 'bg-orange-500'; // Orange for operation errors (not connection errors)
      case 'connection_error':
        return 'bg-red-500'; // Red only for connection errors
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
        <div className="mb-8 flex items-center justify-between">
          <div>
          <h1 className="text-4xl font-bold mb-2">Medusa Operations Dashboard</h1>
          <p className="text-slate-400">AI Adversary Simulation Control Center</p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={handleReset}
              className="px-4 py-2 bg-red-700 hover:bg-red-600 rounded-lg text-sm font-medium transition"
              title="Reset all operation history and discovered data"
            >
              🔄 Reset Data
            </button>
            <button
              onClick={() => setShowSettings(!showSettings)}
              className="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm font-medium transition"
            >
              ⚙️ Settings
            </button>
          </div>
        </div>

        {/* Settings Modal */}
        {showSettings && (
          <SettingsModal
            config={llmConfig}
            onSave={saveLLMConfig}
            onClose={() => setShowSettings(false)}
            loading={settingsLoading}
          />
        )}

        {/* Status Card */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-semibold">System Status</h2>
            <div className="flex items-center gap-3">
              <div className={`w-4 h-4 rounded-full ${getStatusColor(status?.status || 'idle')}`}></div>
              {status?.status === 'connection_error' && (
                <span className="text-xs text-red-400">
                  API Server: {API_URL}
                </span>
              )}
            </div>
          </div>
          {status?.status === 'connection_error' && (
            <div className="mb-4 p-3 bg-red-900/20 border border-red-700 rounded-lg">
              <p className="text-red-400 text-sm font-semibold mb-1">⚠️ Cannot connect to API server</p>
              <p className="text-red-300 text-xs">
                Please start the Medusa API server: <code className="bg-slate-900 px-2 py-1 rounded">cd medusa-cli && python3 api_server.py</code>
              </p>
            </div>
          )}
          {status?.status === 'error' && status?.current_operation === null && (
            <div className="mb-4 p-3 bg-yellow-900/20 border border-yellow-700 rounded-lg">
              <p className="text-yellow-400 text-sm font-semibold mb-1">⚠️ Previous operation encountered an error</p>
              <p className="text-yellow-300 text-xs">
                The system is ready for a new operation. Check the operations log for details.
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
          <h2 className="text-2xl font-semibold mb-4">Find Data Operation</h2>
          <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Objective
                </label>
                <input
                  type="text"
                  value={objective}
                  onChange={(e) => setObjective(e.target.value)}
                placeholder="e.g., medical records, passwords, patient data"
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            <div className="flex gap-4">
              <button
                onClick={startOperation}
                disabled={loading || status?.status === 'running'}
                className="flex-1 px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed rounded-lg font-semibold transition"
              >
                {loading ? 'Starting...' : 'Start Find Data Operation'}
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

        {/* Discovered Data Section */}
        <DiscoveredDataView
          API_URL={API_URL}
          currentObjective={
            status?.current_operation?.objective ||
            lastOperationObjective
          }
        />

        {/* Learning Insights */}
        <LearningInsights API_URL={API_URL} />

        {/* Continuous Learning Dashboard */}
        <LearningDashboard API_URL={API_URL} />

        {/* Operations Log - Redesigned for Human Readability */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-semibold">Operations Log</h2>
            <div className="flex gap-2">
              <button
                onClick={() => setLogView('structured')}
                className={`px-3 py-1 text-sm rounded-lg transition ${
                  logView === 'structured'
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                }`}
              >
                📊 Structured
              </button>
              <button
                onClick={() => setLogView('raw')}
                className={`px-3 py-1 text-sm rounded-lg transition ${
                  logView === 'raw'
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
                }`}
              >
                📝 Raw Log
              </button>
            </div>
                      </div>

          {logView === 'structured' ? (
            <StructuredLogView operations={operations} status={status} />
          ) : (
            <RawLogView operations={operations} getLevelColor={getLevelColor} />
          )}
                    </div>
                  </div>
                </div>
  );
}

// Settings Modal Component
function SettingsModal({ config, onSave, onClose, loading }: {
  config: LLMConfig | null;
  onSave: (config: LLMConfig) => void;
  onClose: () => void;
  loading: boolean;
}) {
  const [provider, setProvider] = useState(config?.provider || 'auto');
  const [apiKey, setApiKey] = useState('');
  const [cloudModel, setCloudModel] = useState(config?.cloud_model || 'gemini-pro');
  const [localModel, setLocalModel] = useState(config?.local_model || 'mistral:7b-instruct');

  useEffect(() => {
    if (config) {
      setProvider(config.provider || 'auto');
      setCloudModel(config.cloud_model || 'gemini-pro');
      setLocalModel(config.local_model || 'mistral:7b-instruct');
      // Don't pre-fill API key for security
      setApiKey('');
    }
  }, [config]);

  const handleSave = () => {
    const configToSave: LLMConfig = {
      provider,
      cloud_model: cloudModel,
      local_model: localModel,
    };

    // Only include API key if it was changed (not empty and not masked)
    if (apiKey && apiKey.trim() && !apiKey.startsWith('sk-...')) {
      configToSave.api_key = apiKey.trim();
    }

    onSave(configToSave);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-semibold">LLM Provider Settings</h2>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white"
          >
            ✕
          </button>
        </div>

        <div className="space-y-6">
          {/* Provider Selection */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              LLM Provider
            </label>
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => setProvider('local')}
                className={`p-4 rounded-lg border-2 transition ${
                  provider === 'local'
                    ? 'border-blue-500 bg-blue-500/20'
                    : 'border-slate-600 hover:border-slate-500'
                }`}
              >
                <div className="font-semibold mb-1">Ollama (Local)</div>
                <div className="text-xs text-slate-400">Free, runs locally</div>
              </button>
              <button
                onClick={() => setProvider('google')}
                className={`p-4 rounded-lg border-2 transition ${
                  provider === 'google'
                    ? 'border-blue-500 bg-blue-500/20'
                    : 'border-slate-600 hover:border-slate-500'
                }`}
              >
                <div className="font-semibold mb-1">Google Gemini</div>
                <div className="text-xs text-slate-400">Cloud-based, requires API key</div>
              </button>
              <button
                onClick={() => setProvider('auto')}
                className={`p-4 rounded-lg border-2 transition col-span-2 ${
                  provider === 'auto'
                    ? 'border-blue-500 bg-blue-500/20'
                    : 'border-slate-600 hover:border-slate-500'
                }`}
              >
                <div className="font-semibold mb-1">Auto-detect</div>
                <div className="text-xs text-slate-400">Tries Ollama first, falls back to Gemini if configured</div>
              </button>
            </div>
          </div>

          {/* Model Selection */}
          {provider === 'local' && (
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Local Model (Ollama)
              </label>
              <input
                type="text"
                value={localModel}
                onChange={(e) => setLocalModel(e.target.value)}
                placeholder="e.g., mistral:7b-instruct"
                className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <p className="text-xs text-slate-400 mt-1">
                Make sure the model is installed: <code className="bg-slate-900 px-1 rounded">ollama pull {localModel}</code>
              </p>
            </div>
          )}

          {provider === 'google' && (
            <>
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Gemini Model
                </label>
                <select
                  value={cloudModel}
                  onChange={(e) => setCloudModel(e.target.value)}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="gemini-pro">Gemini Pro</option>
                  <option value="gemini-1.5-pro">Gemini 1.5 Pro</option>
                  <option value="gemini-1.5-flash">Gemini 1.5 Flash</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Gemini API Key
                </label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder={config?.api_key_configured ? "Enter new key to update, or leave blank" : "Enter your Gemini API key"}
                  className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                {config?.api_key_configured && (
                  <p className="text-xs text-slate-400 mt-1">
                    Current key: {config.api_key_preview || 'sk-...'}
                  </p>
                )}
                <p className="text-xs text-slate-400 mt-1">
                  Get your API key from{' '}
                  <a
                    href="https://ai.google.dev/gemini-api/docs/quickstart"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 underline"
                  >
                    Google AI Studio
                  </a>
                </p>
              </div>
            </>
          )}

          {provider === 'auto' && (
            <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4">
              <p className="text-sm text-blue-300">
                Auto-detect will try Ollama first. If Ollama is not available, it will use Google Gemini (if API key is configured).
              </p>
            </div>
          )}

          {/* Save Button */}
          <div className="flex gap-4 pt-4 border-t border-slate-700">
            <button
              onClick={handleSave}
              disabled={loading || (provider === 'google' && !apiKey && !config?.api_key_configured)}
              className="flex-1 px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 disabled:cursor-not-allowed rounded-lg font-semibold transition"
            >
              {loading ? 'Saving...' : 'Save Configuration'}
            </button>
            <button
              onClick={onClose}
              className="px-6 py-3 bg-slate-700 hover:bg-slate-600 rounded-lg font-semibold transition"
            >
              Cancel
            </button>
          </div>

          <p className="text-xs text-slate-500 text-center">
            Keys are stored locally in your medusa config. Never share your configuration file.
          </p>
        </div>
      </div>
    </div>
  );
}


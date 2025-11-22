import React, { useEffect, useState } from 'react';
import { Server, Cpu, Globe, Database, Activity, CheckCircle, XCircle, RefreshCw } from 'lucide-react';
import { medusaApi } from '../../lib/api';
import LogsViewer from '../Logs/LogsViewer';

export default function SystemStatus() {
    const [llmStatus, setLlmStatus] = useState<any>(null);
    const [config, setConfig] = useState<any>(null);
    const [isLoading, setIsLoading] = useState(false);

    const fetchSystemInfo = async () => {
        setIsLoading(true);
        try {
            const [llm, cfg] = await Promise.all([
                medusaApi.getLLMStatus(),
                // Config might fail if file not found, handle gracefully
                medusaApi.request('/api/config').catch(() => ({ config: 'Unavailable' }))
            ]);
            setLlmStatus(llm);
            setConfig(cfg);
        } catch (err) {
            console.error(err);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchSystemInfo();
    }, []);

    return (
        <div className="h-full grid grid-cols-1 lg:grid-cols-2 gap-6 p-6 overflow-hidden">
            <div className="space-y-6 flex flex-col">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h2 className="text-2xl font-bold text-white font-mono">System Status</h2>
                        <p className="text-slate-500 mt-1">Infrastructure and configuration health</p>
                    </div>
                    <button 
                        onClick={fetchSystemInfo}
                        className={`p-2 text-slate-400 hover:text-cyan-400 hover:bg-slate-900 rounded-lg transition-colors ${isLoading ? 'animate-spin' : ''}`}
                    >
                        <RefreshCw className="w-5 h-5" />
                    </button>
                </div>

                {/* Status Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* API Server */}
                    <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
                        <div className="flex items-center gap-3 mb-4">
                            <div className="p-2 bg-green-500/10 rounded-lg">
                                <Server className="w-6 h-6 text-green-400" />
                            </div>
                            <div>
                                <h3 className="text-slate-200 font-medium">API Server</h3>
                                <p className="text-xs text-slate-500">Core Service</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-2 text-sm text-green-400">
                            <CheckCircle className="w-4 h-4" />
                            <span>Operational</span>
                        </div>
                    </div>

                    {/* LLM Provider */}
                    <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
                        <div className="flex items-center gap-3 mb-4">
                            <div className={`p-2 rounded-lg ${llmStatus?.connected ? 'bg-purple-500/10' : 'bg-red-500/10'}`}>
                                <Cpu className={`w-6 h-6 ${llmStatus?.connected ? 'text-purple-400' : 'text-red-400'}`} />
                            </div>
                            <div>
                                <h3 className="text-slate-200 font-medium">AI Engine</h3>
                                <p className="text-xs text-slate-500">{llmStatus?.provider || 'Unknown Provider'}</p>
                            </div>
                        </div>
                        <div className={`flex items-center gap-2 text-sm ${llmStatus?.connected ? 'text-green-400' : 'text-red-400'}`}>
                            {llmStatus?.connected ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                            <span>{llmStatus?.connected ? 'Connected' : 'Disconnected'}</span>
                        </div>
                    </div>
                </div>

                 {/* Configuration View */}
                 <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col min-h-0">
                    <div className="p-4 border-b border-slate-800 bg-slate-900/50">
                        <h3 className="font-medium text-white flex items-center gap-2">
                            <Activity className="w-4 h-4 text-cyan-400" />
                            System Configuration
                        </h3>
                    </div>
                    <div className="flex-1 overflow-auto p-4 custom-scrollbar">
                        {config ? (
                             <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap">
                                {typeof config.config === 'string' ? config.config : JSON.stringify(config, null, 2)}
                            </pre>
                        ) : (
                            <div className="text-slate-500 text-sm">Loading configuration...</div>
                        )}
                    </div>
                </div>
            </div>

            {/* Logs View */}
            <div className="h-full min-h-0 flex flex-col">
                <div className="mb-4">
                     <h2 className="text-lg font-bold text-white font-mono flex items-center gap-2">
                        <Database className="w-5 h-5 text-blue-400" />
                        Live System Logs
                    </h2>
                </div>
                <div className="flex-1 min-h-0">
                    <LogsViewer />
                </div>
            </div>
        </div>
    );
}


import React from 'react';
import { Shield, AlertTriangle, Activity, Server, Database, DollarSign } from 'lucide-react';
import { useMedusa, useMedusaStatus } from '../contexts/MedusaContext';
import ActivityChart from './Charts/ActivityChart';
import CostBreakdown from './Charts/CostBreakdown';
import AgentEfficiency from './Charts/AgentEfficiency';
import { MedusaLogEntry } from '../types/medusa';

interface DashboardProps {
    apiUrl: string;
}

export default function Dashboard({ apiUrl }: DashboardProps) {
    const { metrics, logs, isLoading } = useMedusa();
    const { status, isConnected } = useMedusaStatus();

    // Derive recent operations for charts (using logs as proxy for now)
    const recentOperations = logs.filter((l: MedusaLogEntry) => l.message.includes('Starting') || l.message.includes('Operation')).map((l: MedusaLogEntry) => ({
        ...l,
        type: l.message.includes('assess') ? 'assess' : l.message.includes('recon') ? 'recon_only' : 'unknown',
        status: l.level === 'error' ? 'error' : 'completed'
    }));

    const stats = [
        { 
            label: 'System Status', 
            value: isConnected ? status : 'Offline', 
            icon: Server, 
            color: isConnected ? (status === 'running' ? 'text-yellow-400' : 'text-green-400') : 'text-red-400', 
            bg: isConnected ? (status === 'running' ? 'bg-yellow-400/10' : 'bg-green-400/10') : 'bg-red-400/10' 
        },
        { 
            label: 'Data Points Found', 
            value: metrics?.data_found || '0', 
            icon: AlertTriangle, 
            color: 'text-red-400', 
            bg: 'bg-red-400/10' 
        },
        { 
            label: 'Est. Cost (Session)', 
            value: metrics?.total_cost ? `$${Number(metrics.total_cost).toFixed(2)}` : '$0.00',
            icon: DollarSign, 
            color: 'text-emerald-400', 
            bg: 'bg-emerald-400/10' 
        },
        { 
            label: 'Total Operations', 
            value: metrics?.operations_completed || '0', 
            icon: Database, 
            color: 'text-purple-400', 
            bg: 'bg-purple-400/10' 
        },
    ];

    if (isLoading) {
        return <div className="h-full flex items-center justify-center text-slate-400">Loading system metrics...</div>;
    }

    return (
        <div className="space-y-6 h-full overflow-y-auto custom-scrollbar p-1">
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {stats.map((stat, i) => (
                    <div key={i} className="p-4 bg-slate-900 border border-slate-800 rounded-xl hover:border-cyan-500/30 transition-all duration-300 group">
                        <div className="flex items-center justify-between mb-4">
                            <div className={`p-2 rounded-lg ${stat.bg}`}>
                                <stat.icon className={`w-6 h-6 ${stat.color}`} />
                            </div>
                            <span className={`text-xl font-bold text-white group-hover:scale-105 transition-transform truncate`}>
                                {String(stat.value).toUpperCase()}
                            </span>
                        </div>
                        <h3 className="text-slate-400 text-sm font-medium">{stat.label}</h3>
                    </div>
                ))}
            </div>

            {/* Charts Area */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Activity Chart */}
                <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
                    <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                        <Activity className="w-5 h-5 text-cyan-400" />
                        System Activity
                    </h3>
                    <ActivityChart logs={logs} />
                </div>

                {/* Cost Breakdown */}
                <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
                    <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                        <DollarSign className="w-5 h-5 text-emerald-400" />
                        Cost Estimation
                    </h3>
                    <CostBreakdown operations={recentOperations} />
                </div>
            </div>

             <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                 {/* Agent Efficiency */}
                 <div className="lg:col-span-1 p-6 bg-slate-900 border border-slate-800 rounded-xl">
                    <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                        <Shield className="w-5 h-5 text-purple-400" />
                        Operation Success
                    </h3>
                    <AgentEfficiency operations={recentOperations} />
            </div>

            {/* Recent Logs Preview */}
                <div className="lg:col-span-2 p-6 bg-slate-900 border border-slate-800 rounded-xl">
                    <h3 className="text-lg font-semibold text-white mb-4">Live Log Stream</h3>
                    <div className="space-y-2 font-mono text-sm max-h-[300px] overflow-y-auto custom-scrollbar pr-2">
                        {logs.slice(0, 10).map((log, i) => (
                            <div key={i} className="flex items-start gap-4 text-slate-400 py-2 border-b border-slate-800/50 last:border-0">
                                <span className="text-slate-600 text-xs shrink-0 mt-0.5">
                                    {new Date(log.timestamp).toLocaleTimeString()}
                                </span>
                                <span className={`text-xs font-bold shrink-0 w-16 uppercase ${
                                    log.level === 'error' ? 'text-red-400' :
                                    log.level === 'warning' ? 'text-yellow-400' :
                                    log.level === 'success' ? 'text-green-400' : 'text-cyan-400'
                                }`}>
                                    [{log.level}]
                                </span>
                                <span className="break-all">{log.message}</span>
                        </div>
                    ))}
                        {logs.length === 0 && (
                            <div className="text-slate-600 italic">No logs available yet...</div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}

import React from 'react';
import { Play, CheckCircle, AlertTriangle, XCircle, Clock, Target, Terminal } from 'lucide-react';
import { MedusaLogEntry, MedusaOperation } from '../../types/medusa';

interface OperationCardProps {
    operation: MedusaOperation | any; // Using any for now as log entries are returned as ops
    isActive?: boolean;
    onClick?: () => void;
}

export default function OperationCard({ operation, isActive, onClick }: OperationCardProps) {
    // Helper to parse operation from log entry if needed (legacy support)
    const getStatusColor = (status: string) => {
        switch (status) {
            case 'running': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20';
            case 'completed': return 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20';
            case 'error': return 'text-red-400 bg-red-400/10 border-red-400/20';
            default: return 'text-slate-400 bg-slate-800/50 border-slate-700';
        }
    };

    const status = isActive ? 'running' : (operation.level === 'error' ? 'error' : 'completed');
    const statusColor = getStatusColor(status);

    return (
        <div 
            onClick={onClick}
            className={`p-4 rounded-xl border transition-all duration-200 cursor-pointer hover:bg-slate-800/50 ${isActive ? 'border-cyan-500/50 bg-slate-900/80' : 'border-slate-800 bg-slate-900'}`}
        >
            <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${statusColor}`}>
                        {isActive ? <Play className="w-5 h-5 animate-pulse" /> : 
                         status === 'error' ? <AlertTriangle className="w-5 h-5" /> :
                         <CheckCircle className="w-5 h-5" />}
                    </div>
                    <div>
                        <h4 className="text-slate-200 font-medium font-mono">
                            {operation.type?.toUpperCase() || 'OPERATION'}
                        </h4>
                        <div className="flex items-center gap-2 text-xs text-slate-500 mt-1">
                            <Clock className="w-3 h-3" />
                            <span>{new Date(operation.timestamp || operation.started_at || Date.now()).toLocaleString()}</span>
                        </div>
                    </div>
                </div>
                {isActive && (
                    <span className="px-2 py-1 rounded bg-cyan-500/20 text-cyan-400 text-xs font-bold font-mono animate-pulse">
                        ACTIVE
                    </span>
                )}
            </div>

            <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm text-slate-400 bg-slate-950/50 p-2 rounded border border-slate-800/50">
                    <Target className="w-4 h-4 text-slate-500" />
                    <span className="font-mono truncate">{operation.objective || operation.message || 'Unknown Target'}</span>
                </div>
                
                {isActive && (
                    <div className="flex items-center gap-2 text-xs text-cyan-400 mt-2">
                        <Terminal className="w-3 h-3" />
                        <span>Processing...</span>
                    </div>
                )}
            </div>
        </div>
    );
}


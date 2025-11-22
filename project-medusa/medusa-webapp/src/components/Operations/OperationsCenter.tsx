import React, { useState, useEffect } from 'react';
import { Plus, Filter, RefreshCw, StopCircle, AlertTriangle, FileText, X } from 'lucide-react';
import OperationCard from './OperationCard';
import AgentStatusPanel from './AgentStatusPanel';
import NewOperationModal from './NewOperationModal';
import ApprovalModal from './ApprovalModal';
import FindingsViewer from '../Reports/FindingsViewer';
import { useMedusa, useMedusaStatus } from '../../contexts/MedusaContext';

export default function OperationsCenter() {
    const { logs, refresh, stopOperation, detailedOperation, approveOperation, rejectOperation } = useMedusa();
    const { status, currentOperation } = useMedusaStatus();
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [showApprovalModal, setShowApprovalModal] = useState(false);
    const [showFindings, setShowFindings] = useState(false);
    const [filter, setFilter] = useState('all');

    // Automatically show approval modal when operation reaches approval gate
    useEffect(() => {
        if (detailedOperation?.status === 'WAITING_FOR_APPROVAL' && detailedOperation.awaiting_approval) {
            setShowApprovalModal(true);
        } else {
            setShowApprovalModal(false);
        }
    }, [detailedOperation]);

    // Deduplicate logs to create an "operations history" view
    // In a real app, we'd query /api/operations which would return distinct ops
    // For now, we'll treat the 'currentOperation' + logs as our data source
    // This is a simplification for the MVP phase
    
    // We use logs as a proxy for history for now, filtering for start events
    const history = logs.filter(l => l.message.includes('Starting') || l.message.includes('Operation')).map(l => ({
        id: l.id.toString(),
        type: l.message.includes('assess') ? 'assess' : l.message.includes('recon') ? 'recon_only' : 'unknown',
        objective: l.message.split(':').pop()?.trim() || 'Unknown Target',
        started_at: l.timestamp,
        status: l.level === 'error' ? 'error' : 'completed', // simplified
        level: l.level
    })).reverse();

    return (
        <div className="h-full flex flex-col gap-6 p-6 overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-white font-mono">Operations Center</h2>
                    <p className="text-slate-500 mt-1">Manage and monitor security assessments</p>
                </div>
                <div className="flex items-center gap-3">
                    <button 
                        onClick={() => refresh()}
                        className="p-2 text-slate-400 hover:text-cyan-400 hover:bg-slate-900 rounded-lg transition-colors"
                    >
                        <RefreshCw className="w-5 h-5" />
                    </button>
                    <button 
                        onClick={() => setIsModalOpen(true)}
                        disabled={status === 'running'}
                        className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors shadow-lg shadow-cyan-900/20 flex items-center gap-2"
                    >
                        <Plus className="w-4 h-4" />
                        New Operation
                    </button>
                </div>
            </div>

            {/* Active Operation Panel */}
            {status === 'running' && currentOperation && (
                <div className={`bg-slate-900/50 border rounded-xl p-6 relative overflow-hidden ${
                    detailedOperation?.awaiting_approval
                        ? 'border-orange-500/30'
                        : 'border-cyan-500/30'
                }`}>
                    <div className={`absolute inset-0 animate-pulse pointer-events-none ${
                        detailedOperation?.awaiting_approval
                            ? 'bg-orange-500/5'
                            : 'bg-cyan-500/5'
                    }`} />

                    <div className="flex items-start justify-between relative z-10 mb-6">
                        <div>
                            <div className="flex items-center gap-3 mb-2">
                                {detailedOperation?.awaiting_approval ? (
                                    <span className="px-2 py-1 rounded bg-orange-500/20 text-orange-400 text-xs font-bold font-mono animate-pulse flex items-center gap-1">
                                        <AlertTriangle className="w-3 h-3" />
                                        AWAITING APPROVAL
                                    </span>
                                ) : (
                                    <span className="px-2 py-1 rounded bg-cyan-500/20 text-cyan-400 text-xs font-bold font-mono animate-pulse">
                                        IN PROGRESS
                                    </span>
                                )}
                                <span className="text-slate-400 font-mono text-sm">ID: {currentOperation.id}</span>
                            </div>
                            <h3 className="text-xl font-bold text-white font-mono">{currentOperation.type.toUpperCase()}</h3>
                            <p className="text-slate-400 mt-1">Target: <span className="text-cyan-300">{currentOperation.objective}</span></p>
                            {detailedOperation?.next_step && (
                                <p className="text-orange-300 mt-2 text-sm flex items-center gap-1">
                                    <AlertTriangle className="w-4 h-4" />
                                    Next: {detailedOperation.next_step}
                                </p>
                            )}
                        </div>
                        <button
                            onClick={() => stopOperation()}
                            className="px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 rounded-lg font-medium transition-colors flex items-center gap-2"
                        >
                            <StopCircle className="w-4 h-4" />
                            Abort Operation
                        </button>
                    </div>

                    <div className="relative z-10">
                        <div className="mb-4 flex items-center justify-between text-sm text-slate-400">
                            <span>Agent Status</span>
                            <span className="font-mono">Time Elapsed: 00:02:14</span>
                        </div>
                        <AgentStatusPanel isActive={true} logs={logs} />
                    </div>
                </div>
            )}

            {/* Completed Operation - Show Findings */}
            {detailedOperation?.status === 'completed' && detailedOperation.results?.findings && (
                <div className="bg-slate-900/50 border border-green-500/30 rounded-xl p-6 relative overflow-hidden">
                    <div className="absolute inset-0 bg-green-500/5 pointer-events-none" />

                    <div className="flex items-start justify-between relative z-10">
                        <div>
                            <div className="flex items-center gap-3 mb-2">
                                <span className="px-2 py-1 rounded bg-green-500/20 text-green-400 text-xs font-bold font-mono">
                                    COMPLETED
                                </span>
                                <span className="text-slate-400 font-mono text-sm">ID: {detailedOperation.operation_id}</span>
                            </div>
                            <h3 className="text-xl font-bold text-white font-mono">{detailedOperation.operation_type.toUpperCase()}</h3>
                            <p className="text-slate-400 mt-1">Target: <span className="text-cyan-300">{detailedOperation.objective}</span></p>
                            <p className="text-green-400 mt-2 text-sm">
                                {detailedOperation.results.findings.length} findings discovered
                            </p>
                        </div>
                        <button
                            onClick={() => setShowFindings(true)}
                            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-medium transition-colors flex items-center gap-2 shadow-lg shadow-cyan-900/20"
                        >
                            <FileText className="w-4 h-4" />
                            View Findings
                        </button>
                    </div>
                </div>
            )}

            {/* History & Filters */}
            <div className="flex-1 flex flex-col min-h-0 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div className="p-4 border-b border-slate-800 flex items-center gap-4 bg-slate-900/50">
                    <div className="flex items-center gap-2 text-slate-400">
                        <Filter className="w-4 h-4" />
                        <span className="text-sm font-medium">Filter:</span>
                    </div>
                    {['all', 'completed', 'error'].map((f) => (
                        <button
                            key={f}
                            onClick={() => setFilter(f)}
                            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                                filter === f 
                                ? 'bg-slate-700 text-white' 
                                : 'text-slate-500 hover:text-slate-300'
                            }`}
                        >
                            {f.charAt(0).toUpperCase() + f.slice(1)}
                        </button>
                    ))}
                </div>

                <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
                    {history.length === 0 ? (
                        <div className="h-full flex flex-col items-center justify-center text-slate-500">
                            <p>No operations history found.</p>
                        </div>
                    ) : (
                        history.map((op, i) => (
                            <OperationCard key={i} operation={op} />
                        ))
                    )}
                </div>
            </div>

            <NewOperationModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} />

            {/* Approval Modal */}
            {showApprovalModal && detailedOperation && (
                <ApprovalModal
                    operation={detailedOperation}
                    onApprove={approveOperation}
                    onReject={rejectOperation}
                    onClose={() => setShowApprovalModal(false)}
                />
            )}

            {/* Findings Modal */}
            {showFindings && detailedOperation?.results?.findings && (
                <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm p-4">
                    <div className="h-full max-w-7xl mx-auto bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
                        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
                            <h2 className="text-xl font-semibold text-white">Operation Findings</h2>
                            <button
                                onClick={() => setShowFindings(false)}
                                className="p-2 text-slate-400 hover:text-white hover:bg-slate-900 rounded-lg transition-colors"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>
                        <div className="flex-1 overflow-hidden">
                            <FindingsViewer
                                findings={detailedOperation.results.findings}
                                operationId={detailedOperation.operation_id}
                                objective={detailedOperation.objective}
                            />
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}


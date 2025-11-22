import React, { useState } from 'react';
import { X, AlertTriangle, CheckCircle, XCircle, Shield } from 'lucide-react';
import { OperationStatusResponse } from '../../types/medusa';

interface ApprovalModalProps {
    operation: OperationStatusResponse;
    onApprove: (notes: string, approver: string) => Promise<void>;
    onReject: (notes: string, approver: string) => Promise<void>;
    onClose: () => void;
}

export default function ApprovalModal({ operation, onApprove, onReject, onClose }: ApprovalModalProps) {
    const [notes, setNotes] = useState('');
    const [approver, setApprover] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleApprove = async () => {
        setIsLoading(true);
        setError(null);
        try {
            await onApprove(notes, approver);
            onClose();
        } catch (err: any) {
            setError(err.message || 'Failed to approve');
        } finally {
            setIsLoading(false);
        }
    };

    const handleReject = async () => {
        setIsLoading(true);
        setError(null);
        try {
            await onReject(notes, approver);
            onClose();
        } catch (err: any) {
            setError(err.message || 'Failed to reject');
        } finally {
            setIsLoading(false);
        }
    };

    const getRiskColor = (risk: string) => {
        switch (risk.toUpperCase()) {
            case 'CRITICAL':
                return 'text-red-400 bg-red-500/10 border-red-500/20';
            case 'HIGH':
                return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
            case 'MEDIUM':
                return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
            case 'LOW':
                return 'text-green-400 bg-green-500/10 border-green-500/20';
            default:
                return 'text-slate-400 bg-slate-500/10 border-slate-500/20';
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
            <div className="w-full max-w-3xl bg-slate-950 border border-orange-500/30 rounded-2xl shadow-2xl overflow-hidden">
                {/* Header */}
                <div className="p-6 border-b border-orange-500/20 bg-gradient-to-r from-orange-900/20 to-red-900/20">
                    <div className="flex items-start justify-between">
                        <div className="flex items-start gap-4">
                            <div className="p-3 rounded-xl bg-orange-500/10 border border-orange-500/20">
                                <AlertTriangle className="w-6 h-6 text-orange-400" />
                            </div>
                            <div>
                                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                                    Exploitation Approval Required
                                </h2>
                                <p className="text-orange-300/80 text-sm mt-1">
                                    Review and approve planned exploitation actions
                                </p>
                            </div>
                        </div>
                        <button
                            onClick={onClose}
                            disabled={isLoading}
                            className="text-slate-400 hover:text-white transition-colors disabled:opacity-50"
                        >
                            <X className="w-6 h-6" />
                        </button>
                    </div>
                </div>

                {/* Body */}
                <div className="p-6 space-y-6 max-h-[60vh] overflow-y-auto custom-scrollbar">
                    {/* Operation Info */}
                    <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4">
                        <div className="flex items-center gap-2 mb-2">
                            <Shield className="w-4 h-4 text-cyan-400" />
                            <span className="text-sm font-medium text-slate-300">Operation Details</span>
                        </div>
                        <div className="grid grid-cols-2 gap-3 text-sm">
                            <div>
                                <span className="text-slate-500">ID:</span>
                                <span className="ml-2 font-mono text-slate-300">{operation.operation_id}</span>
                            </div>
                            <div>
                                <span className="text-slate-500">Type:</span>
                                <span className="ml-2 text-slate-300">{operation.operation_type}</span>
                            </div>
                            <div className="col-span-2">
                                <span className="text-slate-500">Target:</span>
                                <span className="ml-2 text-cyan-300">{operation.objective}</span>
                            </div>
                        </div>
                    </div>

                    {/* Planned Exploitation */}
                    <div>
                        <h3 className="text-sm font-medium text-slate-300 mb-3 flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-orange-400" />
                            Planned Exploitation Actions ({operation.planned_exploitation?.length || 0})
                        </h3>
                        <div className="space-y-3">
                            {operation.planned_exploitation?.map((plan, index) => (
                                <div
                                    key={index}
                                    className="bg-slate-900/70 border border-slate-800 rounded-lg p-4 hover:border-slate-700 transition-colors"
                                >
                                    <div className="flex items-start justify-between mb-2">
                                        <div className="flex-1">
                                            <div className="font-medium text-white mb-1">{plan.technique}</div>
                                            <div className="text-sm text-slate-400 font-mono">{plan.target}</div>
                                        </div>
                                        <span className={`px-2 py-1 rounded text-xs font-bold border ${getRiskColor(plan.risk)}`}>
                                            {plan.risk}
                                        </span>
                                    </div>
                                    <div className="text-sm text-slate-300 bg-slate-950/50 p-2 rounded border border-slate-800 mt-2">
                                        <span className="text-slate-500">Vulnerability: </span>
                                        {plan.vulnerability}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Approval Form */}
                    <div className="space-y-4 pt-4 border-t border-slate-800">
                        <div>
                            <label className="text-sm font-medium text-slate-300 mb-2 block">
                                Approver (email or name)
                            </label>
                            <input
                                type="text"
                                value={approver}
                                onChange={(e) => setApprover(e.target.value)}
                                placeholder="security-team@example.com"
                                className="w-full bg-slate-900 border border-slate-800 rounded-lg px-4 py-2 text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 transition-colors"
                            />
                        </div>
                        <div>
                            <label className="text-sm font-medium text-slate-300 mb-2 block">
                                Notes / Justification
                            </label>
                            <textarea
                                value={notes}
                                onChange={(e) => setNotes(e.target.value)}
                                placeholder="Add notes about this approval decision..."
                                rows={3}
                                className="w-full bg-slate-900 border border-slate-800 rounded-lg px-4 py-2 text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 transition-colors resize-none"
                            />
                        </div>
                    </div>

                    {/* Error Message */}
                    {error && (
                        <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
                            {error}
                        </div>
                    )}
                </div>

                {/* Footer Actions */}
                <div className="p-6 border-t border-slate-800 bg-slate-900/30">
                    <div className="flex items-center justify-end gap-3">
                        <button
                            onClick={onClose}
                            disabled={isLoading}
                            className="px-4 py-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors disabled:opacity-50"
                        >
                            Cancel
                        </button>
                        <button
                            onClick={handleReject}
                            disabled={isLoading}
                            className="px-6 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 rounded-lg font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
                        >
                            {isLoading ? (
                                <span className="w-4 h-4 border-2 border-red-400/20 border-t-red-400 rounded-full animate-spin" />
                            ) : (
                                <XCircle className="w-4 h-4" />
                            )}
                            Reject Exploitation
                        </button>
                        <button
                            onClick={handleApprove}
                            disabled={isLoading}
                            className="px-6 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg font-medium transition-colors disabled:opacity-50 shadow-lg shadow-green-900/20 flex items-center gap-2"
                        >
                            {isLoading ? (
                                <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                            ) : (
                                <CheckCircle className="w-4 h-4" />
                            )}
                            Approve & Execute
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}

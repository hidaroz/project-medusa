import React, { useState } from 'react';
import { X, Shield, Zap, Search, Eye, AlertTriangle } from 'lucide-react';
import { useMedusa } from '../../contexts/MedusaContext';

interface NewOperationModalProps {
    isOpen: boolean;
    onClose: () => void;
}

export default function NewOperationModal({ isOpen, onClose }: NewOperationModalProps) {
    const { startOperation } = useMedusa();
    const [target, setTarget] = useState('');
    const [type, setType] = useState('recon_only');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    if (!isOpen) return null;

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!target) return;

        setIsLoading(true);
        setError(null);

        try {
            await startOperation(type, target);
            onClose();
        } catch (err: any) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    const operationTypes = [
        { id: 'recon_only', label: 'Reconnaissance Only', icon: Eye, desc: 'Non-intrusive gathering of public info', cost: '~ $0.05' },
        { id: 'vuln_scan', label: 'Vulnerability Scan', icon: Search, desc: 'Identify potential weaknesses (Safe)', cost: '~ $0.15' },
        { id: 'full_assessment', label: 'Full Assessment', icon: Shield, desc: 'Comprehensive security analysis', cost: '~ $0.30' },
        { id: 'penetration_test', label: 'Penetration Test', icon: Zap, desc: 'Controlled exploitation (Auth Required)', cost: '~ $0.50+' },
    ];

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="w-full max-w-2xl bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden">
                <div className="p-6 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
                    <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                        <Shield className="w-6 h-6 text-cyan-400" />
                        New Operation
                    </h2>
                    <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
                        <X className="w-6 h-6" />
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="p-6 space-y-8">
                    {/* Target Input */}
                    <div className="space-y-2">
                        <label className="text-sm font-medium text-slate-300">Target URL / IP</label>
                        <input
                            type="text"
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                            placeholder="https://example.com or 192.168.1.1"
                            className="w-full bg-slate-900 border border-slate-800 rounded-lg px-4 py-3 text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50 transition-colors font-mono"
                            autoFocus
                        />
                        <p className="text-xs text-slate-500 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            Only scan targets you have explicit permission to test.
                        </p>
                    </div>

                    {/* Operation Type Selection */}
                    <div className="space-y-3">
                        <label className="text-sm font-medium text-slate-300">Operation Mode</label>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            {operationTypes.map((op) => (
                                <div
                                    key={op.id}
                                    onClick={() => setType(op.id)}
                                    className={`p-4 rounded-xl border cursor-pointer transition-all duration-200 ${
                                        type === op.id 
                                        ? 'bg-cyan-900/20 border-cyan-500/50 ring-1 ring-cyan-500/20' 
                                        : 'bg-slate-900/50 border-slate-800 hover:bg-slate-900 hover:border-slate-700'
                                    }`}
                                >
                                    <div className="flex items-start gap-3">
                                        <div className={`p-2 rounded-lg ${type === op.id ? 'bg-cyan-500/20 text-cyan-400' : 'bg-slate-800 text-slate-500'}`}>
                                            <op.icon className="w-5 h-5" />
                                        </div>
                                        <div>
                                            <div className="font-medium text-slate-200">{op.label}</div>
                                            <div className="text-xs text-slate-500 mt-1">{op.desc}</div>
                                            <div className="text-xs font-mono text-emerald-400/80 mt-2 bg-emerald-950/30 inline-block px-2 py-0.5 rounded">
                                                Est. Cost: {op.cost}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Error Message */}
                    {error && (
                        <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
                            {error}
                        </div>
                    )}

                    {/* Actions */}
                    <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                        <button
                            type="button"
                            onClick={onClose}
                            className="px-4 py-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={!target || isLoading}
                            className="px-6 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium transition-colors shadow-lg shadow-cyan-900/20 flex items-center gap-2"
                        >
                            {isLoading ? (
                                <>
                                    <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                                    Initializing...
                                </>
                            ) : (
                                <>
                                    <Zap className="w-4 h-4" />
                                    Launch Operation
                                </>
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}


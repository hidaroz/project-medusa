import React from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { useMedusa } from '../../contexts/MedusaContext';

export default function ZombieAlert() {
    const { zombieAlert, healthStatus } = useMedusa();
    const [isDismissed, setIsDismissed] = React.useState(false);

    if (!zombieAlert || isDismissed || !healthStatus) return null;

    const stalledOps = healthStatus.stalled_operations || [];

    return (
        <div className="fixed top-4 right-4 z-50 w-96 bg-gradient-to-r from-red-900/90 to-orange-900/90 backdrop-blur-md border border-red-500/50 rounded-xl shadow-2xl overflow-hidden animate-shake">
            {/* Animated border glow */}
            <div className="absolute inset-0 bg-red-500/20 animate-pulse pointer-events-none" />

            <div className="relative p-4">
                <div className="flex items-start gap-3">
                    <div className="p-2 rounded-lg bg-red-500/20 border border-red-500/30 animate-pulse">
                        <AlertTriangle className="w-5 h-5 text-red-400" />
                    </div>
                    <div className="flex-1">
                        <h3 className="text-white font-bold flex items-center gap-2">
                            🧟 Zombie Agent Detected
                        </h3>
                        <p className="text-red-200/80 text-sm mt-1">
                            {stalledOps.length} operation{stalledOps.length > 1 ? 's have' : ' has'} stalled
                        </p>
                        <div className="mt-2 space-y-1">
                            {stalledOps.slice(0, 3).map((op) => (
                                <div key={op.operation_id} className="text-xs text-red-200/70 font-mono bg-black/20 px-2 py-1 rounded">
                                    {op.operation_id}: {Math.floor((op.time_since_update || 0) / 60)}min stalled
                                </div>
                            ))}
                            {stalledOps.length > 3 && (
                                <div className="text-xs text-red-200/50">
                                    + {stalledOps.length - 3} more
                                </div>
                            )}
                        </div>
                    </div>
                    <button
                        onClick={() => setIsDismissed(true)}
                        className="text-red-200/60 hover:text-white transition-colors"
                    >
                        <X className="w-4 h-4" />
                    </button>
                </div>
            </div>
        </div>
    );
}

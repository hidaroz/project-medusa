import React from 'react';
import { DollarSign, TrendingUp, CreditCard, Percent } from 'lucide-react';
import { useMedusa } from '../../contexts/MedusaContext';
import CostBreakdown from '../Charts/CostBreakdown';

export default function CostDashboard() {
    const { logs } = useMedusa();

    // Mock data derivations
    const totalCost = 12.45;
    const monthlyProjection = 45.00;
    const savings = 65;

    const operations = logs.filter(l => l.message.includes('Starting')).map(l => ({
         type: l.message.includes('assess') ? 'assess' : l.message.includes('recon') ? 'recon_only' : 'unknown',
    }));

    const stats = [
        { label: 'Total Cost (MTD)', value: `$${totalCost.toFixed(2)}`, icon: DollarSign, color: 'text-green-400', bg: 'bg-green-400/10' },
        { label: 'Projected Cost', value: `$${monthlyProjection.toFixed(2)}`, icon: TrendingUp, color: 'text-blue-400', bg: 'bg-blue-400/10' },
        { label: 'Model Savings', value: `${savings}%`, icon: Percent, color: 'text-purple-400', bg: 'bg-purple-400/10' },
        { label: 'Transactions', value: '842', icon: CreditCard, color: 'text-yellow-400', bg: 'bg-yellow-400/10' },
    ];

    return (
        <div className="h-full p-6 overflow-y-auto custom-scrollbar space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-white font-mono">Cost Management</h2>
                    <p className="text-slate-500 mt-1">Track LLM usage and optimization metrics</p>
                </div>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {stats.map((stat, i) => (
                    <div key={i} className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
                        <div className="flex items-center justify-between mb-4">
                            <div className={`p-2 rounded-lg ${stat.bg}`}>
                                <stat.icon className={`w-6 h-6 ${stat.color}`} />
                            </div>
                            <span className="text-2xl font-bold text-white">{stat.value}</span>
                        </div>
                        <h3 className="text-slate-400 text-sm font-medium">{stat.label}</h3>
                    </div>
                ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
                     <h3 className="text-lg font-semibold text-white mb-6">Cost Breakdown by Agent</h3>
                     <CostBreakdown operations={operations} />
                </div>

                <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl flex flex-col">
                    <h3 className="text-lg font-semibold text-white mb-4">Optimization Insights</h3>
                    <div className="space-y-4 flex-1">
                         <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-slate-300 font-medium">Smart Routing</span>
                                <span className="text-green-400 font-bold">Active</span>
                            </div>
                            <p className="text-sm text-slate-500">
                                Automatically routing simple tasks to Haiku and complex reasoning to Sonnet, saving ~60% on token costs.
                            </p>
                        </div>

                        <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
                             <div className="flex items-center justify-between mb-2">
                                <span className="text-slate-300 font-medium">Model Usage Distribution</span>
                            </div>
                            <div className="space-y-2">
                                <div>
                                    <div className="flex justify-between text-xs text-slate-400 mb-1">
                                        <span>Claude 3.5 Haiku</span>
                                        <span>75%</span>
                                    </div>
                                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                                        <div className="h-full bg-cyan-500 w-3/4" />
                                    </div>
                                </div>
                                <div>
                                    <div className="flex justify-between text-xs text-slate-400 mb-1">
                                        <span>Claude 3.5 Sonnet</span>
                                        <span>25%</span>
                                    </div>
                                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                                        <div className="h-full bg-purple-500 w-1/4" />
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}


import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

interface CostBreakdownProps {
    operations: any[]; // Should be MedusaOperation[]
}

export default function CostBreakdown({ operations }: CostBreakdownProps) {
    // Mock data generation or real data processing
    // Since API doesn't return cost yet, we'll simulate for visualization purposes
    // OR we can parse from logs if available.
    // For this MVP, let's show estimated costs based on operation types found in history
    
    const processData = () => {
        const costs = {
            'orchestrator': 0,
            'recon': 0,
            'vuln': 0,
            'planning': 0,
            'exploit': 0,
            'report': 0
        };

        // Heuristic: Count operations and multiply by estimated cost per agent usage
        operations.forEach(op => {
            // Base base cost
            costs.orchestrator += 0.05;
            
            if (op.type === 'recon_only') {
                costs.recon += 0.03;
            } else if (op.type === 'vuln_scan') {
                costs.recon += 0.03;
                costs.vuln += 0.04;
            } else if (op.type === 'full_assessment' || op.type === 'assess') {
                costs.recon += 0.03;
                costs.vuln += 0.04;
                costs.planning += 0.08;
                costs.exploit += 0.02;
                costs.report += 0.01;
            }
        });

        return [
            { name: 'Orchestrator', cost: costs.orchestrator },
            { name: 'Recon', cost: costs.recon },
            { name: 'Vuln Analysis', cost: costs.vuln },
            { name: 'Planning', cost: costs.planning },
            { name: 'Exploitation', cost: costs.exploit },
            { name: 'Reporting', cost: costs.report },
        ].filter(item => item.cost > 0);
    };

    const data = processData();
    const colors = ['#06b6d4', '#3b82f6', '#8b5cf6', '#a855f7', '#d946ef', '#f43f5e'];

    if (data.length === 0) {
        return (
            <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                No cost data available
            </div>
        );
    }

    return (
        <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data} layout="vertical" margin={{ left: 20 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
                    <XAxis type="number" stroke="#94a3b8" tickFormatter={(val) => `$${val.toFixed(2)}`} />
                    <YAxis dataKey="name" type="category" stroke="#94a3b8" width={100} />
                    <Tooltip
                        contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f1f5f9' }}
                        formatter={(value: number) => [`$${value.toFixed(2)}`, 'Cost']}
                        cursor={{ fill: '#1e293b' }}
                    />
                    <Bar dataKey="cost" radius={[0, 4, 4, 0]}>
                        {data.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}


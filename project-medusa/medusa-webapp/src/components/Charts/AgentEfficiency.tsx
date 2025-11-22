import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

interface AgentEfficiencyProps {
    operations: any[];
}

export default function AgentEfficiency({ operations }: AgentEfficiencyProps) {
    // Mock distribution based on op types
    const data = [
        { name: 'Successful', value: operations.filter(op => op.status === 'completed').length },
        { name: 'Failed', value: operations.filter(op => op.status === 'error').length },
        { name: 'In Progress', value: operations.filter(op => op.status === 'running').length },
    ].filter(d => d.value > 0);

    const COLORS = ['#10b981', '#ef4444', '#eab308'];

    if (data.length === 0) {
        return (
             <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                No operation data available
            </div>
        );
    }

    return (
        <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={data}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        fill="#8884d8"
                        paddingAngle={5}
                        dataKey="value"
                    >
                        {data.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                    </Pie>
                    <Tooltip 
                        contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f1f5f9' }}
                    />
                    <Legend />
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
}


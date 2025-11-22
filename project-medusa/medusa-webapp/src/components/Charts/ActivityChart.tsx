import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { MedusaLogEntry } from '../../types/medusa';

interface ActivityChartProps {
    logs: MedusaLogEntry[];
}

export default function ActivityChart({ logs }: ActivityChartProps) {
    // Aggregate logs by hour/time bucket for the chart
    const processData = () => {
        if (logs.length === 0) return [];

        const dataMap = new Map<string, number>();
        
        // Process last 24 hours or available logs
        logs.forEach(log => {
            if (!log.timestamp) return;
            const date = new Date(log.timestamp);
            const timeKey = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            dataMap.set(timeKey, (dataMap.get(timeKey) || 0) + 1);
        });

        // Convert to array and sort
        // In a real scenario, we'd fill in gaps with 0
        return Array.from(dataMap.entries())
            .map(([name, activity]) => ({ name, activity }))
            .slice(-20); // Show last 20 data points
    };

    const data = processData();

    return (
        <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data.length > 0 ? data : [{name: 'No Data', activity: 0}]}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="name" stroke="#94a3b8" />
                    <YAxis stroke="#94a3b8" />
                    <Tooltip
                        contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f1f5f9' }}
                        itemStyle={{ color: '#f1f5f9' }}
                    />
                    <Line type="monotone" dataKey="activity" stroke="#06b6d4" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                </LineChart>
            </ResponsiveContainer>
        </div>
    );
}


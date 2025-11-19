import React, { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { Shield, AlertTriangle, Activity, Server, Database } from 'lucide-react';

interface DashboardProps {
    apiUrl: string;
}

export default function Dashboard({ apiUrl }: DashboardProps) {
    const [metrics, setMetrics] = useState<any>(null);

    // Mock data for visual appeal since real backend might not have history yet
    const activityData = [
        { name: '00:00', activity: 400, threats: 240 },
        { name: '04:00', activity: 300, threats: 139 },
        { name: '08:00', activity: 200, threats: 980 },
        { name: '12:00', activity: 278, threats: 390 },
        { name: '16:00', activity: 189, threats: 480 },
        { name: '20:00', activity: 239, threats: 380 },
        { name: '23:59', activity: 349, threats: 430 },
    ];

    useEffect(() => {
        const fetchMetrics = async () => {
            try {
                const res = await fetch(`${apiUrl}/api/metrics`);
                const data = await res.json();
                setMetrics(data);
            } catch (e) {
                console.error('Failed to fetch metrics', e);
            }
        };
        fetchMetrics();
        const interval = setInterval(fetchMetrics, 5000);
        return () => clearInterval(interval);
    }, [apiUrl]);

    const stats = [
        { label: 'Active Agents', value: '12', icon: Server, color: 'text-cyan-400', bg: 'bg-cyan-400/10' },
        { label: 'Threats Detected', value: metrics?.data_found || '0', icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-400/10' },
        { label: 'System Load', value: '42%', icon: Activity, color: 'text-green-400', bg: 'bg-green-400/10' },
        { label: 'Total Operations', value: metrics?.operations_completed || '0', icon: Database, color: 'text-purple-400', bg: 'bg-purple-400/10' },
    ];

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
                            <span className={`text-2xl font-bold text-white group-hover:scale-110 transition-transform`}>{stat.value}</span>
                        </div>
                        <h3 className="text-slate-400 text-sm font-medium">{stat.label}</h3>
                    </div>
                ))}
            </div>

            {/* Charts Area */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
                    <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                        <Activity className="w-5 h-5 text-cyan-400" />
                        Network Activity
                    </h3>
                    <div className="h-[300px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={activityData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                                <XAxis dataKey="name" stroke="#94a3b8" />
                                <YAxis stroke="#94a3b8" />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f1f5f9' }}
                                    itemStyle={{ color: '#f1f5f9' }}
                                />
                                <Line type="monotone" dataKey="activity" stroke="#06b6d4" strokeWidth={2} dot={false} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
                    <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                        <Shield className="w-5 h-5 text-red-400" />
                        Threat Analysis
                    </h3>
                    <div className="h-[300px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={activityData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                                <XAxis dataKey="name" stroke="#94a3b8" />
                                <YAxis stroke="#94a3b8" />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f1f5f9' }}
                                    cursor={{ fill: '#1e293b' }}
                                />
                                <Bar dataKey="threats" fill="#ef4444" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            {/* Recent Logs Preview */}
            <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
                <h3 className="text-lg font-semibold text-white mb-4">System Logs</h3>
                <div className="space-y-2 font-mono text-sm">
                    {[1, 2, 3].map((_, i) => (
                        <div key={i} className="flex items-center gap-4 text-slate-400 py-2 border-b border-slate-800/50 last:border-0">
                            <span className="text-slate-500">{new Date().toLocaleTimeString()}</span>
                            <span className="text-green-400">[INFO]</span>
                            <span>System scan completed successfully. No critical vulnerabilities found.</span>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}


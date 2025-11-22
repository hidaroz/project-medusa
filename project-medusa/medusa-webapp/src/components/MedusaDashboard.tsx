'use client';
import React, { useState } from 'react';
import Sidebar from './Sidebar';
import Terminal from './Terminal';
import Dashboard from './Dashboard';
import OperationsCenter from './Operations/OperationsCenter';
import ReportsPage from './Reports/ReportsPage';
import SystemStatus from './System/SystemStatus';
import CostDashboard from './Cost/CostDashboard';
import SettingsPage from './Settings/SettingsPage';
import { Search, Bell, User, Shield } from 'lucide-react';

interface MedusaDashboardProps {
    apiUrl: string;
}

export default function MedusaDashboard({ apiUrl }: MedusaDashboardProps) {
    const [activeTab, setActiveTab] = useState('dashboard');

    return (
        <div className="flex h-screen bg-slate-950 text-slate-200 overflow-hidden">
            <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

            <div className="flex-1 flex flex-col h-full min-w-0 relative">
                {/* Background Effect */}
                <div className="absolute inset-0 pointer-events-none z-0 bg-[radial-gradient(circle_at_top_right,_var(--tw-gradient-stops))] from-cyan-900/10 via-slate-950 to-slate-950" />

                {/* Top Bar */}
                <header className="h-16 bg-slate-950/80 backdrop-blur-md border-b border-slate-800 flex items-center justify-between px-6 shadow-lg z-10">
                    <div className="flex items-center gap-4 w-1/3">
                        <div className="relative w-full max-w-md">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                            <input
                                type="text"
                                placeholder="Search operations, targets, or logs..."
                                className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-cyan-500/50 transition-colors placeholder:text-slate-600 text-slate-300"
                            />
                        </div>
                    </div>

                    <div className="flex items-center gap-4">
                        <button className="p-2 text-slate-400 hover:text-cyan-400 hover:bg-slate-900 rounded-lg transition-colors relative">
                            <Bell className="w-5 h-5" />
                            <span className="absolute top-2 right-2 w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                        </button>
                        <div className="h-6 w-px bg-slate-800" />
                        <div className="flex items-center gap-3">
                            <div className="text-right hidden md:block">
                                <div className="text-sm font-medium text-white font-mono">Admin Operator</div>
                                <div className="text-[10px] text-cyan-400 font-mono tracking-wider">LEVEL 5 ACCESS</div>
                            </div>
                            <div className="w-10 h-10 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center relative overflow-hidden group cursor-pointer">
                                <div className="absolute inset-0 bg-cyan-500/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300" />
                                <User className="w-5 h-5 text-slate-400 group-hover:text-cyan-300 transition-colors relative z-10" />
                            </div>
                        </div>
                    </div>
                </header>

                {/* Main Content */}
                <main className="flex-1 p-6 overflow-hidden z-10">
                    {activeTab === 'dashboard' && <Dashboard apiUrl={apiUrl} />}
                    {activeTab === 'terminal' && <Terminal apiUrl={apiUrl} />}
                    {activeTab === 'operations' && <OperationsCenter />}
                    {activeTab === 'reports' && <ReportsPage />}
                    {activeTab === 'system' && <SystemStatus />}
                    {activeTab === 'cost' && <CostDashboard />}
                    {activeTab === 'settings' && <SettingsPage />}
                </main>
            </div>
        </div>
    );
}

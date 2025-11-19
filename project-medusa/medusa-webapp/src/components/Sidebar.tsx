import React from 'react';
import { LayoutDashboard, Terminal, Shield, Settings, Activity, Lock } from 'lucide-react';
import clsx from 'clsx';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export default function Sidebar({ activeTab, setActiveTab }: SidebarProps) {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'operations', label: 'Operations', icon: Shield },
    { id: 'terminal', label: 'Terminal', icon: Terminal },
    { id: 'system', label: 'System Status', icon: Activity },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <div className="h-screen w-64 bg-slate-950 border-r border-slate-800 flex flex-col shadow-[4px_0_24px_rgba(0,0,0,0.4)] z-10 relative">
      <div className="p-6 flex items-center gap-3 border-b border-slate-800/50">
        <div className="relative">
          <Lock className="w-8 h-8 text-cyan-400" />
          <div className="absolute inset-0 bg-cyan-400/20 blur-lg rounded-full" />
        </div>
        <h1 className="text-2xl font-bold text-white tracking-wider font-mono">MEDUSA</h1>
      </div>

      <nav className="flex-1 px-3 py-6 space-y-1">
        {menuItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={clsx(
              'w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 group relative overflow-hidden',
              activeTab === item.id
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-[0_0_12px_rgba(6,182,212,0.1)]'
                : 'text-slate-400 hover:text-cyan-300 hover:bg-slate-900/80'
            )}
          >
            {activeTab === item.id && (
              <div className="absolute left-0 top-0 bottom-0 w-1 bg-cyan-500 shadow-[0_0_8px_rgba(6,182,212,0.8)]" />
            )}
            <item.icon className={clsx(
              'w-5 h-5 transition-colors',
              activeTab === item.id ? 'text-cyan-400' : 'text-slate-500 group-hover:text-cyan-300'
            )} />
            <span className="font-medium tracking-wide text-sm">{item.label.toUpperCase()}</span>
          </button>
        ))}
      </nav>

      <div className="p-4 border-t border-slate-800/50 bg-slate-950/50 backdrop-blur-sm">
        <div className="flex items-center justify-between gap-3 px-4 py-2 rounded-lg bg-slate-900 border border-slate-800">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)] animate-pulse" />
            <span className="text-[10px] font-mono text-emerald-400 tracking-widest">ONLINE</span>
          </div>
          <span className="text-[10px] font-mono text-slate-500">v1.0.0</span>
        </div>
      </div>
    </div>
  );
}


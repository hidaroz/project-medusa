import React from 'react';
import { Bot, Eye, Search, Brain, Zap, FileText } from 'lucide-react';

interface AgentStatusPanelProps {
    isActive: boolean;
    logs?: any[]; // To infer active agent
}

export default function AgentStatusPanel({ isActive, logs = [] }: AgentStatusPanelProps) {
    const agents = [
        { id: 'orchestrator', name: 'Orchestrator', icon: Bot, description: 'Coordinating' },
        { id: 'recon', name: 'Reconnaissance', icon: Eye, description: 'Scanning' },
        { id: 'vuln', name: 'Vuln Analysis', icon: Search, description: 'Analyzing' },
        { id: 'planning', name: 'Planning', icon: Brain, description: 'Strategizing' },
        { id: 'exploit', name: 'Exploitation', icon: Zap, description: 'Testing' },
        { id: 'report', name: 'Reporting', icon: FileText, description: 'Generating' },
    ];

    // Simple logic to guess active agent from recent logs
    const getAgentStatus = (agentId: string) => {
        if (!isActive) return 'idle';
        
        // This is a heuristic since we don't have structured agent status yet
        const recentLog = logs[logs.length - 1]?.message?.toLowerCase() || '';
        if (recentLog.includes(agentId) || recentLog.includes(agents.find(a => a.id === agentId)?.name.toLowerCase() || '')) {
            return 'active';
        }
        return 'waiting';
    };

    return (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            {agents.map((agent) => {
                const status = getAgentStatus(agent.id);
                const isWorking = status === 'active';

                return (
                    <div 
                        key={agent.id}
                        className={`relative p-4 rounded-xl border transition-all duration-300 ${
                            isWorking 
                            ? 'bg-cyan-950/30 border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.15)]' 
                            : 'bg-slate-900/50 border-slate-800 opacity-70'
                        }`}
                    >
                        <div className="flex flex-col items-center text-center gap-3">
                            <div className={`p-3 rounded-full ${
                                isWorking ? 'bg-cyan-500/20 text-cyan-400' : 'bg-slate-800 text-slate-500'
                            }`}>
                                <agent.icon className={`w-6 h-6 ${isWorking ? 'animate-pulse' : ''}`} />
                            </div>
                            <div>
                                <h4 className={`text-sm font-medium ${isWorking ? 'text-white' : 'text-slate-400'}`}>
                                    {agent.name}
                                </h4>
                                <p className="text-[10px] text-slate-500 mt-1 font-mono uppercase">
                                    {isWorking ? 'ACTIVE' : 'IDLE'}
                                </p>
                            </div>
                        </div>
                        
                        {isWorking && (
                            <div className="absolute inset-x-0 bottom-0 h-1 bg-gradient-to-r from-transparent via-cyan-500 to-transparent opacity-50" />
                        )}
                    </div>
                );
            })}
        </div>
    );
}


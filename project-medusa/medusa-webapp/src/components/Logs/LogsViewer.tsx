import React, { useState, useRef, useEffect } from 'react';
import { Search, Filter, Download, ArrowDown, ArrowUp } from 'lucide-react';
import { useMedusa, useLogs } from '../../contexts/MedusaContext';

export default function LogsViewer() {
    const logs = useLogs();
    const [filter, setFilter] = useState('all');
    const [search, setSearch] = useState('');
    const [autoScroll, setAutoScroll] = useState(true);
    const logsEndRef = useRef<HTMLDivElement>(null);

    const filteredLogs = logs.filter(log => {
        if (filter !== 'all' && log.level !== filter) return false;
        if (search && !log.message.toLowerCase().includes(search.toLowerCase()) && !log.source.toLowerCase().includes(search.toLowerCase())) return false;
        return true;
    });

    useEffect(() => {
        if (autoScroll) {
            logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
        }
    }, [logs, autoScroll]);

    const handleDownload = () => {
        const content = JSON.stringify(filteredLogs, null, 2);
        const blob = new Blob([content], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `medusa-logs-${new Date().toISOString()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    return (
        <div className="h-full flex flex-col bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            {/* Toolbar */}
            <div className="p-4 border-b border-slate-800 flex items-center gap-4 bg-slate-900/50">
                <div className="relative flex-1 max-w-md">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                        type="text"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search logs..."
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-cyan-500/50 transition-colors text-slate-300 font-mono"
                    />
                </div>
                
                <div className="flex items-center gap-2">
                    {['all', 'info', 'warning', 'error', 'success'].map(f => (
                        <button
                            key={f}
                            onClick={() => setFilter(f)}
                            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors uppercase ${
                                filter === f 
                                ? 'bg-slate-700 text-white' 
                                : 'text-slate-500 hover:bg-slate-800'
                            }`}
                        >
                            {f}
                        </button>
                    ))}
                </div>

                <div className="flex-1" />

                <button 
                    onClick={() => setAutoScroll(!autoScroll)}
                    className={`p-2 rounded-lg transition-colors ${autoScroll ? 'text-cyan-400 bg-cyan-500/10' : 'text-slate-500 hover:bg-slate-800'}`}
                    title="Auto-scroll"
                >
                    {autoScroll ? <ArrowDown className="w-5 h-5" /> : <ArrowUp className="w-5 h-5" />}
                </button>

                <button 
                    onClick={handleDownload}
                    className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
                    title="Export JSON"
                >
                    <Download className="w-5 h-5" />
                </button>
            </div>

            {/* Logs List */}
            <div className="flex-1 overflow-y-auto p-4 space-y-1 font-mono text-sm custom-scrollbar">
                {filteredLogs.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-slate-500">No logs found</div>
                ) : (
                    filteredLogs.map((log, i) => (
                        <div key={i} className="flex items-start gap-3 hover:bg-slate-800/30 p-1 rounded transition-colors group">
                            <span className="text-slate-600 text-xs shrink-0 select-none mt-0.5 w-36">
                                {new Date(log.timestamp).toLocaleString()}
                            </span>
                            <span className={`text-xs font-bold shrink-0 w-20 uppercase ${
                                log.source === 'medusa' ? 'text-purple-400' :
                                log.source === 'system' ? 'text-blue-400' : 'text-slate-400'
                            }`}>
                                {log.source}
                            </span>
                            <span className={`text-xs font-bold shrink-0 w-16 uppercase ${
                                log.level === 'error' ? 'text-red-400' :
                                log.level === 'warning' ? 'text-yellow-400' :
                                log.level === 'success' ? 'text-green-400' : 'text-cyan-400'
                            }`}>
                                [{log.level}]
                            </span>
                            <span className="text-slate-300 break-all whitespace-pre-wrap">{log.message}</span>
                        </div>
                    ))
                )}
                <div ref={logsEndRef} />
            </div>
        </div>
    );
}


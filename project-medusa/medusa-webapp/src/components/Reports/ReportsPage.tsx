import React, { useEffect, useState } from 'react';
import { FileText, Search, Filter, Download, RefreshCw, FileJson, FileCode } from 'lucide-react';
import { medusaApi } from '../../lib/api';
import ReportViewer from './ReportViewer';

export default function ReportsPage() {
    const [reports, setReports] = useState<any[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [selectedReport, setSelectedReport] = useState<any | null>(null);
    const [filter, setFilter] = useState('all');
    const [search, setSearch] = useState('');

    const fetchReports = async () => {
        setIsLoading(true);
        try {
            const data = await medusaApi.getReports();
            setReports(data.reports || []);
        } catch (err) {
            console.error('Failed to fetch reports:', err);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchReports();
    }, []);

    const filteredReports = reports.filter(r => {
        if (filter !== 'all' && r.type !== filter) return false;
        if (search && !r.name.toLowerCase().includes(search.toLowerCase())) return false;
        return true;
    });

    return (
        <div className="h-full flex flex-col gap-6 p-6 overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-white font-mono">Reports Archive</h2>
                    <p className="text-slate-500 mt-1">Access generated security assessment reports</p>
                </div>
                <button 
                    onClick={fetchReports}
                    className="p-2 text-slate-400 hover:text-cyan-400 hover:bg-slate-900 rounded-lg transition-colors"
                >
                    <RefreshCw className="w-5 h-5" />
                </button>
            </div>

            {/* Toolbar */}
            <div className="flex items-center gap-4 bg-slate-900 p-4 rounded-xl border border-slate-800">
                <div className="relative flex-1 max-w-md">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                        type="text"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search reports..."
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-cyan-500/50 transition-colors text-slate-300"
                    />
                </div>
                <div className="h-8 w-px bg-slate-800" />
                <div className="flex gap-2">
                    {['all', 'html', 'json'].map(f => (
                        <button
                            key={f}
                            onClick={() => setFilter(f)}
                            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors uppercase ${
                                filter === f ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:bg-slate-800'
                            }`}
                        >
                            {f}
                        </button>
                    ))}
                </div>
            </div>

            {/* List */}
            <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
                <div className="overflow-y-auto flex-1 p-2 custom-scrollbar">
                    {isLoading ? (
                        <div className="h-full flex items-center justify-center text-slate-500">Loading...</div>
                    ) : filteredReports.length === 0 ? (
                        <div className="h-full flex items-center justify-center text-slate-500">No reports found</div>
                    ) : (
                        <div className="grid grid-cols-1 gap-2">
                            {filteredReports.map((report) => (
                                <div 
                                    key={report.id}
                                    onClick={() => setSelectedReport(report)}
                                    className="flex items-center justify-between p-4 rounded-lg hover:bg-slate-800/50 transition-colors cursor-pointer group border border-transparent hover:border-slate-700"
                                >
                                    <div className="flex items-center gap-4">
                                        <div className={`p-3 rounded-lg ${
                                            report.type === 'html' ? 'bg-orange-500/10 text-orange-400' : 
                                            report.type === 'json' ? 'bg-yellow-500/10 text-yellow-400' : 'bg-blue-500/10 text-blue-400'
                                        }`}>
                                            {report.type === 'html' ? <FileCode className="w-6 h-6" /> : <FileJson className="w-6 h-6" />}
                                        </div>
                                        <div>
                                            <h3 className="text-slate-200 font-medium group-hover:text-white transition-colors">{report.name}</h3>
                                            <div className="flex items-center gap-3 text-xs text-slate-500 mt-1">
                                                <span>{(report.size / 1024).toFixed(1)} KB</span>
                                                <span>•</span>
                                                <span>{new Date(report.created_at).toLocaleString()}</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="opacity-0 group-hover:opacity-100 transition-opacity">
                                        <button className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg transition-colors">
                                            View Report
                                        </button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {selectedReport && (
                <ReportViewer report={selectedReport} onClose={() => setSelectedReport(null)} />
            )}
        </div>
    );
}


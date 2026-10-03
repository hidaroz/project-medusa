import React, { useState } from 'react';
import { AlertTriangle, ShieldAlert, Info, Download, Filter, Search, ExternalLink } from 'lucide-react';
import { Finding } from '../../types/medusa';

interface FindingsViewerProps {
    findings: Finding[];
    operationId?: string;
    objective?: string;
}

export default function FindingsViewer({ findings, operationId, objective }: FindingsViewerProps) {
    const [filterSeverity, setFilterSeverity] = useState<string>('all');
    const [searchQuery, setSearchQuery] = useState('');

    // Filter findings
    const filteredFindings = findings.filter(finding => {
        const matchesSeverity = filterSeverity === 'all' || finding.severity === filterSeverity;
        const matchesSearch = !searchQuery ||
            finding.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
            finding.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
            finding.description.toLowerCase().includes(searchQuery.toLowerCase());

        return matchesSeverity && matchesSearch;
    });

    // Severity counts
    const severityCounts = {
        CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
        HIGH: findings.filter(f => f.severity === 'HIGH').length,
        MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
        LOW: findings.filter(f => f.severity === 'LOW').length,
        INFO: findings.filter(f => f.severity === 'INFO').length
    };

    const getSeverityColor = (severity: string) => {
        switch (severity) {
            case 'CRITICAL':
                return 'bg-red-500/10 text-red-400 border-red-500/20';
            case 'HIGH':
                return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
            case 'MEDIUM':
                return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
            case 'LOW':
                return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
            case 'INFO':
                return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
            default:
                return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
        }
    };

    const getSeverityIcon = (severity: string) => {
        switch (severity) {
            case 'CRITICAL':
            case 'HIGH':
                return <ShieldAlert className="w-4 h-4" />;
            case 'MEDIUM':
                return <AlertTriangle className="w-4 h-4" />;
            default:
                return <Info className="w-4 h-4" />;
        }
    };

    const handleExportJSON = () => {
        const exportData = {
            operation_id: operationId,
            objective: objective,
            generated_at: new Date().toISOString(),
            total_findings: findings.length,
            severity_breakdown: severityCounts,
            findings: findings
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `medusa-findings-${operationId || 'report'}-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    return (
        <div className="flex flex-col h-full bg-slate-950">
            {/* Header with Summary */}
            <div className="bg-slate-900/50 border-b border-slate-800 p-6">
                <div className="flex items-start justify-between mb-4">
                    <div>
                        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                            <ShieldAlert className="w-6 h-6 text-cyan-400" />
                            Security Findings
                        </h2>
                        {objective && (
                            <p className="text-slate-400 mt-1">Target: <span className="text-cyan-300">{objective}</span></p>
                        )}
                        {operationId && (
                            <p className="text-slate-500 text-sm mt-1 font-mono">ID: {operationId}</p>
                        )}
                    </div>
                    <button
                        onClick={handleExportJSON}
                        className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-medium transition-colors shadow-lg shadow-cyan-900/20 flex items-center gap-2"
                    >
                        <Download className="w-4 h-4" />
                        Export JSON
                    </button>
                </div>

                {/* Severity Summary Cards */}
                <div className="grid grid-cols-5 gap-3">
                    {Object.entries(severityCounts).map(([severity, count]) => (
                        <div
                            key={severity}
                            className={`p-3 rounded-lg border ${getSeverityColor(severity)}`}
                        >
                            <div className="flex items-center justify-between">
                                <span className="text-xs font-medium">{severity}</span>
                                {getSeverityIcon(severity)}
                            </div>
                            <div className="text-2xl font-bold mt-1">{count}</div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Filters and Search */}
            <div className="bg-slate-900/30 border-b border-slate-800 p-4 flex items-center gap-4">
                {/* Search */}
                <div className="relative flex-1 max-w-md">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Search findings..."
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-cyan-500/50 transition-colors text-slate-300"
                    />
                </div>

                {/* Severity Filter */}
                <div className="flex items-center gap-2">
                    <Filter className="w-4 h-4 text-slate-500" />
                    <select
                        value={filterSeverity}
                        onChange={(e) => setFilterSeverity(e.target.value)}
                        className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-300 focus:outline-none focus:border-cyan-500/50 transition-colors"
                    >
                        <option value="all">All Severity</option>
                        <option value="CRITICAL">Critical Only</option>
                        <option value="HIGH">High Only</option>
                        <option value="MEDIUM">Medium Only</option>
                        <option value="LOW">Low Only</option>
                        <option value="INFO">Info Only</option>
                    </select>
                </div>

                <div className="text-sm text-slate-400">
                    Showing <span className="text-cyan-400 font-mono">{filteredFindings.length}</span> of <span className="text-cyan-400 font-mono">{findings.length}</span> findings
                </div>
            </div>

            {/* Findings Table */}
            <div className="flex-1 overflow-auto custom-scrollbar">
                {filteredFindings.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-full text-slate-500">
                        <ShieldAlert className="w-16 h-16 mb-4 opacity-20" />
                        <p>No findings match the current filters</p>
                    </div>
                ) : (
                    <div className="p-4 space-y-3">
                        {filteredFindings.map((finding, index) => (
                            <div
                                key={index}
                                className="bg-slate-900/50 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition-all duration-200 hover:shadow-lg hover:shadow-slate-900/50"
                            >
                                {/* Header Row */}
                                <div className="flex items-start justify-between mb-3">
                                    <div className="flex items-start gap-3 flex-1">
                                        <span className={`px-2 py-1 rounded text-xs font-bold border flex items-center gap-1 ${getSeverityColor(finding.severity)}`}>
                                            {getSeverityIcon(finding.severity)}
                                            {finding.severity}
                                        </span>
                                        <div className="flex-1">
                                            <h3 className="text-white font-semibold text-lg">{finding.type}</h3>
                                            <div className="flex items-center gap-3 mt-1 text-sm">
                                                <span className="text-cyan-400 font-mono">{finding.host}{finding.port ? `:${finding.port}` : ''}</span>
                                                {finding.cvss_score && (
                                                    <>
                                                        <span className="text-slate-600">•</span>
                                                        <span className="text-orange-400">CVSS: {finding.cvss_score}</span>
                                                    </>
                                                )}
                                                {finding.discovered_at && (
                                                    <>
                                                        <span className="text-slate-600">•</span>
                                                        <span className="text-slate-500">{new Date(finding.discovered_at).toLocaleString()}</span>
                                                    </>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* Description */}
                                <div className="mb-3">
                                    <p className="text-slate-300 text-sm leading-relaxed">{finding.description}</p>
                                </div>

                                {/* Vulnerability */}
                                {finding.vulnerability && (
                                    <div className="mb-3 bg-slate-950/50 rounded-lg p-3 border border-slate-800">
                                        <div className="text-xs text-slate-500 mb-1">Vulnerability</div>
                                        <div className="text-slate-300 text-sm">{finding.vulnerability}</div>
                                    </div>
                                )}

                                {/* Evidence */}
                                {finding.evidence && (
                                    <div className="mb-3 bg-slate-950/50 rounded-lg p-3 border border-slate-800">
                                        <div className="text-xs text-slate-500 mb-1">Evidence</div>
                                        <pre className="text-slate-300 text-xs font-mono overflow-x-auto whitespace-pre-wrap">{finding.evidence}</pre>
                                    </div>
                                )}

                                {/* Remediation */}
                                {finding.remediation && (
                                    <div className="bg-green-950/20 rounded-lg p-3 border border-green-500/20">
                                        <div className="text-xs text-green-400 mb-1 font-medium">Recommended Remediation</div>
                                        <div className="text-green-300/80 text-sm">{finding.remediation}</div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}

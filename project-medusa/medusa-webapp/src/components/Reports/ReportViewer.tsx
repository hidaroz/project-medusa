import React, { useEffect, useState } from 'react';
import { X, Download, ExternalLink } from 'lucide-react';
import { medusaApi } from '../../lib/api';

interface ReportViewerProps {
    report: any;
    onClose: () => void;
}

export default function ReportViewer({ report, onClose }: ReportViewerProps) {
    const [content, setContent] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const fetchContent = async () => {
            try {
                const blob = await medusaApi.getReportContent(report.id);
                const text = await blob.text();
                setContent(text);
            } catch (err) {
                setError('Failed to load report content');
            } finally {
                setIsLoading(false);
            }
        };

        if (report) fetchContent();
    }, [report]);

    const handleDownload = () => {
        if (!content) return;
        const blob = new Blob([content], { type: report.type === 'json' ? 'application/json' : 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = report.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <div className="w-full h-full max-w-6xl bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
                {/* Header */}
                <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
                    <div>
                        <h2 className="text-xl font-semibold text-white flex items-center gap-2">
                            {report.name}
                        </h2>
                        <p className="text-sm text-slate-400">
                            {new Date(report.created_at).toLocaleString()} • {report.type.toUpperCase()}
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        <button 
                            onClick={handleDownload}
                            className="p-2 text-slate-400 hover:text-cyan-400 hover:bg-slate-900 rounded-lg transition-colors"
                            title="Download"
                        >
                            <Download className="w-5 h-5" />
                        </button>
                        <button 
                            onClick={onClose}
                            className="p-2 text-slate-400 hover:text-white hover:bg-slate-900 rounded-lg transition-colors"
                        >
                            <X className="w-5 h-5" />
                        </button>
                    </div>
                </div>

                {/* Content */}
                <div className="flex-1 bg-white overflow-hidden relative">
                    {isLoading && (
                        <div className="absolute inset-0 flex items-center justify-center bg-slate-900 text-slate-400">
                            Loading report...
                        </div>
                    )}
                    
                    {error && (
                        <div className="absolute inset-0 flex items-center justify-center bg-slate-900 text-red-400">
                            {error}
                        </div>
                    )}

                    {!isLoading && !error && content && (
                        report.type === 'html' ? (
                            <iframe 
                                srcDoc={content} 
                                className="w-full h-full border-none" 
                                title="Report Content"
                                sandbox="allow-scripts" 
                            />
                        ) : (
                            <div className="w-full h-full overflow-auto bg-slate-900 p-4 text-slate-300 font-mono text-sm whitespace-pre-wrap custom-scrollbar">
                                {content}
                            </div>
                        )
                    )}
                </div>
            </div>
        </div>
    );
}


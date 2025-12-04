'use client';

import { useState, useEffect } from 'react';

interface TrendData {
  vulnerabilities_over_time: Array<{ x: number; y: number; timestamp: string }>;
  data_items_over_time?: Array<{ x: number; y: number; timestamp: string }>;
  extraction_quality_over_time?: Array<{ x: number; y: number; timestamp: string }>;
  success_rate_over_time: Array<{ x: number; y: number; timestamp: string }>;
  technique_effectiveness: Record<string, {
    success_rate: number;
    usage_count: number;
    last_used: string | null;
  }>;
  operations_timeline: Array<{
    operation_id: number;
    timestamp: string;
    vulnerabilities_found: number;
    data_items_found?: number;
    structured_data_count?: number;
    success: boolean;
    duration: number;
    objective?: string;
  }>;
}

interface LearningDashboardProps {
  API_URL: string;
}

export default function LearningDashboard({ API_URL }: LearningDashboardProps) {
  const [trends, setTrends] = useState<TrendData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchTrends();
    const interval = setInterval(fetchTrends, 5000); // Update every 5 seconds
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchTrends = async () => {
    try {
      const response = await fetch(`${API_URL}/api/learning/trends`);
      if (response.ok) {
        const data = await response.json();
        setTrends(data);
      }
    } catch (error) {
      console.error('Failed to fetch trends:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <p className="text-slate-400">Loading learning trends...</p>
      </div>
    );
  }

  if (!trends || trends.operations_timeline.length === 0) {
    return (
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-xl font-semibold mb-4">📈 Learning Trends</h3>
        <p className="text-slate-400 text-center py-8">
          No trend data available yet. Run operations to see improvement over time.
        </p>
      </div>
    );
  }

  // Calculate improvement metrics - use data items found instead of vulnerabilities
  const recentOps = trends.operations_timeline.slice(-10);

  // Average data items found per recent operation
  const recentAvg = recentOps.length > 0
    ? recentOps.reduce((sum, op) => {
        const items = op.data_items_found ?? op.vulnerabilities_found ?? 0;
        return sum + items;
      }, 0) / recentOps.length
    : 0;

  // Calculate extraction quality (structured data percentage)
  const recentQuality = recentOps.length > 0
    ? recentOps.reduce((sum, op) => {
        const total = op.data_items_found || op.vulnerabilities_found || 0;
        const structured = op.structured_data_count || 0;
        return sum + (total > 0 ? (structured / total * 100) : 0);
      }, 0) / recentOps.length
    : 0;

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
      <h3 className="text-xl font-semibold mb-6">📈 Continuous Learning Trends</h3>

      {/* Improvement Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <p className="text-slate-400 text-sm mb-1">Recent Performance</p>
          <p className="text-2xl font-bold text-blue-400">{recentAvg.toFixed(1)}</p>
          <p className="text-xs text-slate-500 mt-1">Avg data items found per run (last 10)</p>
        </div>
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <p className="text-slate-400 text-sm mb-1">Extraction Quality</p>
          <p className="text-2xl font-bold text-green-400">{recentQuality.toFixed(1)}%</p>
          <p className="text-xs text-slate-500 mt-1">Structured data extraction (last 10)</p>
        </div>
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <p className="text-slate-400 text-sm mb-1">Total Operations</p>
          <p className="text-2xl font-bold text-purple-400">{trends.operations_timeline.length}</p>
          <p className="text-xs text-slate-500 mt-1">Operations tracked</p>
        </div>
      </div>

      {/* Data Items Found Over Time Chart */}
      <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 mb-6">
        <h4 className="text-lg font-semibold mb-4 text-blue-400">Data Items Found Over Time</h4>
        <div className="overflow-x-auto">
          <div className="h-48 flex items-end justify-start gap-1" style={{ minHeight: '192px', minWidth: 'max-content' }}>
            {(trends.data_items_over_time || trends.vulnerabilities_over_time).length > 0 ? (
              (trends.data_items_over_time || trends.vulnerabilities_over_time).map((point, idx) => {
              const allPoints = trends.data_items_over_time || trends.vulnerabilities_over_time;
              const maxY = Math.max(...allPoints.map(p => p.y), 1);

              // Calculate height as percentage of max, but ensure minimum visibility
              // Container is 192px (h-48 = 12rem = 192px), so calculate pixel height
              const containerHeight = 192; // h-48 in pixels
              const heightPercent = maxY > 0 ? (point.y / maxY) * 100 : 0;
              const heightPx = Math.max((heightPercent / 100) * containerHeight, point.y > 0 ? 16 : 0);

              return (
                <div key={idx} className="flex flex-col items-center justify-end min-w-[8px] max-w-[12px]" style={{ height: '100%' }}>
                  <div
                    className="w-full bg-blue-600 rounded-t transition-all hover:bg-blue-500"
                    style={{
                      height: `${heightPx}px`,
                      minHeight: point.y > 0 ? '8px' : '0px',
                      width: '100%'
                    }}
                    title={`Operation ${point.x}: ${point.y} data items found`}
                  ></div>
                  {idx % 10 === 0 && <span className="text-xs text-slate-500 mt-1">{point.x}</span>}
                </div>
              );
            })
          ) : (
            <div className="w-full text-center text-slate-500 py-8">
              No data available yet. Run operations to see data items found over time.
            </div>
          )}
          </div>
        </div>
        <p className="text-xs text-slate-500 mt-2 text-center">
          Each bar represents one operation. Height shows number of data items (records, credentials, endpoints) found.
        </p>
      </div>

      {/* Extraction Quality Trend */}
      <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 mb-6">
        <h4 className="text-lg font-semibold mb-4 text-green-400">Extraction Quality Trend</h4>
        <div className="overflow-x-auto">
          <div className="h-32 flex items-end justify-start gap-1" style={{ minHeight: '128px', minWidth: 'max-content' }}>
            {(trends.extraction_quality_over_time || trends.success_rate_over_time).length > 0 ? (
              (trends.extraction_quality_over_time || trends.success_rate_over_time).map((point, idx) => {
                // Container is 128px (h-32 = 8rem = 128px)
                // Use percentage directly, but convert to pixels for consistent rendering
                const containerHeight = 128; // h-32 in pixels
                const heightPercent = Math.max(point.y, 0); // Clamp to 0-100
                const heightPx = Math.max((heightPercent / 100) * containerHeight, point.y >= 0 ? 8 : 0);

                return (
                  <div key={idx} className="flex flex-col items-center justify-end min-w-[8px] max-w-[12px]" style={{ height: '100%' }}>
                    <div
                      className={`w-full rounded-t transition-all ${
                        point.y > 50 ? 'bg-green-600 hover:bg-green-500' :
                        point.y > 0 ? 'bg-yellow-600 hover:bg-yellow-500' :
                        'bg-slate-600 hover:bg-slate-500'
                      }`}
                      style={{
                        height: `${heightPx}px`,
                        minHeight: point.y >= 0 ? '8px' : '0px',
                        width: '100%'
                      }}
                      title={`Operation ${point.x}: ${point.y.toFixed(1)}% structured data extracted`}
                    ></div>
                    {idx % 10 === 0 && <span className="text-xs text-slate-500 mt-1">{point.x}</span>}
                  </div>
                );
              })
            ) : (
              <div className="w-full text-center text-slate-500 py-4 text-sm">
                No quality data yet. Run operations to see extraction quality improve.
              </div>
            )}
          </div>
        </div>
        <p className="text-xs text-slate-500 mt-2 text-center">
          Shows percentage of data that was extracted as structured (vs raw text). Higher is better.
        </p>
      </div>

      {/* Technique Effectiveness */}
      {Object.keys(trends.technique_effectiveness).length > 0 && (
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <h4 className="text-lg font-semibold mb-4 text-purple-400">Technique Effectiveness</h4>
          <div className="space-y-2">
            {Object.entries(trends.technique_effectiveness)
              .sort((a, b) => b[1].success_rate - a[1].success_rate)
              .slice(0, 5)
              .map(([technique, data]) => (
                <div key={technique} className="flex items-center justify-between p-2 bg-slate-800 rounded">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-white">{technique}</p>
                    <p className="text-xs text-slate-400">
                      Used {data.usage_count} time{data.usage_count !== 1 ? 's' : ''}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-semibold text-purple-400">
                      {(data.success_rate * 100).toFixed(0)}%
                    </p>
                    <div className="w-24 h-2 bg-slate-700 rounded-full mt-1">
                      <div
                        className="h-2 bg-purple-600 rounded-full"
                        style={{ width: `${data.success_rate * 100}%` }}
                      ></div>
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Operations Timeline */}
      <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 mt-6">
        <h4 className="text-lg font-semibold mb-4">Recent Operations Timeline</h4>
        <div className="space-y-2 max-h-64 overflow-y-auto">
          {trends.operations_timeline.slice(-10).reverse().map((op) => (
            <div
              key={op.operation_id}
              className="flex items-center justify-between p-2 bg-slate-800 rounded"
            >
              <div className="flex items-center gap-3">
                <div className={`w-3 h-3 rounded-full ${
                  op.success ? 'bg-green-500' : 'bg-red-500'
                }`}></div>
                <div>
                  <p className="text-sm text-white">
                    Operation #{op.operation_id} - {op.data_items_found || op.vulnerabilities_found || 0} data items
                    {op.objective && ` (${op.objective})`}
                  </p>
                  <p className="text-xs text-slate-400">
                    {new Date(op.timestamp).toLocaleString()} • {op.duration.toFixed(1)}s
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}


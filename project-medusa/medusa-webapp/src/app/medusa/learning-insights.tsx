'use client';

import { useState, useEffect } from 'react';

interface LearningInsightsProps {
  API_URL: string;
}

interface TechniqueInsight {
  technique_id: string;
  technique_name: string;
  success_rate: number;
  usage_count: number;
  recommendation: string;
  confidence: number;
}

interface ExtractionInsight {
  data_type: string;
  best_method: string;
  success_rate: number;
  recommendation: string;
}

interface LearningInsightsData {
  recommended_techniques: TechniqueInsight[];
  extraction_recommendations: ExtractionInsight[];
  objective_specific_insights: Record<string, TechniqueInsight[]>;
  improvement_trend: string;
  total_operations: number;
}

export default function LearningInsights({ API_URL }: LearningInsightsProps) {
  const [insights, setInsights] = useState<LearningInsightsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchInsights();
    const interval = setInterval(fetchInsights, 5000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchInsights = async () => {
    try {
      const response = await fetch(`${API_URL}/api/learning/insights`);
      if (response.ok) {
        const data = await response.json();
        setInsights(data);
      }
    } catch (error) {
      console.error('Failed to fetch learning insights:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <p className="text-slate-400">Loading learning insights...</p>
      </div>
    );
  }

  if (!insights || insights.total_operations === 0) {
    return (
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-xl font-semibold mb-4">🧠 Learning Insights</h3>
        <p className="text-slate-400 text-center py-8">
          No learning data available yet. Run operations to see AI-generated insights and recommendations.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-6">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-xl font-semibold">🧠 Learning Insights & Recommendations</h3>
        <div className="px-3 py-1 bg-purple-600/20 border border-purple-600/50 rounded-lg">
          <span className="text-sm font-semibold text-purple-400">
            {insights.total_operations} operations analyzed
          </span>
        </div>
      </div>

      {/* Improvement Trend */}
      <div className="mb-6 p-4 bg-slate-900 border border-slate-700 rounded-lg">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-slate-400 mb-1">Learning Trend</p>
            <p className={`text-2xl font-bold ${
              insights.improvement_trend === 'improving' ? 'text-green-400' :
              insights.improvement_trend === 'declining' ? 'text-red-400' :
              'text-yellow-400'
            }`}>
              {insights.improvement_trend === 'improving' ? '📈 Improving' :
               insights.improvement_trend === 'declining' ? '📉 Declining' :
               '➡️ Stable'}
            </p>
          </div>
          <div className="text-right">
            <p className="text-sm text-slate-400">Based on</p>
            <p className="text-lg font-semibold text-blue-400">{insights.total_operations} operations</p>
          </div>
        </div>
      </div>

      {/* Recommended Techniques */}
      {insights.recommended_techniques && insights.recommended_techniques.length > 0 && (
        <div className="mb-6">
          <h4 className="text-lg font-semibold mb-4 text-blue-400">🎯 Recommended Techniques</h4>
          <div className="space-y-3">
            {insights.recommended_techniques.map((tech, idx) => (
              <div
                key={idx}
                className="bg-slate-900 border border-slate-700 rounded-lg p-4"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-semibold text-white">{tech.technique_id}</span>
                      <span className="text-sm text-slate-400">{tech.technique_name}</span>
                    </div>
                    <p className="text-sm text-slate-300 mb-2">{tech.recommendation}</p>
                  </div>
                  <div className="text-right ml-4">
                    <div className="px-3 py-1 bg-green-600/20 border border-green-600/50 rounded-lg mb-2">
                      <p className="text-lg font-bold text-green-400">
                        {(tech.success_rate * 100).toFixed(0)}%
                      </p>
                      <p className="text-xs text-green-300">Success Rate</p>
                    </div>
                    <p className="text-xs text-slate-500">
                      Used {tech.usage_count} time{tech.usage_count !== 1 ? 's' : ''}
                    </p>
                    <p className="text-xs text-slate-500">
                      Confidence: {(tech.confidence * 100).toFixed(0)}%
                    </p>
                  </div>
                </div>
                <div className="w-full h-2 bg-slate-700 rounded-full mt-2">
                  <div
                    className="h-2 bg-green-600 rounded-full"
                    style={{ width: `${tech.success_rate * 100}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Extraction Method Recommendations */}
      {insights.extraction_recommendations && insights.extraction_recommendations.length > 0 && (
        <div className="mb-6">
          <h4 className="text-lg font-semibold mb-4 text-purple-400">🔧 Extraction Method Recommendations</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {insights.extraction_recommendations.map((rec, idx) => (
              <div
                key={idx}
                className="bg-slate-900 border border-slate-700 rounded-lg p-3"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-semibold text-white capitalize">
                    {rec.data_type.replace('_', ' ')}
                  </span>
                  <span className="px-2 py-1 text-xs bg-purple-600/20 text-purple-400 border border-purple-600/50 rounded">
                    {rec.best_method.toUpperCase()}
                  </span>
                </div>
                <p className="text-sm text-slate-300 mb-2">{rec.recommendation}</p>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-slate-700 rounded-full">
                    <div
                      className="h-2 bg-purple-600 rounded-full"
                      style={{ width: `${rec.success_rate * 100}%` }}
                    ></div>
                  </div>
                  <span className="text-xs text-slate-400">
                    {(rec.success_rate * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Objective-Specific Insights */}
      {insights.objective_specific_insights && Object.keys(insights.objective_specific_insights).length > 0 && (
        <div>
          <h4 className="text-lg font-semibold mb-4 text-yellow-400">🎯 Objective-Specific Insights</h4>
          <div className="space-y-4">
            {Object.entries(insights.objective_specific_insights).map(([objective, techniques]) => (
              <div key={objective} className="bg-slate-900 border border-slate-700 rounded-lg p-4">
                <h5 className="font-semibold text-white mb-3 capitalize">
                  For &quot;{objective.replace('_', ' ')}&quot; objectives:
                </h5>
                <div className="space-y-2">
                  {techniques.map((tech, idx) => (
                    <div key={idx} className="flex items-center justify-between p-2 bg-slate-800 rounded">
                      <span className="text-sm text-slate-300">{tech.technique_id}</span>
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-slate-400">
                          {tech.usage_count} uses
                        </span>
                        <span className="text-sm font-semibold text-green-400">
                          {(tech.success_rate * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No Insights Message */}
      {(!insights.recommended_techniques || insights.recommended_techniques.length === 0) &&
       (!insights.extraction_recommendations || insights.extraction_recommendations.length === 0) && (
        <div className="text-center py-8">
          <p className="text-slate-400 mb-2">
            Learning system is analyzing past operations...
          </p>
          <p className="text-xs text-slate-500">
            Run more operations to generate actionable insights and recommendations.
          </p>
        </div>
      )}
    </div>
  );
}


'use client';

import { useState, useEffect } from 'react';

export interface FilterState {
  types: string[];
  severities: string[];
  sources: string[];
  operations: string[];
  searchQuery: string;
  dateRange: { start: Date | null; end: Date | null };
}

interface DataFiltersProps {
  onFilterChange: (filters: FilterState) => void;
  availableTypes?: string[];
  availableSeverities?: string[];
  availableSources?: string[];
  availableOperations?: string[];
}

export default function DataFilters({
  onFilterChange,
  availableTypes = [],
  availableSeverities = [],
  availableSources = [],
  availableOperations = []
}: DataFiltersProps) {
  const [filters, setFilters] = useState<FilterState>({
    types: [],
    severities: [],
    sources: [],
    operations: [],
    searchQuery: '',
    dateRange: { start: null, end: null }
  });

  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    onFilterChange(filters);
  }, [filters, onFilterChange]);

  const updateFilter = (key: keyof FilterState, value: any) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const toggleArrayFilter = (key: 'types' | 'severities' | 'sources' | 'operations', value: string) => {
    setFilters(prev => {
      const current = prev[key];
      const newArray = current.includes(value)
        ? current.filter(v => v !== value)
        : [...current, value];
      return { ...prev, [key]: newArray };
    });
  };

  const clearFilters = () => {
    setFilters({
      types: [],
      severities: [],
      sources: [],
      operations: [],
      searchQuery: '',
      dateRange: { start: null, end: null }
    });
  };

  const hasActiveFilters =
    filters.types.length > 0 ||
    filters.severities.length > 0 ||
    filters.sources.length > 0 ||
    filters.operations.length > 0 ||
    filters.searchQuery.length > 0 ||
    filters.dateRange.start !== null ||
    filters.dateRange.end !== null;

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-4 mb-4">
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-lg font-semibold">🔍 Filters</h4>
        <div className="flex gap-2">
          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="px-3 py-1 text-xs bg-slate-700 hover:bg-slate-600 rounded text-slate-300"
            >
              Clear All
            </button>
          )}
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="px-3 py-1 text-xs bg-slate-700 hover:bg-slate-600 rounded text-slate-300"
          >
            {showAdvanced ? '▼' : '▶'} Advanced
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="mb-4">
        <input
          type="text"
          placeholder="Search across all data..."
          value={filters.searchQuery}
          onChange={(e) => updateFilter('searchQuery', e.target.value)}
          className="w-full px-4 py-2 bg-slate-900 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      {/* Quick Filters */}
      <div className="flex flex-wrap gap-2 mb-4">
        <button
          onClick={() => updateFilter('types', filters.types.includes('credential') ? [] : ['credential'])}
          className={`px-3 py-1 text-xs rounded transition ${
            filters.types.includes('credential')
              ? 'bg-orange-600 text-white'
              : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
          }`}
        >
          🔑 Credentials Only
        </button>
        <button
          onClick={() => updateFilter('types', filters.types.includes('medical_record') ? [] : ['medical_record'])}
          className={`px-3 py-1 text-xs rounded transition ${
            filters.types.includes('medical_record')
              ? 'bg-purple-600 text-white'
              : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
          }`}
        >
          📊 Medical Records
        </button>
        <button
          onClick={() => updateFilter('severities', filters.severities.includes('high') ? [] : ['high', 'critical'])}
          className={`px-3 py-1 text-xs rounded transition ${
            filters.severities.includes('high')
              ? 'bg-red-600 text-white'
              : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
          }`}
        >
          🚨 High Severity
        </button>
        <button
          onClick={() => {
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);
            updateFilter('dateRange', { start: yesterday, end: new Date() });
          }}
          className={`px-3 py-1 text-xs rounded transition ${
            filters.dateRange.start !== null
              ? 'bg-blue-600 text-white'
              : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
          }`}
        >
          📅 Last 24h
        </button>
      </div>

      {/* Advanced Filters */}
      {showAdvanced && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mt-4 pt-4 border-t border-slate-700">
          {/* Type Filter */}
          {availableTypes.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Type</label>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {availableTypes.map(type => (
                  <label key={type} className="flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={filters.types.includes(type)}
                      onChange={() => toggleArrayFilter('types', type)}
                      className="mr-2 rounded"
                    />
                    <span className="text-sm text-slate-300 capitalize">{type.replace('_', ' ')}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Severity Filter */}
          {availableSeverities.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Severity</label>
              <div className="space-y-1">
                {availableSeverities.map(severity => (
                  <label key={severity} className="flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={filters.severities.includes(severity)}
                      onChange={() => toggleArrayFilter('severities', severity)}
                      className="mr-2 rounded"
                    />
                    <span className="text-sm text-slate-300 capitalize">{severity}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Source Filter */}
          {availableSources.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Source</label>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {availableSources.map(source => (
                  <label key={source} className="flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={filters.sources.includes(source)}
                      onChange={() => toggleArrayFilter('sources', source)}
                      className="mr-2 rounded"
                    />
                    <span className="text-sm text-slate-300 truncate">{source}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Date Range */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">Date Range</label>
            <div className="space-y-2">
              <input
                type="date"
                value={filters.dateRange.start ? filters.dateRange.start.toISOString().split('T')[0] : ''}
                onChange={(e) => updateFilter('dateRange', {
                  ...filters.dateRange,
                  start: e.target.value ? new Date(e.target.value) : null
                })}
                className="w-full px-2 py-1 bg-slate-900 border border-slate-600 rounded text-white text-sm"
              />
              <input
                type="date"
                value={filters.dateRange.end ? filters.dateRange.end.toISOString().split('T')[0] : ''}
                onChange={(e) => updateFilter('dateRange', {
                  ...filters.dateRange,
                  end: e.target.value ? new Date(e.target.value) : null
                })}
                className="w-full px-2 py-1 bg-slate-900 border border-slate-600 rounded text-white text-sm"
              />
            </div>
          </div>
        </div>
      )}

      {/* Active Filters Summary */}
      {hasActiveFilters && (
        <div className="mt-4 pt-4 border-t border-slate-700">
          <div className="flex flex-wrap gap-2">
            <span className="text-xs text-slate-400">Active filters:</span>
            {filters.types.length > 0 && (
              <span className="px-2 py-1 bg-blue-600/20 text-blue-400 rounded text-xs">
                Types: {filters.types.length}
              </span>
            )}
            {filters.severities.length > 0 && (
              <span className="px-2 py-1 bg-red-600/20 text-red-400 rounded text-xs">
                Severities: {filters.severities.length}
              </span>
            )}
            {filters.searchQuery && (
              <span className="px-2 py-1 bg-green-600/20 text-green-400 rounded text-xs">
                Search: "{filters.searchQuery}"
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}


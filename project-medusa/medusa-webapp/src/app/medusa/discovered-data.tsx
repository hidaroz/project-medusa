'use client';

import { useState, useEffect, useMemo } from 'react';
import JsonViewer from './components/json-viewer';
import DataFilters from './components/data-filters';
import type { FilterState } from './components/data-filters';

interface DiscoveredData {
  vulnerabilities: Array<{
    id: string;
    description: string;
    severity: string;
    discovered_at: string;
    source: string;
  }>;
  services: Array<{
    port: string;
    name: string;
    description: string;
    discovered_at: string;
  }>;
  endpoints: Array<{
    url: string;
    discovered_at: string;
  }>;
  credentials: Array<{
    type?: string;
    value?: string;
    username?: string;
    password?: string;
    discovered_at: string;
    source?: string;
  }>;
  data_records: Array<{
    type: string;
    description?: string;
    raw_data?: string;
    structured_data?: Record<string, unknown>;
    file_path?: string;
    content_preview?: string;
    discovered_at: string;
  }>;
  total_items: number;
  has_operations: boolean;
}

interface DiscoveredDataViewProps {
  API_URL: string;
  currentObjective?: string;
}

export default function DiscoveredDataView({ API_URL, currentObjective = '' }: DiscoveredDataViewProps) {
  const [data, setData] = useState<DiscoveredData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'all' | 'vulnerabilities' | 'services' | 'endpoints' | 'data'>('all');
  const [viewMode, setViewMode] = useState<'tabs' | 'consolidated' | 'by_type' | 'by_severity' | 'by_operation'>('consolidated');
  const [filters, setFilters] = useState<FilterState>({
    types: [],
    severities: [],
    sources: [],
    operations: [],
    searchQuery: '',
    dateRange: { start: null, end: null }
  });

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000); // Update every 3 seconds
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentObjective]);

  // Memoize available filter options - MUST be at top level before any conditional returns
  const availableTypes = useMemo(() => {
    const types = new Set<string>();
    data?.data_records.forEach(r => types.add(r.type));
    data?.credentials.forEach(c => types.add(c.type || 'credential'));
    return Array.from(types);
  }, [data]);

  const availableSeverities = useMemo(() => {
    const severities = new Set<string>();
    data?.vulnerabilities.forEach(v => severities.add(v.severity));
    return Array.from(severities);
  }, [data]);

  const availableSources = useMemo(() => {
    const sources = new Set<string>();
    data?.vulnerabilities.forEach(v => sources.add(v.source));
    data?.data_records.forEach(r => sources.add(r.source || 'unknown'));
    return Array.from(sources);
  }, [data]);

  // Apply filters to data
  const filteredData = useMemo(() => {
    if (!data) return null;

    const filtered = { ...data };

    // Filter by type
    if (filters.types.length > 0) {
      filtered.data_records = filtered.data_records.filter(r =>
        filters.types.includes(r.type)
      );
      filtered.credentials = filtered.credentials.filter(c =>
        filters.types.includes(c.type || 'credential')
      );
    }

    // Filter by severity
    if (filters.severities.length > 0) {
      filtered.vulnerabilities = filtered.vulnerabilities.filter(v =>
        filters.severities.includes(v.severity)
      );
    }

    // Filter by source
    if (filters.sources.length > 0) {
      filtered.vulnerabilities = filtered.vulnerabilities.filter(v =>
        filters.sources.includes(v.source)
      );
      filtered.data_records = filtered.data_records.filter(r =>
        filters.sources.includes(r.source || 'unknown')
      );
    }

    // Filter by date range
    if (filters.dateRange.start || filters.dateRange.end) {
      const filterByDate = (item: { discovered_at: string }) => {
        const itemDate = new Date(item.discovered_at);
        if (filters.dateRange.start && itemDate < filters.dateRange.start) return false;
        if (filters.dateRange.end) {
          const endDate = new Date(filters.dateRange.end);
          endDate.setHours(23, 59, 59, 999);
          if (itemDate > endDate) return false;
        }
        return true;
      };
      filtered.vulnerabilities = filtered.vulnerabilities.filter(filterByDate);
      filtered.services = filtered.services.filter(filterByDate);
      filtered.endpoints = filtered.endpoints.filter(filterByDate);
      filtered.credentials = filtered.credentials.filter(filterByDate);
      filtered.data_records = filtered.data_records.filter(filterByDate);
    }

    // Search query filter
    if (filters.searchQuery) {
      const query = filters.searchQuery.toLowerCase();
      const matchesSearch = (item: { discovered_at: string; [key: string]: unknown }): boolean => {
        const searchableText = JSON.stringify(item).toLowerCase();
        return searchableText.includes(query);
      };
      filtered.vulnerabilities = filtered.vulnerabilities.filter(matchesSearch);
      filtered.services = filtered.services.filter(matchesSearch);
      filtered.endpoints = filtered.endpoints.filter(matchesSearch);
      filtered.credentials = filtered.credentials.filter(matchesSearch);
      filtered.data_records = filtered.data_records.filter(matchesSearch);
    }

    // Recalculate total
    filtered.total_items =
      filtered.vulnerabilities.length +
      filtered.services.length +
      filtered.endpoints.length +
      filtered.credentials.length +
      filtered.data_records.length;

    return filtered;
  }, [data, filters]);

  const fetchData = async () => {
    try {
      // Add objective filter if provided
      const url = currentObjective
        ? `${API_URL}/api/data/discovered?objective=${encodeURIComponent(currentObjective)}`
        : `${API_URL}/api/data/discovered`;
      const response = await fetch(url);
      if (response.ok) {
        const result = await response.json();
        setData(result);
      }
    } catch (error) {
      console.error('Failed to fetch discovered data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <p className="text-slate-400">Loading discovered data...</p>
      </div>
    );
  }

  const exportData = async (format: 'json' | 'csv' = 'json') => {
    try {
      const dataToExport = filteredData || data;
      if (!dataToExport) return;

      if (format === 'json') {
        const exportData = {
          export_timestamp: new Date().toISOString(),
          filters_applied: filters,
          summary: {
            vulnerabilities_count: dataToExport.vulnerabilities.length,
            services_count: dataToExport.services.length,
            endpoints_count: dataToExport.endpoints.length,
            credentials_count: dataToExport.credentials.length,
            data_records_count: dataToExport.data_records.length
          },
          vulnerabilities: dataToExport.vulnerabilities,
          services: dataToExport.services,
          endpoints: dataToExport.endpoints,
          credentials: dataToExport.credentials,
          data_records: dataToExport.data_records
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `medusa-discovered-data-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else if (format === 'csv') {
        // CSV export for data records
        const csvRows: string[] = [];

        // Headers
        csvRows.push('Type,Discovered At,Source,Operation ID,Data');

        // Data records
        dataToExport.data_records.forEach(record => {
          const dataStr = record.structured_data
            ? JSON.stringify(record.structured_data).replace(/"/g, '""')
            : (record.raw_data || '').replace(/"/g, '""');
          csvRows.push(
            `"${record.type}","${record.discovered_at}","${record.source || ''}","${record.operation_id || ''}","${dataStr}"`
          );
        });

        const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `medusa-data-records-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Failed to export data:', error);
      alert('Failed to export data');
    }
  };

  if (!data || (!data.has_operations && data.total_items === 0)) {
    return (
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-xl font-semibold mb-4">🔍 Discovered Data</h3>
        <p className="text-slate-400 text-center py-8">
          No data discovered yet. Run operations to see findings here.
        </p>
      </div>
    );
  }

  if (data.total_items === 0 && data.has_operations) {
    return (
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-xl font-semibold mb-4">🔍 Discovered Data</h3>
        <p className="text-slate-400 text-center py-8">
          Operations completed but no data was extracted. Check the operations log for details.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-xl font-semibold">🔍 Discovered Data</h3>
          <p className="text-xs text-slate-400 mt-1">
            ✅ Real data extracted from actual operations • Not pre-created or mock data
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="px-3 py-1 bg-blue-600/20 border border-blue-600/50 rounded-lg">
            <span className="text-sm font-semibold text-blue-400">{data.total_items} items</span>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => exportData('json')}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-sm font-medium transition"
            >
              📥 Export JSON
            </button>
            <button
              onClick={() => exportData('csv')}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm font-medium transition"
            >
              📊 Export CSV
            </button>
          </div>
        </div>
      </div>

      {/* Filters */}
      <DataFilters
        onFilterChange={setFilters}
        availableTypes={availableTypes}
        availableSeverities={availableSeverities}
        availableSources={availableSources}
      />

      {/* View Mode Toggle */}
      <div className="flex gap-2 mb-4 flex-wrap">
        <button
          onClick={() => setViewMode('consolidated')}
          className={`px-3 py-1 text-sm rounded-lg transition ${
            viewMode === 'consolidated'
              ? 'bg-blue-600 text-white'
              : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
          }`}
        >
          📋 Chronological
        </button>
        <button
          onClick={() => setViewMode('tabs')}
          className={`px-3 py-1 text-sm rounded-lg transition ${
            viewMode === 'tabs'
              ? 'bg-blue-600 text-white'
              : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
          }`}
        >
          📑 By Category
        </button>
        <button
          onClick={() => setViewMode('by_type')}
          className={`px-3 py-1 text-sm rounded-lg transition ${
            viewMode === 'by_type'
              ? 'bg-blue-600 text-white'
              : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
          }`}
        >
          🏷️ By Type
        </button>
        <button
          onClick={() => setViewMode('by_severity')}
          className={`px-3 py-1 text-sm rounded-lg transition ${
            viewMode === 'by_severity'
              ? 'bg-blue-600 text-white'
              : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
          }`}
        >
          ⚠️ By Severity
        </button>
      </div>

      {viewMode === 'consolidated' ? (
        <ConsolidatedView data={filteredData || data} filters={filters} />
      ) : viewMode === 'by_type' ? (
        <ByTypeView data={filteredData || data} filters={filters} />
      ) : viewMode === 'by_severity' ? (
        <BySeverityView data={filteredData || data} filters={filters} />
      ) : (
        <>
          {/* Tabs */}
          <div className="flex gap-2 mb-6 border-b border-slate-700">
            {[
              { id: 'all', label: 'All', count: data.total_items },
              { id: 'vulnerabilities', label: 'Vulnerabilities', count: data.vulnerabilities.length },
              { id: 'services', label: 'Services', count: data.services.length },
              { id: 'endpoints', label: 'Endpoints', count: data.endpoints.length },
              { id: 'data', label: 'Data Records', count: data.data_records.length },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as 'all' | 'vulnerabilities' | 'services' | 'endpoints' | 'data')}
                className={`px-4 py-2 text-sm font-medium transition ${
                  activeTab === tab.id
                    ? 'border-b-2 border-blue-500 text-blue-400'
                    : 'text-slate-400 hover:text-slate-300'
                }`}
              >
                {tab.label} ({tab.count})
              </button>
            ))}
          </div>

      {/* Content */}
      <div className="space-y-6">
        {/* Vulnerabilities */}
        {(activeTab === 'all' || activeTab === 'vulnerabilities') && data.vulnerabilities.length > 0 && (
          <div>
            <h4 className="text-lg font-semibold mb-3 text-red-400">🔴 Security Vulnerabilities</h4>
            <div className="space-y-3">
              {data.vulnerabilities.map((vuln) => (
                <div
                  key={vuln.id}
                  className="bg-slate-900 border border-red-700/50 rounded-lg p-4"
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <span className={`px-2 py-1 text-xs font-semibold rounded ${
                          vuln.severity === 'high' ? 'bg-red-600 text-white' :
                          vuln.severity === 'medium' ? 'bg-yellow-600 text-white' :
                          'bg-orange-600 text-white'
                        }`}>
                          {vuln.severity.toUpperCase()}
                        </span>
                        <span className="text-xs text-slate-500">
                          {new Date(vuln.discovered_at).toLocaleString()}
                        </span>
                      </div>
                      <p className="text-slate-200">{vuln.description}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Services */}
        {(activeTab === 'all' || activeTab === 'services') && data.services.length > 0 && (
          <div>
            <h4 className="text-lg font-semibold mb-3 text-blue-400">🌐 Services Discovered</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {data.services.map((service, idx) => (
                <div
                  key={idx}
                  className="bg-slate-900 border border-slate-700 rounded-lg p-3"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-white uppercase">{service.name}</span>
                    <span className="px-2 py-1 text-xs bg-green-600/20 text-green-400 border border-green-600/50 rounded">
                      Active
                    </span>
                  </div>
                  <p className="text-sm text-slate-400 mb-1">Port: {service.port}</p>
                  {service.description && (
                    <p className="text-xs text-slate-500">{service.description}</p>
                  )}
                  <p className="text-xs text-slate-600 mt-2">
                    {new Date(service.discovered_at).toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Endpoints */}
        {(activeTab === 'all' || activeTab === 'endpoints') && data.endpoints.length > 0 && (
          <div>
            <h4 className="text-lg font-semibold mb-3 text-green-400">🔗 API Endpoints</h4>
            <div className="space-y-2">
              {data.endpoints.map((endpoint, idx) => (
                <div
                  key={idx}
                  className="bg-slate-900 border border-slate-700 rounded-lg p-3 flex items-center justify-between"
                >
                  <a
                    href={endpoint.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 break-all"
                  >
                    {endpoint.url}
                  </a>
                  <span className="text-xs text-slate-500 ml-4">
                    {new Date(endpoint.discovered_at).toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Data Records - Show Actual Medical Records */}
        {(activeTab === 'all' || activeTab === 'data') && data.data_records.length > 0 && (
          <div>
            <h4 className="text-lg font-semibold mb-3 text-purple-400">📊 Medical Records & Data</h4>
            <div className="space-y-3">
              {data.data_records.map((record, idx) => (
                <div
                  key={idx}
                  className="bg-slate-900 border border-purple-700/50 rounded-lg p-4"
                >
                  <div className="flex items-start justify-between mb-2">
                    <span className="px-2 py-1 text-xs font-semibold bg-purple-600/20 text-purple-400 border border-purple-600/50 rounded">
                      {record.type === 'medical_record' ? 'Medical Record' :
                       record.type === 'data_file' ? 'Data File' : 'Data Record'}
                    </span>
                    <span className="text-xs text-slate-500">
                      {new Date(record.discovered_at).toLocaleString()}
                    </span>
                  </div>

                  {/* Show structured data if available using JsonViewer */}
                  {record.structured_data && Object.keys(record.structured_data).length > 0 && (
                    <div className="mt-3">
                      <p className="text-xs text-slate-400 mb-2">Structured Data:</p>
                      <JsonViewer
                        data={record.structured_data}
                        maxDepth={5}
                        collapsed={true}
                        showCopyButton={true}
                      />
                    </div>
                  )}

                  {/* Show raw data */}
                  {record.raw_data && (
                    <div className="mt-3">
                      <p className="text-xs text-slate-400 mb-1">Raw Data:</p>
                      <pre className="bg-slate-800 border border-slate-700 rounded p-2 text-xs text-slate-300 overflow-x-auto">
                        {record.raw_data}
                      </pre>
                    </div>
                  )}

                  {/* Show description if no structured/raw data */}
                  {!record.raw_data && !record.structured_data && record.description && (
                    <p className="text-slate-200 mt-2">{record.description}</p>
                  )}

                  {/* Show file content preview */}
                  {record.type === 'data_file' && record.content_preview && (
                    <div className="mt-3">
                      <p className="text-xs text-slate-400 mb-1">File: {record.file_path}</p>
                      <pre className="bg-slate-800 border border-slate-700 rounded p-2 text-xs text-slate-300 overflow-x-auto max-h-40">
                        {record.content_preview}
                      </pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
        </>
      )}
    </div>
  );
}

// Helper function to highlight search terms
function highlightSearch(text: string, searchQuery: string): JSX.Element {
  if (!searchQuery) return <>{text}</>;

  const parts = text.split(new RegExp(`(${searchQuery})`, 'gi'));
  return (
    <>
      {parts.map((part, i) =>
        part.toLowerCase() === searchQuery.toLowerCase() ? (
          <mark key={i} className="bg-yellow-500/30 text-yellow-200">{part}</mark>
        ) : (
          <span key={i}>{part}</span>
        )
      )}
    </>
  );
}

// Consolidated View - All data in one organized view
function ConsolidatedView({ data, filters }: { data: DiscoveredData; filters: FilterState }) {
  // Combine all data into a single timeline
  const allItems: Array<{
    type: 'vulnerability' | 'service' | 'endpoint' | 'credential' | 'data_record';
    data: DiscoveredData['vulnerabilities'][0] | DiscoveredData['services'][0] | DiscoveredData['endpoints'][0] | DiscoveredData['credentials'][0] | DiscoveredData['data_records'][0];
    timestamp: string;
  }> = [];

  data.vulnerabilities.forEach(v => {
    allItems.push({ type: 'vulnerability', data: v, timestamp: v.discovered_at });
  });
  data.services.forEach(s => {
    allItems.push({ type: 'service', data: s, timestamp: s.discovered_at });
  });
  data.endpoints.forEach(e => {
    allItems.push({ type: 'endpoint', data: e, timestamp: e.discovered_at });
  });
  data.credentials.forEach(c => {
    allItems.push({ type: 'credential', data: c, timestamp: c.discovered_at });
  });
  data.data_records.forEach(r => {
    allItems.push({ type: 'data_record', data: r, timestamp: r.discovered_at });
  });

  // Sort by timestamp (newest first)
  allItems.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return (
    <div className="space-y-4">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
        <div className="bg-red-900/20 border border-red-700 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-red-400">{data.vulnerabilities.length}</p>
          <p className="text-xs text-red-300 mt-1">Vulnerabilities</p>
        </div>
        <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-blue-400">{data.services.length}</p>
          <p className="text-xs text-blue-300 mt-1">Services</p>
        </div>
        <div className="bg-green-900/20 border border-green-700 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-green-400">{data.endpoints.length}</p>
          <p className="text-xs text-green-300 mt-1">Endpoints</p>
        </div>
        <div className="bg-yellow-900/20 border border-yellow-700 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-yellow-400">{data.credentials.length}</p>
          <p className="text-xs text-yellow-300 mt-1">Credentials</p>
        </div>
        <div className="bg-purple-900/20 border border-purple-700 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-purple-400">{data.data_records.length}</p>
          <p className="text-xs text-purple-300 mt-1">Data Records</p>
        </div>
      </div>

      {/* All Items Timeline */}
      <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-lg font-semibold">📋 All Discovered Items (Chronological)</h4>
          <span className="text-xs text-green-400 bg-green-900/20 px-2 py-1 rounded">
            ✅ Real Data from Operations
          </span>
        </div>
        <div className="space-y-4">
          {allItems.map((item, idx) => (
            <div
              key={idx}
              className={`border-l-4 rounded-lg p-4 ${
                item.type === 'vulnerability' ? 'border-red-500 bg-red-900/10' :
                item.type === 'service' ? 'border-blue-500 bg-blue-900/10' :
                item.type === 'endpoint' ? 'border-green-500 bg-green-900/10' :
                item.type === 'credential' ? 'border-yellow-500 bg-yellow-900/10' :
                'border-purple-500 bg-purple-900/10'
              }`}
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-1 text-xs font-semibold rounded ${
                    item.type === 'vulnerability' ? 'bg-red-600 text-white' :
                    item.type === 'service' ? 'bg-blue-600 text-white' :
                    item.type === 'endpoint' ? 'bg-green-600 text-white' :
                    item.type === 'credential' ? 'bg-yellow-600 text-white' :
                    'bg-purple-600 text-white'
                  }`}>
                    {item.type.replace('_', ' ').toUpperCase()}
                  </span>
                  {item.type === 'vulnerability' && item.data.severity && (
                    <span className={`px-2 py-1 text-xs rounded ${
                      item.data.severity === 'high' ? 'bg-red-600 text-white' :
                      item.data.severity === 'medium' ? 'bg-yellow-600 text-white' :
                      'bg-orange-600 text-white'
                    }`}>
                      {item.data.severity.toUpperCase()}
                    </span>
                  )}
                </div>
                <span className="text-xs text-slate-500">
                  {new Date(item.timestamp).toLocaleString()}
                </span>
              </div>

              {/* Display item-specific data */}
              {item.type === 'vulnerability' && (
                <div>
                  <p className="font-semibold text-white mb-1">
                    {highlightSearch(item.data.id || 'Vulnerability', filters.searchQuery)}
                  </p>
                  <p className="text-sm text-slate-300">
                    {highlightSearch(item.data.description, filters.searchQuery)}
                  </p>
                  {item.data.operation_type && (
                    <p className="text-xs text-slate-500 mt-1">
                      From: {item.data.operation_type} operation
                      {item.data.operation_objective && ` - ${item.data.operation_objective}`}
                      {item.data.technique_id && ` • Technique: ${item.data.technique_id}`}
                      {item.data.extraction_method && ` • Method: ${item.data.extraction_method}`}
                    </p>
                  )}
                </div>
              )}

              {item.type === 'service' && (
                <div>
                  <p className="font-semibold text-white mb-1">{item.data.name.toUpperCase()} - Port {item.data.port}</p>
                  {item.data.description && (
                    <p className="text-sm text-slate-300">{item.data.description}</p>
                  )}
                </div>
              )}

              {item.type === 'endpoint' && (
                <div>
                  <a
                    href={item.data.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300 break-all"
                  >
                    {item.data.url}
                  </a>
                </div>
              )}

              {item.type === 'credential' && (
                <div>
                  {item.data.username && (
                    <p className="text-sm text-slate-300">Username: <span className="text-white">{item.data.username}</span></p>
                  )}
                  {item.data.password && (
                    <p className="text-sm text-slate-300">Password: <span className="text-white">{item.data.password}</span></p>
                  )}
                  {item.data.value && (
                    <p className="text-sm text-slate-300">{item.data.value}</p>
                  )}
                </div>
              )}

              {item.type === 'data_record' && (
                <div>
                  {item.data.structured_data && Object.keys(item.data.structured_data).length > 0 && (
                    <div className="mb-2">
                      <JsonViewer
                        data={item.data.structured_data}
                        maxDepth={3}
                        collapsed={true}
                        showCopyButton={true}
                      />
                    </div>
                  )}
                  {item.data.raw_data && (
                    <details className="mt-2">
                      <summary className="text-sm text-slate-400 cursor-pointer hover:text-slate-300">
                        View Raw Data
                      </summary>
                      <pre className="mt-2 bg-slate-800 border border-slate-700 rounded p-2 text-xs text-slate-300 overflow-x-auto max-h-40">
                        {highlightSearch(item.data.raw_data, filters.searchQuery)}
                      </pre>
                    </details>
                  )}
                  {item.data.operation_type && (
                    <div className="text-xs text-slate-500 mt-2 space-y-1">
                      <p>
                        ✅ Real data from: {item.data.operation_type} operation
                        {item.data.operation_objective && ` - ${item.data.operation_objective}`}
                      </p>
                      {item.data.operation_id && (
                        <p>Operation ID: {item.data.operation_id}</p>
                      )}
                      {item.data.technique_id && (
                        <p>Technique: {item.data.technique_id}</p>
                      )}
                      {item.data.extraction_method && (
                        <p>Extraction Method: {item.data.extraction_method.toUpperCase()}</p>
                      )}
                      {item.data.confidence && (
                        <p>Confidence: {(item.data.confidence * 100).toFixed(0)}%</p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
        </div>
      </div>
    );
  }

// By Type View - Group data by type
function ByTypeView({ data, filters }: { data: DiscoveredData; filters: FilterState }) {
  const grouped = useMemo(() => {
    const groups: Record<string, DiscoveredData['data_records']> = {};

    data.data_records.forEach(r => {
      const type = r.type || 'unknown';
      if (!groups[type]) groups[type] = [];
      groups[type].push(r);
    });

    data.credentials.forEach(c => {
      const type = c.type || 'credential';
      if (!groups[type]) groups[type] = [];
      groups[type].push(c);
    });

    return groups;
  }, [data]);

  return (
    <div className="space-y-6">
      {Object.entries(grouped).map(([type, items]) => (
        <div key={type} className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <h4 className="text-lg font-semibold mb-4 capitalize text-purple-400">
            {type.replace('_', ' ')} ({items.length})
          </h4>
          <div className="space-y-3">
            {items.map((item, idx) => (
              <div key={idx} className="bg-slate-800 border border-slate-700 rounded-lg p-3">
                {item.structured_data && (
                  <JsonViewer data={item.structured_data} maxDepth={3} collapsed={true} />
                )}
                {item.raw_data && (
                  <pre className="text-xs text-slate-300 mt-2 overflow-x-auto">
                    {highlightSearch(item.raw_data, filters.searchQuery)}
                  </pre>
                )}
                <p className="text-xs text-slate-500 mt-2">
                  {new Date(item.discovered_at).toLocaleString()}
                  {item.operation_id && ` • Op: ${item.operation_id}`}
                </p>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// By Severity View - Group vulnerabilities by severity
function BySeverityView({ data, filters }: { data: DiscoveredData; filters: FilterState }) {
  const grouped = useMemo(() => {
    const groups: Record<string, typeof data.vulnerabilities> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: []
    };

    data.vulnerabilities.forEach(v => {
      const severity = v.severity?.toLowerCase() || 'info';
      if (groups[severity]) {
        groups[severity].push(v);
      } else {
        groups.info.push(v);
      }
    });

    return groups;
  }, [data]);

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const severityColors: Record<string, string> = {
    critical: 'text-red-400 border-red-700',
    high: 'text-orange-400 border-orange-700',
    medium: 'text-yellow-400 border-yellow-700',
    low: 'text-blue-400 border-blue-700',
    info: 'text-slate-400 border-slate-700'
  };

  return (
    <div className="space-y-6">
      {severityOrder.map(severity => {
        const items = grouped[severity];
        if (items.length === 0) return null;

        return (
          <div key={severity} className={`bg-slate-900 border rounded-lg p-4 ${severityColors[severity]}`}>
            <h4 className="text-lg font-semibold mb-4 capitalize">
              {severity.toUpperCase()} ({items.length})
            </h4>
            <div className="space-y-3">
              {items.map((vuln, idx) => (
                <div key={idx} className="bg-slate-800 border border-slate-700 rounded-lg p-3">
                  <p className="font-semibold text-white mb-1">
                    {highlightSearch(vuln.id || 'Vulnerability', filters.searchQuery)}
                  </p>
                  <p className="text-sm text-slate-300">
                    {highlightSearch(vuln.description, filters.searchQuery)}
                  </p>
                  <p className="text-xs text-slate-500 mt-2">
                    {new Date(vuln.discovered_at).toLocaleString()} • Source: {vuln.source}
                  </p>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}


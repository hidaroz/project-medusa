'use client';

import { useState } from 'react';

interface JsonViewerProps {
  data: any;
  maxDepth?: number;
  collapsed?: boolean;
  showCopyButton?: boolean;
}

export default function JsonViewer({
  data,
  maxDepth = 10,
  collapsed = false,
  showCopyButton = true
}: JsonViewerProps) {
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());
  const [copied, setCopied] = useState(false);

  const togglePath = (path: string) => {
    const newExpanded = new Set(expandedPaths);
    if (newExpanded.has(path)) {
      newExpanded.delete(path);
    } else {
      newExpanded.add(path);
    }
    setExpandedPaths(newExpanded);
  };

  const copyToClipboard = () => {
    const jsonString = JSON.stringify(data, null, 2);
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const renderValue = (value: any, path: string = '', depth: number = 0): JSX.Element => {
    if (depth > maxDepth) {
      return <span className="text-slate-500 italic">[Max depth reached]</span>;
    }

    if (value === null) {
      return <span className="text-slate-400">null</span>;
    }

    if (value === undefined) {
      return <span className="text-slate-400">undefined</span>;
    }

    if (typeof value === 'boolean') {
      return <span className="text-purple-400">{String(value)}</span>;
    }

    if (typeof value === 'number') {
      return <span className="text-blue-400">{value}</span>;
    }

    if (typeof value === 'string') {
      // Truncate long strings
      const displayValue = value.length > 200 ? `${value.substring(0, 200)}...` : value;
      return (
        <span className="text-green-400">
          "{displayValue}"
        </span>
      );
    }

    if (Array.isArray(value)) {
      const isExpanded = expandedPaths.has(path);
      const shouldCollapse = collapsed && depth > 0 && !isExpanded;

      if (shouldCollapse) {
        return (
          <span>
            <button
              onClick={() => togglePath(path)}
              className="text-blue-400 hover:text-blue-300 cursor-pointer"
            >
              [{value.length} items]
            </button>
          </span>
        );
      }

      return (
        <div className="ml-4">
          <button
            onClick={() => togglePath(path)}
            className="text-slate-400 hover:text-slate-300 cursor-pointer mr-2"
          >
            {isExpanded ? '▼' : '▶'}
          </button>
          <span className="text-slate-300">[</span>
          {isExpanded && (
            <div className="ml-4">
              {value.map((item, index) => (
                <div key={index} className="flex items-start">
                  <span className="text-slate-500 mr-2">{index}:</span>
                  <div className="flex-1">
                    {renderValue(item, `${path}[${index}]`, depth + 1)}
                  </div>
                  {index < value.length - 1 && <span className="text-slate-500">,</span>}
                </div>
              ))}
            </div>
          )}
          {!isExpanded && <span className="text-slate-500 ml-2">... {value.length} items</span>}
          <span className="text-slate-300">]</span>
        </div>
      );
    }

    if (typeof value === 'object') {
      const isExpanded = expandedPaths.has(path);
      const shouldCollapse = collapsed && depth > 0 && !isExpanded;
      const keys = Object.keys(value);

      if (shouldCollapse) {
        return (
          <span>
            <button
              onClick={() => togglePath(path)}
              className="text-blue-400 hover:text-blue-300 cursor-pointer"
            >
              {'{'} {keys.length} keys {'}'}
            </button>
          </span>
        );
      }

      return (
        <div className="ml-4">
          <button
            onClick={() => togglePath(path)}
            className="text-slate-400 hover:text-slate-300 cursor-pointer mr-2"
          >
            {isExpanded ? '▼' : '▶'}
          </button>
          <span className="text-slate-300">{'{'}</span>
          {isExpanded && (
            <div className="ml-4">
              {keys.map((key, index) => (
                <div key={key} className="flex items-start">
                  <span className="text-yellow-400 mr-2">"{key}":</span>
                  <div className="flex-1">
                    {renderValue(value[key], `${path}.${key}`, depth + 1)}
                  </div>
                  {index < keys.length - 1 && <span className="text-slate-500">,</span>}
                </div>
              ))}
            </div>
          )}
          {!isExpanded && <span className="text-slate-500 ml-2">... {keys.length} keys</span>}
          <span className="text-slate-300">{'}'}</span>
        </div>
      );
    }

    return <span className="text-slate-300">{String(value)}</span>;
  };

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 relative">
      {showCopyButton && (
        <button
          onClick={copyToClipboard}
          className="absolute top-2 right-2 px-2 py-1 text-xs bg-slate-700 hover:bg-slate-600 rounded text-slate-300"
        >
          {copied ? '✓ Copied' : '📋 Copy'}
        </button>
      )}
      <div className="font-mono text-sm overflow-x-auto">
        {renderValue(data)}
      </div>
    </div>
  );
}


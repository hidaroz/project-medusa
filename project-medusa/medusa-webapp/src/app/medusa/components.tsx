'use client';

import type { Operation, Status } from './page';

// Structured Log View - Human Readable
export function StructuredLogView({ operations, status }: { operations: Operation[]; status: Status | null }) {
  // Parse operations to extract structured data
  const parseOperations = () => {
    const phases: Record<string, Operation[]> = {};
    const findings: Array<{ type: string; description: string; severity: string }> = [];
    const services: Array<{ name: string; port: string; status: string }> = [];
    const vulnerabilities: Array<{ id: string; description: string; severity: string }> = [];
    const timeline: Operation[] = [];

    operations.forEach((op) => {
      timeline.push(op);

      // Categorize by phase
      const message = op.message.toLowerCase();
      if (message.includes('reconnaissance') || message.includes('recon')) {
        if (!phases['reconnaissance']) phases['reconnaissance'] = [];
        phases['reconnaissance'].push(op);
      } else if (message.includes('enumeration') || message.includes('enumerate')) {
        if (!phases['enumeration']) phases['enumeration'] = [];
        phases['enumeration'].push(op);
      } else if (message.includes('exploitation') || message.includes('exploit')) {
        if (!phases['exploitation']) phases['exploitation'] = [];
        phases['exploitation'].push(op);
      } else if (message.includes('vulnerability') || message.includes('vuln')) {
        if (!phases['vulnerabilities']) phases['vulnerabilities'] = [];
        phases['vulnerabilities'].push(op);

        // Extract vulnerability info
        const vulnMatch = op.message.match(/(vulnerability|vuln)[\s:]+([^,\n]+)/i);
        if (vulnMatch) {
          vulnerabilities.push({
            id: `vuln-${vulnerabilities.length + 1}`,
            description: vulnMatch[2].trim(),
            severity: op.level === 'error' ? 'high' : op.level === 'warning' ? 'medium' : 'low'
          });
        }
      } else if (message.includes('service') || message.includes('port')) {
        const portMatch = op.message.match(/port[\s:]+(\d+)/i);
        const serviceMatch = op.message.match(/(http|https|ssh|ftp|mysql|redis|ldap)/i);
        if (portMatch || serviceMatch) {
          services.push({
            name: serviceMatch ? serviceMatch[1] : 'unknown',
            port: portMatch ? portMatch[1] : 'unknown',
            status: op.level === 'success' ? 'discovered' : 'checked'
          });
        }
      }

      // Extract findings
      if (op.level === 'success' && (message.includes('found') || message.includes('discovered') || message.includes('detected'))) {
        findings.push({
          type: 'discovery',
          description: op.message,
          severity: 'info'
        });
      }
    });

    return { phases, findings, services, vulnerabilities, timeline };
  };

  const { phases, findings, services, vulnerabilities } = parseOperations();
  const isCompleted = status?.status === 'completed';
  const isRunning = status?.status === 'running';

  return (
    <div className="space-y-6">
      {/* Success Summary */}
      {isCompleted && (
        <div className="bg-green-900/20 border border-green-700 rounded-lg p-4" role="alert">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-2xl" aria-hidden="true">✅</span>
            <div>
              <h3 className="text-lg font-semibold text-green-400">Operation Completed Successfully</h3>
              <p className="text-sm text-green-300">
                {status.metrics.data_found > 0
                  ? `Found ${status.metrics.data_found} item${status.metrics.data_found !== 1 ? 's' : ''}`
                  : 'Operation completed without errors'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Progress Indicator */}
      {isRunning && (
        <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4" role="status" aria-live="polite">
          <div className="flex items-center gap-3">
            <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-400" aria-hidden="true"></div>
            <div>
              <h3 className="text-lg font-semibold text-blue-400">Operation in Progress</h3>
              <p className="text-sm text-blue-300">
                {status?.current_operation?.type || 'Running'} - {status?.current_operation?.objective || 'Processing...'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Key Findings Summary */}
      {(findings.length > 0 || vulnerabilities.length > 0 || services.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {vulnerabilities.length > 0 && (
            <div className="bg-red-900/20 border border-red-700 rounded-lg p-4">
              <h3 className="text-lg font-semibold text-red-400 mb-2">🔴 Vulnerabilities</h3>
              <p className="text-3xl font-bold text-red-300">{vulnerabilities.length}</p>
              <p className="text-sm text-red-300/70 mt-1">Security issues found</p>
            </div>
          )}

          {services.length > 0 && (
            <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4">
              <h3 className="text-lg font-semibold text-blue-400 mb-2">🌐 Services</h3>
              <p className="text-3xl font-bold text-blue-300">{services.length}</p>
              <p className="text-sm text-blue-300/70 mt-1">Services discovered</p>
            </div>
          )}

          {findings.length > 0 && (
            <div className="bg-green-900/20 border border-green-700 rounded-lg p-4">
              <h3 className="text-lg font-semibold text-green-400 mb-2">📊 Findings</h3>
              <p className="text-3xl font-bold text-green-300">{findings.length}</p>
              <p className="text-sm text-green-300/70 mt-1">Items discovered</p>
            </div>
          )}
        </div>
      )}

      {/* Vulnerabilities Section */}
      {vulnerabilities.length > 0 && (
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
          <h3 className="text-xl font-semibold mb-4 text-red-400">🔴 Security Vulnerabilities</h3>
          <div className="space-y-3" role="list">
            {vulnerabilities.map((vuln) => (
              <div
                key={vuln.id}
                className="bg-slate-800 border border-red-700/50 rounded-lg p-4"
                role="listitem"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`px-2 py-1 text-xs font-semibold rounded ${
                        vuln.severity === 'high' ? 'bg-red-600 text-white' :
                        vuln.severity === 'medium' ? 'bg-yellow-600 text-white' :
                        'bg-orange-600 text-white'
                      }`}>
                        {vuln.severity.toUpperCase()}
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

      {/* Services Discovered */}
      {services.length > 0 && (
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
          <h3 className="text-xl font-semibold mb-4 text-blue-400">🌐 Services Discovered</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3" role="list">
            {services.map((service, idx) => (
              <div
                key={idx}
                className="bg-slate-800 border border-slate-700 rounded-lg p-3"
                role="listitem"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-semibold text-white uppercase">{service.name}</span>
                  <span className={`px-2 py-1 text-xs rounded ${
                    service.status === 'discovered'
                      ? 'bg-green-600/20 text-green-400 border border-green-600/50'
                      : 'bg-slate-700 text-slate-400'
                  }`}>
                    {service.status}
                  </span>
                </div>
                <p className="text-sm text-slate-400">Port: {service.port}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Operation Phases */}
      {Object.keys(phases).length > 0 && (
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
          <h3 className="text-xl font-semibold mb-4">📋 Operation Phases</h3>
          <div className="space-y-4">
            {Object.entries(phases).map(([phaseName, phaseOps]) => (
              <div key={phaseName} className="border-l-4 border-blue-500 pl-4">
                <h4 className="font-semibold text-white mb-2 capitalize">
                  {phaseName.replace('_', ' ')}
                </h4>
                <div className="space-y-2">
                  {phaseOps.slice(-3).map((op) => (
                    <div key={op.id} className="text-sm text-slate-300">
                      <span className="text-slate-500">
                        {new Date(op.timestamp).toLocaleTimeString()}
                      </span>
                      {' • '}
                      <span>{op.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Activity Timeline */}
      <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
        <h3 className="text-xl font-semibold mb-4">🕐 Recent Activity</h3>
        <div className="space-y-2 max-h-64 overflow-y-auto" role="log" aria-live="polite">
          {operations.slice(-10).map((op) => (
            <div
              key={op.id}
              className="flex items-start gap-3 p-2 rounded hover:bg-slate-800 transition"
            >
              <div className={`w-2 h-2 rounded-full mt-2 flex-shrink-0 ${
                op.level === 'success' ? 'bg-green-500' :
                op.level === 'error' ? 'bg-red-500' :
                op.level === 'warning' ? 'bg-yellow-500' :
                'bg-blue-500'
              }`} aria-label={`${op.level} level`}></div>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-slate-300 break-words">{op.message}</p>
                <p className="text-xs text-slate-500 mt-1">
                  {op.source} • {new Date(op.timestamp).toLocaleString()}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {operations.length === 0 && (
        <div className="text-center py-12">
          <p className="text-slate-400 text-lg mb-2">No operations yet</p>
          <p className="text-slate-500 text-sm">Start an operation to see results here</p>
        </div>
      )}
    </div>
  );
}

// Raw Log View - Original format
export function RawLogView({ operations, getLevelColor }: { operations: Operation[]; getLevelColor: (level: string) => string }) {
  return (
    <div className="space-y-2 max-h-96 overflow-y-auto" role="log">
      {operations.length === 0 ? (
        <p className="text-slate-400 text-center py-8">No operations yet</p>
      ) : (
        operations.map((op) => (
          <div
            key={op.id}
            className="bg-slate-900 border border-slate-700 rounded-lg p-4"
          >
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-sm font-semibold ${getLevelColor(op.level)}`}>
                    [{op.level.toUpperCase()}]
                  </span>
                  <span className="text-sm text-slate-400">{op.source}</span>
                  <span className="text-xs text-slate-500">
                    {new Date(op.timestamp).toLocaleString()}
                  </span>
                </div>
                <p className="text-slate-200 whitespace-pre-wrap break-words">{op.message}</p>
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  );
}


export type MedusaStatus = 'idle' | 'running' | 'completed' | 'error';

export interface MedusaMetrics {
    operations_completed: number;
    data_found: number;
    time_started: string | null;
    time_completed: string | null;
    // Cost tracking (future enhancement based on plan)
    total_cost?: number;
    last_operation_cost?: number;
}

export interface MedusaOperation {
    id: string;
    type: 'assess' | 'find' | 'deploy' | 'recon_only' | 'vuln_scan' | 'full_assessment' | 'penetration_test';
    objective: string;
    started_at: string;
    status?: MedusaStatus; // Added for history tracking
    cost?: number;
    findings_count?: number;
}

export interface MedusaLogEntry {
    id: number;
    timestamp: string;
    source: string;
    level: 'info' | 'warning' | 'error' | 'success' | 'debug';
    message: string;
}

export interface SystemStatus {
    status: MedusaStatus;
    current_operation: MedusaOperation | null;
    metrics: MedusaMetrics;
    last_update: string;
}

export interface MedusaCommandResponse {
    command: string;
    stdout: string;
    stderr: string;
    returncode: number;
    error?: string;
}

export interface OperationsResponse {
    operations: MedusaLogEntry[]; // The API currently returns logs as 'operations' in get_operations. This might need adjustment if we separate logs and ops history.
    total: number;
}

export interface LogsResponse {
    logs: MedusaLogEntry[];
    total: number;
}

export interface StartOperationRequest {
    type: string;
    objective: string;
    // Additional options
    max_duration?: number;
    auto_approve?: boolean;
}

// New interfaces for Phase 5+ workflow
export interface StartOperationResponse {
    status: string;
    operation_id: string;
    thread_id: string;
    message: string;
}

export interface OperationStatusResponse {
    operation_id: string;
    thread_id: string;
    objective: string;
    operation_type: string;
    status: 'initializing' | 'running' | 'completed' | 'failed' | 'stopped' | 'WAITING_FOR_APPROVAL';
    logs: Array<{
        timestamp: string;
        level: string;
        message: string;
    }>;
    created_at: string;
    completed_at?: string;
    // Added for approval flow
    awaiting_approval?: boolean;
    next_step?: string;
    planned_exploitation?: Array<{
        target: string;
        vulnerability: string;
        technique: string;
        risk: string;
    }>;
    results?: {
        cost?: number;
        findings?: any[];
    };
}

export interface DetailedHealthResponse {
    timestamp: string;
    database: 'connected' | 'disconnected';
    active_operations_count: number;
    operations_checked: Array<{
        thread_id: string;
        operation_id: string;
        status: string;
        last_updated?: string;
        time_since_update?: number;
        is_stalled: boolean;
    }>;
    stalled_operations: Array<{
        thread_id: string;
        operation_id: string;
        last_updated?: string;
        time_since_update?: number;
        action: string;
    }>;
    status: 'OK' | 'STALLED';
    alert: boolean;
}

export interface ApprovalDecision {
    decision: 'APPROVED' | 'REJECTED';
    approver?: string;
    notes?: string;
}

export interface ApprovalResponse {
    status: string;
    message: string;
    thread_id: string;
    operation_id: string;
}

// Findings from operation results
export interface Finding {
    host: string;
    port?: number;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    type: string;
    vulnerability?: string;
    description: string;
    evidence?: string;
    remediation?: string;
    cvss_score?: number;
    discovered_at?: string;
}


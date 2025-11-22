'use client';

import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { medusaApi } from '../lib/api';
import {
    SystemStatus,
    MedusaLogEntry,
    MedusaMetrics,
    OperationStatusResponse,
    DetailedHealthResponse
} from '../types/medusa';

interface MedusaContextType {
    status: SystemStatus | null;
    logs: MedusaLogEntry[];
    metrics: MedusaMetrics | null;
    isConnected: boolean;
    lastRefreshed: Date | null;
    refresh: () => Promise<void>;
    startOperation: (type: string, objective: string) => Promise<void>;
    stopOperation: () => Promise<void>;
    executeCommand: (cmd: string) => Promise<any>;
    error: string | null;
    isLoading: boolean;

    // Phase 5+ additions
    detailedOperation: OperationStatusResponse | null;
    healthStatus: DetailedHealthResponse | null;
    zombieAlert: boolean;
    approveOperation: (notes?: string, approver?: string) => Promise<void>;
    rejectOperation: (notes?: string, approver?: string) => Promise<void>;
}

const MedusaContext = createContext<MedusaContextType | undefined>(undefined);

export function MedusaProvider({ children }: { children: React.ReactNode }) {
    const [status, setStatus] = useState<SystemStatus | null>(null);
    const [logs, setLogs] = useState<MedusaLogEntry[]>([]);
    const [metrics, setMetrics] = useState<MedusaMetrics | null>(null);
    const [isConnected, setIsConnected] = useState(false);
    const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    // Phase 5+ state
    const [detailedOperation, setDetailedOperation] = useState<OperationStatusResponse | null>(null);
    const [healthStatus, setHealthStatus] = useState<DetailedHealthResponse | null>(null);
    const [zombieAlert, setZombieAlert] = useState(false);

    const fetchData = useCallback(async () => {
        try {
            const [statusData, logsData] = await Promise.all([
                medusaApi.getStatus(),
                medusaApi.getLogs(100)
            ]);

            setStatus(statusData);
            setMetrics(statusData.metrics);
            setLogs(logsData.logs);
            setIsConnected(true);
            setLastRefreshed(new Date());
            setError(null);

            // If there's an active operation, fetch detailed status
            if (statusData.current_operation?.id) {
                try {
                    const detailedStatus = await medusaApi.getOperationStatus(
                        statusData.current_operation.id
                    );
                    setDetailedOperation(detailedStatus);
                } catch (err) {
                    console.error('Failed to fetch detailed operation status:', err);
                }
            } else {
                setDetailedOperation(null);
            }
        } catch (err) {
            console.error('Failed to fetch Medusa data:', err);
            setIsConnected(false);
            setError('Failed to connect to Medusa API');
        } finally {
            setIsLoading(false);
        }
    }, []);

    // Zombie detection polling (every 30 seconds)
    const checkHealth = useCallback(async () => {
        try {
            const health = await medusaApi.getSystemHealth();
            setHealthStatus(health);
            setZombieAlert(health.alert);

            if (health.alert) {
                console.warn('🧟 ZOMBIE AGENTS DETECTED:', health.stalled_operations);
            }
        } catch (err) {
            console.error('Failed to fetch health status:', err);
        }
    }, []);

    // Initial fetch
    useEffect(() => {
        fetchData();
        checkHealth();
    }, [fetchData, checkHealth]);

    // Polling interval (every 3 seconds for status if connected, else every 10s)
    useEffect(() => {
        const intervalTime = isConnected ? 3000 : 10000;
        const interval = setInterval(fetchData, intervalTime);
        return () => clearInterval(interval);
    }, [fetchData, isConnected]);

    // Zombie detection polling (every 30 seconds)
    useEffect(() => {
        const healthInterval = setInterval(checkHealth, 30000);
        return () => clearInterval(healthInterval);
    }, [checkHealth]);

    const startOperation = async (type: string, objective: string) => {
        try {
            await medusaApi.startOperation({ type, objective });
            await fetchData(); // Immediate refresh
        } catch (err: any) {
            throw new Error(err.message || 'Failed to start operation');
        }
    };

    const stopOperation = async () => {
        try {
            // Get current operation ID from status
            if (!status?.current_operation?.id) {
                throw new Error('No operation is currently running');
            }
            await medusaApi.stopOperation(status.current_operation.id);
            await fetchData();
        } catch (err: any) {
            throw new Error(err.message || 'Failed to stop operation');
        }
    };

    const executeCommand = async (cmd: string) => {
        return await medusaApi.executeCommand(cmd);
    };

    const approveOperation = async (notes?: string, approver?: string) => {
        try {
            if (!status?.current_operation?.id) {
                throw new Error('No operation to approve');
            }

            await medusaApi.approveOperation(
                status.current_operation.id,
                notes,
                approver
            );

            // Immediate refresh to see resumed operation
            await fetchData();
        } catch (err: any) {
            throw new Error(err.message || 'Failed to approve operation');
        }
    };

    const rejectOperation = async (notes?: string, approver?: string) => {
        try {
            if (!status?.current_operation?.id) {
                throw new Error('No operation to reject');
            }

            await medusaApi.rejectOperation(
                status.current_operation.id,
                notes,
                approver
            );

            // Immediate refresh
            await fetchData();
        } catch (err: any) {
            throw new Error(err.message || 'Failed to reject operation');
        }
    };

    const value = {
        status,
        logs,
        metrics,
        isConnected,
        lastRefreshed,
        refresh: fetchData,
        startOperation,
        stopOperation,
        executeCommand,
        error,
        isLoading,

        // Phase 5+ additions
        detailedOperation,
        healthStatus,
        zombieAlert,
        approveOperation,
        rejectOperation
    };

    return (
        <MedusaContext.Provider value={value}>
            {children}
        </MedusaContext.Provider>
    );
}

// Custom Hooks
export function useMedusa() {
    const context = useContext(MedusaContext);
    if (context === undefined) {
        throw new Error('useMedusa must be used within a MedusaProvider');
    }
    return context;
}

export function useMedusaStatus() {
    const { status, isConnected, isLoading } = useMedusa();
    return { status: status?.status || 'unknown', currentOperation: status?.current_operation, isConnected, isLoading };
}

export function useLogs() {
    const { logs } = useMedusa();
    return logs;
}

export function useMetrics() {
    const { metrics } = useMedusa();
    return metrics;
}


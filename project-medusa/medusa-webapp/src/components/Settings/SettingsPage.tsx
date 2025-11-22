import React, { useState, useEffect } from 'react';
import { Save, RefreshCw, Key, Database, Shield } from 'lucide-react';
import { medusaApi } from '../../lib/api';

export default function SettingsPage() {
    const [config, setConfig] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [message, setMessage] = useState<{ text: string, type: 'success' | 'error' } | null>(null);

    useEffect(() => {
        fetchConfig();
    }, []);

    const fetchConfig = async () => {
        try {
            setLoading(true);
            const response = await medusaApi.getConfig();
            setConfig(response.config || {});
        } catch (error) {
            console.error('Failed to fetch config:', error);
            setMessage({ text: 'Failed to load configuration', type: 'error' });
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async () => {
        try {
            setSaving(true);
            await medusaApi.updateConfig(config);
            setMessage({ text: 'Configuration saved successfully', type: 'success' });
            setTimeout(() => setMessage(null), 3000);
        } catch (error) {
            console.error('Failed to save config:', error);
            setMessage({ text: 'Failed to save configuration', type: 'error' });
        } finally {
            setSaving(false);
        }
    };

    const handleChange = (section: string, key: string, value: any) => {
        setConfig((prev: any) => ({
            ...prev,
            [section]: {
                ...prev[section],
                [key]: value
            }
        }));
    };

    if (loading) {
        return <div className="flex items-center justify-center h-full text-slate-400">Loading configuration...</div>;
    }

    return (
        <div className="h-full overflow-y-auto custom-scrollbar p-1">
            <div className="max-w-4xl mx-auto space-y-6">
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h2 className="text-2xl font-bold text-white mb-1">System Configuration</h2>
                        <p className="text-slate-400 text-sm">Manage AI providers, database connections, and security settings</p>
                    </div>
                    <button
                        onClick={handleSave}
                        disabled={saving}
                        className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                        Save Changes
                    </button>
                </div>

                {message && (
                    <div className={`p-4 rounded-lg mb-6 ${message.type === 'success' ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                        {message.text}
                    </div>
                )}

                {/* LLM Configuration */}
                <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
                    <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                        <Key className="w-5 h-5 text-cyan-400" />
                        LLM Provider Settings
                    </h3>
                    
                    <div className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label className="block text-sm font-medium text-slate-400 mb-1">Provider</label>
                                <select
                                    value={config.llm?.provider || 'anthropic'}
                                    onChange={(e) => handleChange('llm', 'provider', e.target.value)}
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:outline-none focus:border-cyan-500/50"
                                >
                                    <option value="anthropic">Anthropic (Claude)</option>
                                    <option value="openai">OpenAI (GPT-4)</option>
                                    <option value="bedrock">AWS Bedrock</option>
                                    <option value="ollama">Ollama (Local)</option>
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-slate-400 mb-1">Model</label>
                                <input
                                    type="text"
                                    value={config.llm?.model || ''}
                                    onChange={(e) => handleChange('llm', 'model', e.target.value)}
                                    placeholder="e.g., claude-3-sonnet-20240229"
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:outline-none focus:border-cyan-500/50"
                                />
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-slate-400 mb-1">API Key</label>
                            <div className="relative">
                                <input
                                    type="password"
                                    value={config.llm?.cloud_api_key || ''}
                                    onChange={(e) => handleChange('llm', 'cloud_api_key', e.target.value)}
                                    placeholder="sk-..."
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:outline-none focus:border-cyan-500/50 font-mono"
                                />
                                <p className="text-xs text-slate-500 mt-1">
                                    Keys are stored locally in your medusa config. Never share your configuration file.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Database Configuration */}
                <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
                    <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                        <Database className="w-5 h-5 text-purple-400" />
                        Database Settings
                    </h3>
                    
                    <div className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-slate-400 mb-1">Neo4j URI</label>
                            <input
                                type="text"
                                value={config.databases?.neo4j?.uri || ''}
                                onChange={(e) => handleChange('databases', 'neo4j', { ...config.databases?.neo4j, uri: e.target.value })}
                                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:outline-none focus:border-cyan-500/50 font-mono"
                            />
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                             <div>
                                <label className="block text-sm font-medium text-slate-400 mb-1">Neo4j User</label>
                                <input
                                    type="text"
                                    value={config.databases?.neo4j?.user || ''}
                                    onChange={(e) => handleChange('databases', 'neo4j', { ...config.databases?.neo4j, user: e.target.value })}
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:outline-none focus:border-cyan-500/50"
                                />
                            </div>
                             <div>
                                <label className="block text-sm font-medium text-slate-400 mb-1">Neo4j Password</label>
                                <input
                                    type="password"
                                    value={config.databases?.neo4j?.password || ''}
                                    onChange={(e) => handleChange('databases', 'neo4j', { ...config.databases?.neo4j, password: e.target.value })}
                                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-200 focus:outline-none focus:border-cyan-500/50"
                                />
                            </div>
                        </div>
                    </div>
                </div>
                
                {/* Security Settings */}
                 <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl">
                    <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                        <Shield className="w-5 h-5 text-emerald-400" />
                        Security Policy
                    </h3>
                    
                    <div className="space-y-4">
                         <div className="flex items-center justify-between p-4 bg-slate-950 rounded-lg border border-slate-800">
                            <div>
                                <h4 className="text-sm font-medium text-white">Require Authorization</h4>
                                <p className="text-xs text-slate-500">Require explicit approval for high-risk actions</p>
                            </div>
                            <div className="relative inline-block w-12 mr-2 align-middle select-none transition duration-200 ease-in">
                                <input 
                                    type="checkbox" 
                                    name="auth" 
                                    id="auth-toggle" 
                                    checked={config.safety?.require_authorization || false}
                                    onChange={(e) => handleChange('safety', 'require_authorization', e.target.checked)}
                                    className="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-4 appearance-none cursor-pointer"/>
                                <label htmlFor="auth-toggle" className={`toggle-label block overflow-hidden h-6 rounded-full cursor-pointer ${config.safety?.require_authorization ? 'bg-cyan-600' : 'bg-slate-700'}`}></label>
                            </div>
                        </div>

                        <div className="flex items-center justify-between p-4 bg-slate-950 rounded-lg border border-slate-800">
                            <div>
                                <h4 className="text-sm font-medium text-white">Auto Rollback</h4>
                                <p className="text-xs text-slate-500">Automatically revert changes on failure</p>
                            </div>
                             <div className="relative inline-block w-12 mr-2 align-middle select-none transition duration-200 ease-in">
                                <input 
                                    type="checkbox" 
                                    name="rollback" 
                                    id="rollback-toggle" 
                                    checked={config.safety?.auto_rollback || false}
                                    onChange={(e) => handleChange('safety', 'auto_rollback', e.target.checked)}
                                    className="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-4 appearance-none cursor-pointer"/>
                                <label htmlFor="rollback-toggle" className={`toggle-label block overflow-hidden h-6 rounded-full cursor-pointer ${config.safety?.auto_rollback ? 'bg-cyan-600' : 'bg-slate-700'}`}></label>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
}


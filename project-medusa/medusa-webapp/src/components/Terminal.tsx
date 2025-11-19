import React, { useState, useRef, useEffect } from 'react';
import { Terminal as TerminalIcon, X, Maximize2, Minus, Send } from 'lucide-react';
import clsx from 'clsx';

interface TerminalProps {
  apiUrl: string;
}

interface CommandHistory {
  type: 'input' | 'output' | 'error';
  content: string;
  timestamp: string;
}

export default function Terminal({ apiUrl }: TerminalProps) {
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<CommandHistory[]>([
    { type: 'output', content: 'Medusa Security Framework v1.0.0\nInitializing command interface...\nConnected to local agent system.\nType "help" for available commands.', timestamp: new Date().toLocaleTimeString() }
  ]);
  const [isProcessing, setIsProcessing] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [history]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleCommand = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isProcessing) return;

    const cmd = input.trim();
    setInput('');
    setIsProcessing(true);
    
    // Add command to history
    setHistory(prev => [...prev, { type: 'input', content: cmd, timestamp: new Date().toLocaleTimeString() }]);

    try {
        // Simulate clear command locally
        if (cmd === 'clear') {
            setHistory([]);
            setIsProcessing(false);
            return;
        }

      const response = await fetch(`${apiUrl}/api/command`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: cmd }),
      });

      const data = await response.json();

      if (response.ok) {
        if (data.stdout) {
            setHistory(prev => [...prev, { type: 'output', content: data.stdout, timestamp: new Date().toLocaleTimeString() }]);
        }
        if (data.stderr) {
             setHistory(prev => [...prev, { type: 'error', content: data.stderr, timestamp: new Date().toLocaleTimeString() }]);
        }
        if (!data.stdout && !data.stderr) {
             setHistory(prev => [...prev, { type: 'output', content: 'Command executed successfully (no output)', timestamp: new Date().toLocaleTimeString() }]);
        }
      } else {
        setHistory(prev => [...prev, { type: 'error', content: data.error || 'Unknown error', timestamp: new Date().toLocaleTimeString() }]);
      }
    } catch (error) {
      setHistory(prev => [...prev, { type: 'error', content: 'Failed to connect to server', timestamp: new Date().toLocaleTimeString() }]);
    } finally {
      setIsProcessing(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-950 rounded-xl overflow-hidden border border-slate-800 shadow-2xl font-mono text-sm relative">
      {/* Terminal Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-slate-900 border-b border-slate-800">
        <div className="flex items-center gap-2">
            <TerminalIcon className="w-4 h-4 text-slate-400" />
            <span className="text-slate-400 font-medium">user@medusa-ops:~</span>
        </div>
        <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-slate-700 hover:bg-yellow-500 transition-colors cursor-pointer" />
            <div className="w-3 h-3 rounded-full bg-slate-700 hover:bg-green-500 transition-colors cursor-pointer" />
            <div className="w-3 h-3 rounded-full bg-slate-700 hover:bg-red-500 transition-colors cursor-pointer" />
        </div>
      </div>

      {/* Terminal Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2 custom-scrollbar" onClick={() => inputRef.current?.focus()}>
        {history.map((entry, i) => (
            <div key={i} className={clsx(
                "flex gap-2",
                entry.type === 'error' ? 'text-red-400' : 
                entry.type === 'input' ? 'text-cyan-300' : 'text-slate-300'
            )}>
                <span className="text-slate-600 select-none shrink-0">[{entry.timestamp}]</span>
                <div className="whitespace-pre-wrap break-all">
                    {entry.type === 'input' && <span className="text-green-400 mr-2">➜</span>}
                    {entry.content}
                </div>
            </div>
        ))}
        
        {isProcessing && (
            <div className="flex gap-2 text-slate-400 animate-pulse">
                <span>Processing command...</span>
            </div>
        )}
        
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <form onSubmit={handleCommand} className="p-2 bg-slate-900 border-t border-slate-800 flex items-center gap-2">
        <span className="text-green-400 font-bold px-2">➜</span>
        <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="flex-1 bg-transparent border-none outline-none text-cyan-100 placeholder-slate-600 font-mono"
            placeholder="Enter command..."
            spellCheck={false}
            autoComplete="off"
            disabled={isProcessing}
        />
      </form>
    </div>
  );
}


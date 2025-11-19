#!/usr/bin/env python3
"""
Medusa API Server - REST API for Medusa CLI Operations
Exposes Medusa functionality via HTTP for web dashboard
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import os
import subprocess
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import shlex
from pathlib import Path

app = Flask(__name__)
CORS(app)  # Enable CORS for Next.js frontend

# Global state
medusa_state = {
    'status': 'idle',  # idle, running, completed, error
    'current_operation': None,
    'operations_log': [],
    'metrics': {
        'operations_completed': 0,
        'data_found': 0,
        'time_started': None,
        'time_completed': None
    }
}

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'service': 'Medusa API Server',
        'version': '0.1.0-alpha',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get current Medusa system status"""
    return jsonify({
        'status': medusa_state['status'],
        'current_operation': medusa_state['current_operation'],
        'metrics': medusa_state['metrics'],
        'last_update': datetime.now().isoformat()
    })

@app.route('/api/operations', methods=['GET'])
def get_operations():
    """Get list of all operations/logs"""
    return jsonify({
        'operations': medusa_state['operations_log'][-50:],  # Last 50 operations
        'total': len(medusa_state['operations_log'])
    })

@app.route('/api/operations', methods=['POST'])
def create_operation():
    """Start a new Medusa operation"""
    data = request.json
    objective = data.get('objective', '')
    operation_type = data.get('type', 'assess')  # assess, find, deploy
    
    if medusa_state['status'] == 'running':
        return jsonify({
            'error': 'Operation already in progress',
            'current_status': medusa_state['status']
        }), 400
    
    # Start operation in background thread
    thread = threading.Thread(
        target=run_medusa_operation,
        args=(operation_type, objective),
        daemon=True
    )
    thread.start()
    
    operation_id = f"op_{int(time.time())}"
    medusa_state['current_operation'] = {
        'id': operation_id,
        'type': operation_type,
        'objective': objective,
        'started_at': datetime.now().isoformat()
    }
    medusa_state['status'] = 'running'
    medusa_state['metrics']['time_started'] = datetime.now().isoformat()
    
    return jsonify({
        'operation_id': operation_id,
        'status': 'started',
        'message': f'{operation_type} operation initiated'
    }), 201

@app.route('/api/operations/stop', methods=['POST'])
def stop_operation():
    """Stop current operation"""
    if medusa_state['status'] != 'running':
        return jsonify({
            'error': 'No operation in progress'
        }), 400
    
    medusa_state['status'] = 'idle'
    medusa_state['current_operation'] = None
    medusa_state['metrics']['time_completed'] = datetime.now().isoformat()
    
    add_log_entry('system', 'Operation stopped by user', 'info')
    
    return jsonify({
        'status': 'stopped',
        'message': 'Operation stopped successfully'
    })

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Get operation metrics"""
    return jsonify(medusa_state['metrics'])

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get operation logs"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify({
        'logs': medusa_state['operations_log'][-limit:],
        'total': len(medusa_state['operations_log'])
    })

def add_log_entry(source: str, message: str, level: str = 'info'):
    """Add entry to operations log"""
    entry = {
        'id': len(medusa_state['operations_log']),
        'timestamp': datetime.now().isoformat(),
        'source': source,
        'level': level,
        'message': message
    }
    medusa_state['operations_log'].append(entry)
    # Keep only last 1000 entries
    if len(medusa_state['operations_log']) > 1000:
        medusa_state['operations_log'] = medusa_state['operations_log'][-1000:]

def run_medusa_operation(operation_type: str, objective: str):
    """Run Medusa operation in background"""
    try:
        add_log_entry('medusa', f'Starting {operation_type} operation: {objective}', 'info')
        
        if operation_type == 'assess':
            # Run assessment (using multi-agent system)
            # objective is treated as the target
            cmd = ['medusa', 'agent', 'run', objective, '--type', 'full_assessment', '--max-duration', '86400', '--save', '--auto-approve']
            add_log_entry('system', f'Executing: medusa agent run {objective} --type full_assessment', 'info')
            
        elif operation_type == 'find':
            # Run reconnaissance (using multi-agent system)
            cmd = ['medusa', 'agent', 'run', objective, '--type', 'recon_only', '--max-duration', '3600', '--save', '--auto-approve']
            add_log_entry('system', f'Executing: medusa agent run {objective} --type recon_only', 'info')
            
        elif operation_type == 'deploy':
            # Run exploitation/deployment (using multi-agent system)
            cmd = ['medusa', 'agent', 'run', objective, '--type', 'penetration_test', '--max-duration', '86400', '--save', '--auto-approve']
            add_log_entry('system', f'Executing: medusa agent run {objective} --type penetration_test', 'info')
        
        else:
            add_log_entry('system', f'Unknown operation type: {operation_type}', 'error')
            medusa_state['status'] = 'error'
            return
        
        # Execute command
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Read output in real-time (simplified for now)
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            add_log_entry('medusa', 'Operation completed successfully', 'success')
            add_log_entry('medusa', f'Output: {stdout[:500]}...', 'info') # Log first 500 chars
            medusa_state['status'] = 'completed'
            medusa_state['metrics']['operations_completed'] += 1
            medusa_state['metrics']['time_completed'] = datetime.now().isoformat()
        else:
            add_log_entry('medusa', f'Operation failed with code {process.returncode}', 'error')
            add_log_entry('medusa', f'Error: {stderr}', 'error')
            medusa_state['status'] = 'error'
            medusa_state['current_operation'] = None
        
    except Exception as e:
        add_log_entry('system', f'Error: {str(e)}', 'error')
        medusa_state['status'] = 'error'
        medusa_state['current_operation'] = None

@app.route('/api/command', methods=['POST'])
def execute_command():
    """Execute a raw CLI command"""
    data = request.json
    command_str = data.get('command', '').strip()
    
    if not command_str:
        return jsonify({'error': 'No command provided'}), 400
        
    # basic security check - only allow medusa commands or specific safe system commands
    if not (command_str.startswith('medusa') or command_str in ['help', 'ls', 'pwd', 'whoami', 'clear']):
        return jsonify({'error': 'Command not allowed. Only "medusa" commands are permitted.'}), 403
        
    try:
        # Split command into list for subprocess
        cmd_args = shlex.split(command_str)
        
        # Run command
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            timeout=30 # timeout to prevent hanging
        )
        
        return jsonify({
            'command': command_str,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Initialize with welcome message
    add_log_entry('system', 'Medusa API Server started', 'info')
    
    # Run Flask server
    # Using port 5000 as default for production
    # Respect PORT env var for Render/Heroku compatibility
    port = int(os.getenv('PORT', os.getenv('MEDUSA_API_PORT', '5000')))
    print(f"Starting Medusa API Server on http://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)


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
from pathlib import Path
import sys
import httpx

# Add medusa-cli to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from src.medusa.core.feedback import get_feedback_tracker
from src.medusa.feedback_analyzer import FeedbackAnalyzer
from src.medusa.config import Config
from src.medusa.core.llm.factory import create_llm_provider
from src.medusa.core.llm.config import LLMConfig
import asyncio
from src.medusa.core.llm.factory import create_llm_provider
from src.medusa.core.llm.config import LLMConfig

app = Flask(__name__)
CORS(app)  # Enable CORS for Next.js frontend

# Global state
medusa_state = {
    'status': 'idle',  # idle, running, completed, error
    'current_operation': None,
    'operations_log': [],
    'discovered_data': {
        'vulnerabilities': [],
        'services': [],
        'endpoints': [],
        'credentials': [],
        'data_records': []
    },
    'operation_history': [],  # Store historical operation data for trends
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
    # Reset error status to idle if no current operation
    if medusa_state['status'] == 'error' and medusa_state['current_operation'] is None:
        medusa_state['status'] = 'idle'

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
    operation_type = data.get('type', 'find')  # Only 'find' is supported

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

@app.route('/api/learning/metrics', methods=['GET'])
def get_learning_metrics():
    """Get continuous learning metrics"""
    try:
        feedback = get_feedback_tracker()
        metrics = feedback.get_metrics()
        return jsonify(metrics)
    except Exception as e:
        return jsonify({
            'error': str(e),
            'technique_success_rates': {},
            'improvement_trend': 'unknown',
            'total_operations': 0,
            'avg_vulnerabilities_per_run': 0.0,
            'avg_time_to_first_vuln': 0.0,
            'learned_techniques': [],
            'best_attack_paths': []
        }), 500

@app.route('/api/learning/techniques', methods=['GET'])
def get_learned_techniques():
    """Get techniques with success rates"""
    try:
        feedback = get_feedback_tracker()
        successful = feedback.get_successful_techniques(min_success_rate=0.5)
        failed = feedback.get_failed_techniques()
        return jsonify({
            'successful_techniques': successful,
            'failed_techniques': failed,
            'working_credentials': feedback.get_working_credentials()[:10]  # Top 10
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'successful_techniques': [],
            'failed_techniques': [],
            'working_credentials': []
        }), 500

@app.route('/api/learning/summary', methods=['GET'])
def get_learning_summary():
    """Get learning progress summary"""
    try:
        analyzer = FeedbackAnalyzer()
        summary = analyzer.get_improvement_summary()
        return jsonify(summary)
    except Exception as e:
        return jsonify({
            'error': str(e),
            'total_operations': 0,
            'improvement_trend': 'unknown'
        }), 500

@app.route('/api/learning/insights', methods=['GET'])
def get_learning_insights():
    """Get AI-generated learning insights and recommendations"""
    try:
        from medusa.core.strategy_selector import StrategySelector
        from medusa.core.objective_parser import ObjectiveParser

        feedback = get_feedback_tracker()
        selector = StrategySelector()
        parser = ObjectiveParser()

        # Get recommended techniques (general)
        general_recommendations = selector.select_techniques(None, limit=5)
        recommended_techniques = [
            {
                'technique_id': rec.technique_id,
                'technique_name': rec.technique_name,
                'success_rate': rec.success_rate,
                'usage_count': rec.usage_count,
                'recommendation': rec.reason,
                'confidence': rec.confidence
            }
            for rec in general_recommendations
        ]

        # Get extraction method recommendations
        extraction_recommendations = []
        for data_type in ['medical_record', 'credential', 'vulnerability']:
            method, confidence = selector.get_extraction_method_recommendation(data_type)
            extraction_feedback = feedback.get_extraction_feedback()
            type_feedback = extraction_feedback.get(data_type, {})
            method_stats = type_feedback.get(method, {})

            total = method_stats.get('success_count', 0) + method_stats.get('failure_count', 0)
            success_rate = method_stats.get('success_count', 0) / total if total > 0 else 0.5

            extraction_recommendations.append({
                'data_type': data_type,
                'best_method': method,
                'success_rate': success_rate,
                'recommendation': f"Use {method.upper()} for {data_type.replace('_', ' ')} extraction (confidence: {confidence:.0%})"
            })

        # Get objective-specific insights
        objective_specific_insights = {}
        for objective_text in ['find password', 'find medical records', 'find vulnerabilities']:
            strategy = parser.parse(objective_text)
            recommendations = selector.select_techniques(strategy, limit=3)
            if recommendations:
                objective_specific_insights[objective_text] = [
                    {
                        'technique_id': rec.technique_id,
                        'technique_name': rec.technique_name,
                        'success_rate': rec.success_rate,
                        'usage_count': rec.usage_count,
                        'recommendation': rec.reason,
                        'confidence': rec.confidence
                    }
                    for rec in recommendations
                ]

        metrics = feedback.get_metrics()

        return jsonify({
            'recommended_techniques': recommended_techniques,
            'extraction_recommendations': extraction_recommendations,
            'objective_specific_insights': objective_specific_insights,
            'improvement_trend': metrics.get('improvement_trend', 'stable'),
            'total_operations': metrics.get('total_operations', 0)
        })
    except Exception as e:
        logger.error(f"Failed to get learning insights: {e}")
        return jsonify({
            'error': str(e),
            'recommended_techniques': [],
            'extraction_recommendations': [],
            'objective_specific_insights': {},
            'improvement_trend': 'stable',
            'total_operations': 0
        }), 500

@app.route('/api/learning/trends', methods=['GET'])
def get_learning_trends():
    """Get historical trend data for continuous learning visualization

    Returns operation history formatted for charts and graphs.
    This is what powers the learning dashboard visualization.
    """
    try:
        # Get operation history from state
        operation_history = medusa_state.get('operation_history', [])

        if not operation_history:
            return jsonify({
                'vulnerabilities_over_time': [],
                'data_items_over_time': [],
                'extraction_quality_over_time': [],
                'success_rate_over_time': [],
                'technique_effectiveness': {},
                'operations_timeline': []
            })

        # Format data for charts - focus on data discovery metrics
        data_items_over_time = []
        extraction_quality_over_time = []
        operations_timeline = []

        # Calculate cumulative totals for better visualization
        cumulative_data_items = 0

        for idx, op in enumerate(operation_history, start=1):
            # Data items found over time - use CUMULATIVE total for better visualization
            # This shows the total data available at each point, not just new items
            incremental = op.get('data_items_found', op.get('vulnerabilities_found', 0))
            cumulative_data_items += incremental

            # Use cumulative total, but if it's 0 and we have incremental, use that
            data_items_value = cumulative_data_items if cumulative_data_items > 0 else incremental

            data_items_over_time.append({
                'x': idx,
                'y': data_items_value,
                'timestamp': op.get('timestamp', '')
            })

            # Extraction quality over time (structured data vs raw data)
            # Use the structured_data_percentage from the operation record
            # This should be calculated based on ALL records, not just new ones
            structured_percentage = op.get('structured_data_percentage', 0.0)

            # If percentage is still 0, try to calculate from available data
            if structured_percentage == 0.0:
                structured_count = op.get('structured_data_count', 0)
                total_data_records = op.get('total_data_records', 0)

                # If we have total_data_records, use that
                if total_data_records > 0:
                    structured_percentage = (structured_count / total_data_records * 100)
                else:
                    # Fallback: use data_items_found as proxy for total records
                    total_data = op.get('data_items_found_total', op.get('data_items_found', 0))
                    if total_data > 0 and structured_count > 0:
                        structured_percentage = (structured_count / total_data * 100)
                    # If still 0, check if we have any structured data at all
                    elif structured_count > 0:
                        # At least some data is structured
                        structured_percentage = 50.0  # Estimate if we have structured count but no total

            extraction_quality_over_time.append({
                'x': idx,
                'y': max(0.0, min(100.0, structured_percentage)),  # Clamp between 0-100
                'timestamp': op.get('timestamp', '')
            })

            # Operations timeline
            operations_timeline.append({
                'operation_id': idx,
                'timestamp': op.get('timestamp', ''),
                'vulnerabilities_found': op.get('vulnerabilities_found', 0),
                'data_items_found': op.get('data_items_found', 0),
                'structured_data_count': op.get('structured_data_count', 0),
                'structured_data_percentage': op.get('structured_data_percentage', 0.0),
                'success': op.get('success', False),
                'duration': op.get('duration', 0),
                'objective': op.get('objective', ''),
                'technique_id': op.get('technique_id', '')
            })

        # Calculate technique effectiveness from actual operation history (realistic learning)
        technique_effectiveness = {}
        technique_stats = {}

        # Count successes and failures per technique from operation history
        for op in operation_history:
            tech_id = op.get('technique_id', '')
            if not tech_id:
                continue

            if tech_id not in technique_stats:
                technique_stats[tech_id] = {'success': 0, 'total': 0, 'last_used': op.get('timestamp', '')}

            technique_stats[tech_id]['total'] += 1
            if op.get('success', False):
                technique_stats[tech_id]['success'] += 1
            technique_stats[tech_id]['last_used'] = max(technique_stats[tech_id]['last_used'], op.get('timestamp', ''))

        # Calculate success rates and build effectiveness data
        for tech_id, stats in technique_stats.items():
            success_rate = stats['success'] / stats['total'] if stats['total'] > 0 else 0.0
            technique_effectiveness[tech_id] = {
                'success_rate': success_rate,
                'usage_count': stats['total'],
                'last_used': stats['last_used'] if stats['last_used'] else None
            }

        # Also try to get from feedback tracker (for real operations)
        try:
            feedback = get_feedback_tracker()
            metrics = feedback.get_metrics()

            # Merge with feedback tracker data (real operations take precedence)
            for tech_id, success_rate in metrics.get('technique_success_rates', {}).items():
                if tech_id not in technique_effectiveness:  # Only add if not already calculated
                    tech_data = feedback.data.get('techniques', {}).get(tech_id, {})
                    technique_effectiveness[tech_id] = {
                        'success_rate': success_rate,
                        'usage_count': tech_data.get('success_count', 0) + tech_data.get('failure_count', 0),
                        'last_used': tech_data.get('last_success') or tech_data.get('last_failure')
                    }
        except Exception as e:
            add_log_entry('system', f'Failed to get technique effectiveness from feedback: {e}', 'warning')

        return jsonify({
            'vulnerabilities_over_time': data_items_over_time,  # Keep name for backward compatibility
            'data_items_over_time': data_items_over_time,  # New: data items found
            'extraction_quality_over_time': extraction_quality_over_time,  # New: extraction quality
            'success_rate_over_time': extraction_quality_over_time,  # Reuse quality as "success" metric
            'technique_effectiveness': technique_effectiveness,
            'operations_timeline': operations_timeline
        })
    except Exception as e:
        add_log_entry('system', f'Error generating learning trends: {e}', 'error')
        return jsonify({
            'error': str(e),
            'vulnerabilities_over_time': [],
            'data_items_over_time': [],
            'extraction_quality_over_time': [],
            'success_rate_over_time': [],
            'technique_effectiveness': {},
            'operations_timeline': []
        }), 500

@app.route('/api/data/discovered', methods=['GET'])
def get_discovered_data():
    """Get all discovered data from current and past operations

    Note: Objective-based filtering is now handled at CLI execution time.
    This endpoint returns all data that was collected (already filtered by CLI).
    """
    try:
        # Only extract from logs if there's been at least one completed operation
        if medusa_state['metrics']['operations_completed'] > 0:
            _extract_data_from_recent_logs()
            # Query discovered API endpoints to fetch actual patient data
            _query_api_endpoints_for_data()

        # Get all discovered data (already filtered by CLI based on objective)
        all_vulnerabilities = medusa_state['discovered_data']['vulnerabilities']
        all_services = medusa_state['discovered_data']['services']
        all_endpoints = medusa_state['discovered_data']['endpoints']
        all_credentials = medusa_state['discovered_data']['credentials']
        all_data_records = medusa_state['discovered_data']['data_records']

        # Return all data (CLI already filtered based on objective during execution)
        return jsonify({
            'vulnerabilities': all_vulnerabilities,
            'services': all_services,
            'endpoints': all_endpoints,
            'credentials': all_credentials,
            'data_records': all_data_records,
            'total_items': (
                len(all_vulnerabilities) +
                len(all_services) +
                len(all_endpoints) +
                len(all_credentials) +
                len(all_data_records)
            ),
            'has_operations': medusa_state['metrics']['operations_completed'] > 0
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'vulnerabilities': [],
            'services': [],
            'endpoints': [],
            'credentials': [],
            'data_records': [],
            'total_items': 0,
            'has_operations': False
        }), 500

@app.route('/api/reset', methods=['POST'])
def reset_data():
    """Reset all operation history, discovered data, and metrics

    This clears:
    - Operation history (trends data)
    - Discovered data (vulnerabilities, services, endpoints, credentials, data records)
    - Operations log
    - Metrics

    Optionally clears persistent feedback data if requested.
    """
    try:
        data = request.json or {}
        clear_feedback = data.get('clear_feedback', False)

        # Clear in-memory state
        medusa_state['operation_history'] = []
        medusa_state['discovered_data'] = {
            'vulnerabilities': [],
            'services': [],
            'endpoints': [],
            'credentials': [],
            'data_records': []
        }
        medusa_state['operations_log'] = []
        medusa_state['metrics'] = {
            'operations_completed': 0,
            'data_found': 0,
            'time_started': None,
            'time_completed': None
        }

        # Optionally clear persistent feedback data
        if clear_feedback:
            try:
                feedback = get_feedback_tracker()
                # Clear feedback file
                feedback_file = Path.home() / ".medusa" / "feedback.json"
                if feedback_file.exists():
                    feedback_file.unlink()
                    add_log_entry('system', 'Cleared persistent feedback data', 'info')
                # Reset feedback tracker
                feedback.data = {
                    "techniques": {},
                    "credentials": [],
                    "attack_paths": {},
                    "metrics": {
                        "total_operations": 0,
                        "avg_vulnerabilities_per_run": 0.0,
                        "avg_time_to_first_vuln": 0.0,
                        "improvement_trend": "stable"
                    },
                    "last_updated": None
                }
                feedback._save()
            except Exception as e:
                add_log_entry('system', f'Failed to clear feedback data: {e}', 'warning')

        add_log_entry('system', 'All operation data and history reset', 'info')

        return jsonify({
            'success': True,
            'message': 'All data reset successfully',
            'feedback_cleared': clear_feedback
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/data/export', methods=['GET'])
def export_discovered_data():
    """Export all discovered data as a single consolidated JSON file"""
    try:
        consolidated_data = {
            'export_timestamp': datetime.now().isoformat(),
            'total_operations': medusa_state['metrics']['operations_completed'],
            'summary': {
                'vulnerabilities_count': len(medusa_state['discovered_data']['vulnerabilities']),
                'services_count': len(medusa_state['discovered_data']['services']),
                'endpoints_count': len(medusa_state['discovered_data']['endpoints']),
                'credentials_count': len(medusa_state['discovered_data']['credentials']),
                'data_records_count': len(medusa_state['discovered_data']['data_records'])
            },
            'vulnerabilities': medusa_state['discovered_data']['vulnerabilities'],
            'services': medusa_state['discovered_data']['services'],
            'endpoints': medusa_state['discovered_data']['endpoints'],
            'credentials': medusa_state['discovered_data']['credentials'],
            'data_records': medusa_state['discovered_data']['data_records']
        }

        return jsonify(consolidated_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def _query_api_endpoints_for_data():
    """Query discovered API endpoints to fetch actual patient data"""
    try:
        import httpx
        import asyncio

        # Get discovered endpoints
        endpoints = medusa_state['discovered_data'].get('endpoints', [])
        if not endpoints:
            return

        # Common API endpoints to query for patient data
        api_paths = ['/api/patients', '/api/employees', '/api/users', '/api/records']

        for endpoint_obj in endpoints:
            base_url = endpoint_obj.get('url', '')
            if not base_url:
                continue

            # Try each API path
            for path in api_paths:
                try:
                    full_url = base_url.rstrip('/') + path

                    # Make synchronous request (we're in a sync context)
                    with httpx.Client(timeout=5.0, follow_redirects=True) as client:
                        response = client.get(full_url)

                        if response.status_code == 200:
                            try:
                                data = response.json()

                                # Check if it's patient data
                                if isinstance(data, dict):
                                    # Check for patient-like structure
                                    if 'data' in data and isinstance(data['data'], list):
                                        patients = data['data']
                                    elif isinstance(data, list):
                                        patients = data
                                    else:
                                        patients = [data]

                                    # Extract patient records
                                    for patient in patients[:10]:  # Limit to 10 per endpoint
                                        if isinstance(patient, dict):
                                            # Create a patient record
                                            record = {
                                                'type': 'medical_record',
                                                'raw_data': json.dumps(patient, indent=2),
                                                'structured_data': patient,
                                                'discovered_at': datetime.now().isoformat(),
                                                'source': f'api_endpoint:{full_url}',
                                                'endpoint': full_url
                                            }

                                            # Check for duplicates based on patient ID or key fields
                                            is_duplicate = False
                                            for existing in medusa_state['discovered_data']['data_records']:
                                                if existing.get('source', '').startswith('api_endpoint:'):
                                                    existing_data = existing.get('structured_data', {})
                                                    if isinstance(existing_data, dict) and isinstance(patient, dict):
                                                        # Compare by ID or key fields
                                                        if existing_data.get('id') == patient.get('id'):
                                                            is_duplicate = True
                                                            break
                                                        if (existing_data.get('ssn') and patient.get('ssn') and
                                                            existing_data.get('ssn') == patient.get('ssn')):
                                                            is_duplicate = True
                                                            break

                                            if not is_duplicate:
                                                medusa_state['discovered_data']['data_records'].append(record)
                                                add_log_entry('system', f'Extracted patient data from {full_url}', 'info')

                            except json.JSONDecodeError:
                                # Not JSON, skip
                                pass

                except Exception as e:
                    # Skip failed requests
                    pass

    except Exception as e:
        add_log_entry('system', f'Error querying API endpoints: {e}', 'warning')

def _query_api_endpoints_for_data():
    """Query discovered API endpoints to fetch actual patient data"""
    try:
        # Get discovered endpoints
        endpoints = medusa_state['discovered_data'].get('endpoints', [])
        if not endpoints:
            return

        # Common API endpoints to query for patient data
        api_paths = ['/api/patients', '/api/employees', '/api/users', '/api/records']

        for endpoint_obj in endpoints:
            base_url = endpoint_obj.get('url', '')
            if not base_url:
                continue

            # Try each API path
            for path in api_paths:
                try:
                    full_url = base_url.rstrip('/') + path

                    # Make synchronous request (we're in a sync context)
                    with httpx.Client(timeout=5.0, follow_redirects=True) as client:
                        response = client.get(full_url)

                        if response.status_code == 200:
                            try:
                                data = response.json()

                                # Check if it's patient data
                                if isinstance(data, dict):
                                    # Check for patient-like structure
                                    if 'data' in data and isinstance(data['data'], list):
                                        patients = data['data']
                                    elif isinstance(data, list):
                                        patients = data
                                    else:
                                        patients = [data]

                                    # Extract patient records (limit to avoid duplicates)
                                    for patient in patients[:10]:  # Limit to 10 per endpoint
                                        if isinstance(patient, dict):
                                            # Create a patient record
                                            record = {
                                                'type': 'medical_record',
                                                'raw_data': json.dumps(patient, indent=2),
                                                'structured_data': patient,
                                                'discovered_at': datetime.now().isoformat(),
                                                'source': f'api_endpoint:{full_url}',
                                                'endpoint': full_url
                                            }

                                            # Check for duplicates based on patient ID or key fields
                                            is_duplicate = False
                                            for existing in medusa_state['discovered_data']['data_records']:
                                                if existing.get('source', '').startswith('api_endpoint:'):
                                                    existing_data = existing.get('structured_data', {})
                                                    if isinstance(existing_data, dict) and isinstance(patient, dict):
                                                        # Compare by ID or key fields
                                                        if existing_data.get('id') == patient.get('id'):
                                                            is_duplicate = True
                                                            break
                                                        if (existing_data.get('ssn') and patient.get('ssn') and
                                                            existing_data.get('ssn') == patient.get('ssn')):
                                                            is_duplicate = True
                                                            break

                                            if not is_duplicate:
                                                medusa_state['discovered_data']['data_records'].append(record)
                                                add_log_entry('system', f'Extracted patient data from {full_url}', 'info')

                            except json.JSONDecodeError:
                                # Not JSON, skip
                                pass

                except Exception as e:
                    # Skip failed requests silently
                    pass

    except Exception as e:
        add_log_entry('system', f'Error querying API endpoints: {e}', 'warning')

def _extract_data_from_recent_logs():
    """Extract medical records from recent log/report files"""
    try:
        config = Config()
        if not config.exists():
            return

        config_data = config.load()
        logs_dir = config.logs_dir if hasattr(config, 'logs_dir') else Path.home() / '.medusa' / 'logs'
        reports_dir = config.reports_dir if hasattr(config, 'reports_dir') else Path.home() / '.medusa' / 'reports'

        # Check recent log files
        if logs_dir.exists():
            log_files = sorted(logs_dir.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:5]
            for log_file in log_files:
                try:
                    with open(log_file) as f:
                        log_data = json.load(f)

                    # Extract findings from log
                    operation = log_data.get('operation', {})
                    findings = operation.get('findings', [])

                    for finding in findings:
                        if 'patient' in str(finding).lower() or 'medical' in str(finding).lower():
                            record = {
                                'type': 'medical_record',
                                'raw_data': json.dumps(finding, indent=2),
                                'structured_data': finding if isinstance(finding, dict) else None,
                                'discovered_at': log_data.get('metadata', {}).get('timestamp', datetime.now().isoformat()),
                                'source': f'log_file:{log_file.name}'
                            }
                            # Avoid duplicates
                            if not any(r.get('raw_data') == record['raw_data'] for r in medusa_state['discovered_data']['data_records']):
                                medusa_state['discovered_data']['data_records'].append(record)
                except:
                    pass

        # Check recent report files
        if reports_dir.exists():
            report_files = sorted(reports_dir.glob('*.html'), key=lambda p: p.stat().st_mtime, reverse=True)[:3]
            for report_file in report_files:
                try:
                    content = report_file.read_text()
                    # Look for patient/medical data in HTML
                    if 'patient' in content.lower() or 'medical' in content.lower():
                        # Extract text content (basic extraction)
                        import re
                        text_content = re.sub(r'<[^>]+>', ' ', content)
                        if len(text_content) > 100:
                            record = {
                                'type': 'medical_record',
                                'raw_data': text_content[:2000],  # First 2000 chars
                                'file_path': str(report_file),
                                'discovered_at': datetime.fromtimestamp(report_file.stat().st_mtime).isoformat(),
                                'source': f'report_file:{report_file.name}'
                            }
                            if not any(r.get('file_path') == record['file_path'] for r in medusa_state['discovered_data']['data_records']):
                                medusa_state['discovered_data']['data_records'].append(record)
                except:
                    pass
    except Exception as e:
        # Silently fail - this is supplementary data extraction
        pass

# Duplicate endpoint removed - using the implementation at line 209

@app.route('/api/config/llm', methods=['GET'])
def get_llm_config():
    """Get current LLM configuration"""
    try:
        config = Config()
        if not config.exists():
            return jsonify({
                'provider': 'auto',
                'local_model': 'mistral:7b-instruct',
                'cloud_model': 'gemini-1.5-flash-latest',
                'api_key_configured': False,
                'ollama_url': 'http://localhost:11434'
            })

        config_data = config.load()
        llm_config = config.get_llm_config()

        return jsonify({
            'provider': llm_config.get('provider', 'auto'),
            'local_model': llm_config.get('local_model', 'mistral:7b-instruct'),
            'cloud_model': llm_config.get('cloud_model', 'gemini-1.5-flash-latest'),
            'api_key_configured': bool(config_data.get('api_key') or llm_config.get('cloud_api_key')),
            'api_key_preview': _mask_api_key(config_data.get('api_key', '') or llm_config.get('cloud_api_key', '')),
            'ollama_url': llm_config.get('ollama_url', 'http://localhost:11434'),
            'temperature': llm_config.get('temperature', 0.7),
            'max_tokens': llm_config.get('max_tokens', 2048),
            'timeout': llm_config.get('timeout', 60)
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'provider': 'auto',
            'api_key_configured': False
        }), 500

@app.route('/api/config/llm', methods=['POST'])
def update_llm_config():
    """Update LLM configuration"""
    try:
        data = request.json
        config = Config()

        # Ensure config exists
        if not config.exists():
            config.ensure_directories()
            # Create default config
            config.save({
                'api_key': '',
                'llm': {
                    'provider': 'auto',
                    'local_model': 'mistral:7b-instruct',
                    'cloud_model': 'gemini-1.5-flash-latest'
                },
                'target': {
                    'url': 'http://localhost:3010'
                }
            })

        # Load existing config
        config_data = config.load()

        # Update LLM settings
        if 'provider' in data:
            if 'llm' not in config_data:
                config_data['llm'] = {}
            config_data['llm']['provider'] = data['provider']

        if 'local_model' in data:
            if 'llm' not in config_data:
                config_data['llm'] = {}
            config_data['llm']['local_model'] = data['local_model']

        if 'cloud_model' in data:
            if 'llm' not in config_data:
                config_data['llm'] = {}
            config_data['llm']['cloud_model'] = data['cloud_model']

        if 'api_key' in data:
            # Only update if a new key is provided (not masked)
            api_key = data['api_key'].strip()
            if api_key and not api_key.startswith('sk-...') and len(api_key) > 10:
                config_data['api_key'] = api_key
                # Also set in llm config for backward compatibility
                if 'llm' not in config_data:
                    config_data['llm'] = {}
                config_data['llm']['cloud_api_key'] = api_key

        if 'temperature' in data:
            if 'llm' not in config_data:
                config_data['llm'] = {}
            config_data['llm']['temperature'] = float(data['temperature'])

        if 'max_tokens' in data:
            if 'llm' not in config_data:
                config_data['llm'] = {}
            config_data['llm']['max_tokens'] = int(data['max_tokens'])

        if 'timeout' in data:
            if 'llm' not in config_data:
                config_data['llm'] = {}
            config_data['llm']['timeout'] = int(data['timeout'])

        # Save updated config
        config.save(config_data)

        add_log_entry('system', 'LLM configuration updated', 'info')

        return jsonify({
            'status': 'success',
            'message': 'LLM configuration updated successfully'
        })
    except Exception as e:
        add_log_entry('system', f'Failed to update LLM config: {str(e)}', 'error')
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

def _mask_api_key(api_key: str) -> str:
    """Mask API key for display"""
    if not api_key or len(api_key) < 8:
        return ''
    return api_key[:4] + '...' + api_key[-4:] if len(api_key) > 8 else 'sk-...'

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

        # Get medusa CLI command path
        # Use the venv's medusa command directly (it's a wrapper script that handles imports correctly)
        script_dir = Path(__file__).parent
        venv_medusa = script_dir / 'venv' / 'bin' / 'medusa'
        if venv_medusa.exists():
            base_cmd = [str(venv_medusa)]
        else:
            # Fallback: try to find medusa in PATH
            import shutil
            medusa_cmd = shutil.which('medusa')
            if medusa_cmd:
                base_cmd = [medusa_cmd]
            else:
                # Last resort: use python with explicit path
                base_cmd = ['python3', str(script_dir / 'venv' / 'bin' / 'python3'), '-m', 'medusa.cli']

        # Default target (can be overridden)
        # Note: Lab environment EHR API runs on port 3010 (override) or 3001 (default)
        default_target = os.getenv('MEDUSA_TARGET', 'http://localhost:3010')

        # Update config file with target URL before running
        # The CLI doesn't accept --target option, so we set it in config
        try:
            from src.medusa.config import Config
            config = Config()
            if config.exists():
                config_data = config.load()
                # Update target in config
                if 'target' not in config_data:
                    config_data['target'] = {}
                config_data['target']['url'] = default_target
                config.save(config_data)
                add_log_entry('system', f'Updated config with target: {default_target}', 'info')
        except Exception as e:
            add_log_entry('system', f'Warning: Could not update config: {e}', 'warning')

        # Store snapshot of data BEFORE this operation to calculate incremental discovery
        # This allows us to track what NEW data was found in THIS operation
        # We DON'T reset discovered_data - we keep accumulating, but track the difference
        data_before_operation = {
            'vulnerabilities_count': len(medusa_state['discovered_data']['vulnerabilities']),
            'services_count': len(medusa_state['discovered_data']['services']),
            'endpoints_count': len(medusa_state['discovered_data']['endpoints']),
            'credentials_count': len(medusa_state['discovered_data']['credentials']),
            'data_records_count': len(medusa_state['discovered_data']['data_records']),
            'total_items_before': (
                len(medusa_state['discovered_data']['vulnerabilities']) +
                len(medusa_state['discovered_data']['services']) +
                len(medusa_state['discovered_data']['endpoints']) +
                len(medusa_state['discovered_data']['credentials']) +
                len(medusa_state['discovered_data']['data_records'])
            )
        }
        add_log_entry('system', f'Starting operation with objective: {objective}. Data before: {data_before_operation["total_items_before"]} items', 'info')

        # Store this in the operation context for later use
        medusa_state['current_operation'] = {
            'type': operation_type,
            'objective': objective,
            'data_before': data_before_operation,
            'started_at': datetime.now().isoformat()
        }

        # Build command for find data operation
        # Don't pass --target since it's set in config
        if operation_type == 'find':
            # Run autonomous mode to find data
            # Pass objective via environment variable so CLI can use it
            cmd = base_cmd + ['run', '--autonomous']
            add_log_entry('system', f'Executing: {" ".join(cmd)} (objective: {objective})', 'info')
        else:
            add_log_entry('system', f'Unsupported operation type: {operation_type}. Only "find" is supported.', 'error')
            medusa_state['status'] = 'error'
            medusa_state['current_operation'] = None
            return

        # Execute command with subprocess
        add_log_entry('system', 'Operation started, executing medusa CLI...', 'info')

        try:
            # Ensure first-run marker exists to skip setup wizard
            first_run_marker = Path.home() / ".medusa" / ".first_run_complete"
            first_run_marker.parent.mkdir(parents=True, exist_ok=True)
            if not first_run_marker.exists():
                first_run_marker.touch()
                add_log_entry('system', 'Created first-run marker to skip setup wizard', 'info')

            # Run the command and capture output
            # Set environment variables to skip interactive prompts and pass objective
            env = os.environ.copy()
            env['MEDUSA_NON_INTERACTIVE'] = '1'
            env['NO_COLOR'] = '1'  # Disable colors for cleaner output
            env['MEDUSA_OBJECTIVE'] = objective  # Pass objective to CLI via environment variable

            # Use Popen with stdin=PIPE to handle any prompts
            # Set PYTHONPATH to include src directory for module imports
            if 'src' not in str(Path(__file__).parent):
                env['PYTHONPATH'] = str(Path(__file__).parent / 'src') + (os.pathsep + env.get('PYTHONPATH', ''))
            else:
                env['PYTHONPATH'] = str(Path(__file__).parent.parent / 'src') + (os.pathsep + env.get('PYTHONPATH', ''))

            # Use shell=True to ensure proper argument parsing with the wrapper script
            # The medusa wrapper script needs to be executed in a shell context
            if isinstance(cmd, list):
                cmd_str = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in cmd)
            else:
                cmd_str = cmd

            process = subprocess.Popen(
                cmd_str,
                shell=True,
                cwd=str(Path(__file__).parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                stdin=subprocess.PIPE
            )

            # Wait for completion with timeout, sending newlines to skip prompts
            try:
                stdout, stderr = process.communicate(input='\n\n', timeout=3600)
                returncode = process.returncode  # Get return code after communicate
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                returncode = -1
                raise subprocess.TimeoutExpired(cmd, 3600)

            # Create result object compatible with subprocess.run return value
            class Result:
                def __init__(self, returncode, stdout, stderr):
                    self.returncode = returncode
                    self.stdout = stdout
                    self.stderr = stderr

            result = Result(returncode, stdout, stderr)

            if result.returncode == 0:
                add_log_entry('medusa', 'Operation completed successfully', 'success')

                # Log output (truncate if too long)
                output_preview = result.stdout[:1000] if result.stdout else "No output"
                if len(result.stdout or '') > 1000:
                    output_preview += "..."
                add_log_entry('system', f'Output: {output_preview}', 'info')

                # Parse and extract discovered data from output
                # IMPORTANT: This extracts REAL data from actual CLI operation output, NOT mock/test data
                # All data comes from parsing the stdout/stderr of the medusa CLI command execution
                try:
                    _parse_and_store_discovered_data(result.stdout, result.stderr, operation_type, objective)
                    items_found = (
                        len(medusa_state['discovered_data']['vulnerabilities']) +
                        len(medusa_state['discovered_data']['services']) +
                        len(medusa_state['discovered_data']['endpoints']) +
                        len(medusa_state['discovered_data']['credentials']) +
                        len(medusa_state['discovered_data']['data_records'])
                    )
                    add_log_entry('system', f'Extracted {items_found} real items from operation output', 'info')
                except Exception as e:
                    add_log_entry('system', f'Failed to parse discovered data: {e}', 'warning')

                # Record feedback for continuous learning
                # This is where the system learns from each operation to improve future ones
                try:
                    feedback = get_feedback_tracker()
                    # Count vulnerabilities from actual discovered data (most accurate)
                    # This reflects what was actually found in THIS operation (after reset)
                    actual_vulns = len(medusa_state['discovered_data']['vulnerabilities'])

                    # Also count from output as fallback, but prioritize discovered_data
                    output_lower = result.stdout.lower()
                    output_vuln_count = output_lower.count('vulnerability') + output_lower.count('vuln')

                    # Use discovered_data count if available, otherwise use output count
                    vuln_count = actual_vulns if actual_vulns > 0 else output_vuln_count

                    add_log_entry('system', f'Counted {vuln_count} vulnerabilities ({actual_vulns} from discovered_data, {output_vuln_count} from output)', 'info')

                    # Update overall metrics
                    feedback.update_operation_metrics(
                        vulnerabilities_found=vuln_count,
                        time_to_first_vuln=None  # Could parse from output if available
                    )

                    # Extract and record technique-level feedback for better learning
                    # This helps the system learn which specific techniques work best
                    output_lower = result.stdout.lower()

                    # Try to identify techniques used and their success
                    # Common MITRE ATT&CK techniques that might appear in output
                    technique_patterns = {
                        'T1046': ['network service scanning', 'port scan', 'nmap'],
                        'T1082': ['system information discovery', 'system info'],
                        'T1018': ['remote system discovery', 'network discovery'],
                        'T1040': ['network sniffing', 'packet capture'],
                        'T1005': ['data from local system', 'file system'],
                        'T1071': ['application layer protocol', 'http', 'https'],
                        'T1190': ['exploit public-facing application', 'exploit', 'vulnerability'],
                    }

                    for tech_id, keywords in technique_patterns.items():
                        if any(keyword in output_lower for keyword in keywords):
                            # If vulnerabilities found, consider it a success
                            if vuln_count > 0:
                                feedback.record_technique_success(
                                    technique_id=tech_id,
                                    target=objective,
                                    payload=None,
                                    objective=objective  # Include objective for objective-specific tracking
                                )
                            else:
                                # No vulnerabilities might indicate failure (or just no vulns found)
                                # Only record failure if operation explicitly failed
                                if result.returncode != 0:
                                    feedback.record_technique_failure(
                                        technique_id=tech_id,
                                        reason="No vulnerabilities found",
                                        target=objective,
                                        objective=objective  # Include objective for objective-specific tracking
                                    )

                    add_log_entry('system', f'Recorded {vuln_count} vulnerabilities and technique feedback for learning', 'info')

                    # Store in operation history for trends
                    time_started = medusa_state['metrics'].get('time_started')
                    duration = 0
                    if time_started:
                        try:
                            start_time = datetime.fromisoformat(time_started)
                            duration = (datetime.now() - start_time).total_seconds()
                        except:
                            pass

                    # Calculate data items found IN THIS OPERATION (difference from before)
                    # Get the snapshot we took at the start of this operation
                    data_before = medusa_state.get('current_operation', {}).get('data_before', {})
                    total_before = data_before.get('total_items_before', 0)

                    # Current total
                    total_after = (
                        len(medusa_state['discovered_data']['vulnerabilities']) +
                        len(medusa_state['discovered_data']['services']) +
                        len(medusa_state['discovered_data']['endpoints']) +
                        len(medusa_state['discovered_data']['credentials']) +
                        len(medusa_state['discovered_data']['data_records'])
                    )

                    # Data items found in THIS operation (incremental - NEW items only)
                    data_items_found_incremental = max(0, total_after - total_before)

                    # Also track TOTAL data items available (for better visualization)
                    # This shows the cumulative total, not just new items
                    data_items_found_total = total_after

                    # Count structured data records found in THIS operation
                    data_records_before = data_before.get('data_records_count', 0)
                    data_records_after = len(medusa_state['discovered_data']['data_records'])
                    new_data_records = medusa_state['discovered_data']['data_records'][data_records_before:]

                    # Count structured data in NEW records found in THIS operation
                    structured_data_count_new = sum(
                        1 for record in new_data_records
                        if record.get('structured_data') and len(record.get('structured_data', {})) > 0
                    )

                    # Calculate structured data percentage for NEW records in THIS operation
                    structured_data_percentage_new = (structured_data_count_new / len(new_data_records) * 100) if len(new_data_records) > 0 else 0.0

                    # ALSO calculate overall structured data percentage (all records, not just new)
                    # This gives a better picture of extraction quality over time
                    all_data_records = medusa_state['discovered_data']['data_records']
                    structured_data_count_all = sum(
                        1 for record in all_data_records
                        if record.get('structured_data') and len(record.get('structured_data', {})) > 0
                    )
                    structured_data_percentage_all = (structured_data_count_all / len(all_data_records) * 100) if len(all_data_records) > 0 else 0.0

                    # Use the overall percentage for trends (more meaningful)
                    # But also track the new percentage for operation-specific metrics
                    structured_data_percentage = structured_data_percentage_all
                    structured_data_count = structured_data_count_all

                    # For data_items_found, use incremental for operation tracking,
                    # but the frontend can show total if needed
                    data_items_found = data_items_found_incremental if data_items_found_incremental > 0 else data_items_found_total

                    operation_record = {
                        'timestamp': datetime.now().isoformat(),
                        'operation_type': operation_type,
                        'objective': objective,
                        'vulnerabilities_found': vuln_count,  # Keep for backward compatibility
                        'data_items_found': data_items_found,  # Data items found (incremental or total)
                        'data_items_found_total': data_items_found_total,  # Total cumulative data items
                        'data_items_found_incremental': data_items_found_incremental,  # New items in this operation
                        'structured_data_count': structured_data_count,  # Quality of extraction (all records)
                        'structured_data_count_new': structured_data_count_new,  # New structured records
                        'structured_data_percentage': structured_data_percentage,  # Percentage structured (all records)
                        'structured_data_percentage_new': structured_data_percentage_new,  # Percentage for new records
                        'total_data_records': len(all_data_records),  # Total data records available
                        'success': True,
                        'duration': duration
                    }
                    medusa_state['operation_history'].append(operation_record)
                    # Keep only last 50 operations
                    if len(medusa_state['operation_history']) > 50:
                        medusa_state['operation_history'] = medusa_state['operation_history'][-50:]

                except Exception as e:
                    add_log_entry('system', f'Failed to record feedback: {e}', 'warning')

                medusa_state['status'] = 'completed'
                medusa_state['metrics']['operations_completed'] += 1
                medusa_state['metrics']['data_found'] += vuln_count
                medusa_state['metrics']['time_completed'] = datetime.now().isoformat()
            else:
                add_log_entry('medusa', f'Operation failed with return code {result.returncode}', 'error')
                # Show both stdout and stderr for debugging
                error_output = result.stderr or result.stdout or "No error output"
                add_log_entry('system', f'Error output: {error_output[:1000]}', 'error')
                # If there's useful output in stdout, log it too
                if result.stdout and len(result.stdout) > 100:
                    add_log_entry('system', f'Output: {result.stdout[:500]}...', 'info')
                medusa_state['status'] = 'error'
                medusa_state['current_operation'] = None

        except subprocess.TimeoutExpired:
            add_log_entry('medusa', 'Operation timed out after 1 hour', 'error')
            medusa_state['status'] = 'error'
            medusa_state['current_operation'] = None

        except Exception as e:
            add_log_entry('system', f'Execution error: {str(e)}', 'error')
            medusa_state['status'] = 'error'
            medusa_state['current_operation'] = None

    except Exception as e:
        add_log_entry('system', f'Error: {str(e)}', 'error')
        medusa_state['status'] = 'error'
        medusa_state['current_operation'] = None

def _parse_and_store_discovered_data(stdout: str, stderr: str, operation_type: str = 'unknown', objective: str = ''):
    """Parse CLI output to extract discovered data including actual medical records
    Uses both regex patterns and LLM (Gemini or Ollama) for intelligent extraction

    IMPORTANT: This extracts REAL data from actual CLI operation output, not mock/test data.
    All data comes from parsing the stdout/stderr of the medusa CLI command execution.

    NOTE: The objective parameter is used to tag discovered data with the operation's goal,
    but the CLI itself doesn't yet use objectives to customize behavior. This is a limitation
    that should be addressed in future CLI updates.
    """
    add_log_entry('system', f'Parsing discovered data for objective: {objective}', 'info')
    import re
    import json
    import asyncio

    output = (stdout or '') + (stderr or '')
    output_lower = output.lower()

    # Track which operation this data came from
    operation_context = {
        'operation_type': operation_type,
        'objective': objective,
        'timestamp': datetime.now().isoformat()
    }

    # First, try regex-based extraction (fast, no API calls)
    _extract_with_regex(output, operation_context)

    # Then, use LLM (Gemini or Ollama) for intelligent extraction if output is substantial
    if len(output) > 200:  # Only use LLM if there's meaningful output
        try:
            _extract_with_llm(output, operation_context)
        except Exception as e:
            # Fallback to regex if LLM extraction fails
            add_log_entry('system', f'LLM extraction failed, using regex only: {e}', 'warning')

def _extract_with_regex(output: str, operation_context: dict = None):
    """Fast regex-based extraction from REAL CLI output"""
    import re
    import json

    if operation_context is None:
        operation_context = {'operation_type': 'unknown', 'objective': '', 'timestamp': datetime.now().isoformat()}

    # Try to parse JSON data first (if CLI outputs structured data)
    json_objects = []
    json_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
    for match in re.finditer(json_pattern, output):
        try:
            json_obj = json.loads(match.group(0))
            json_objects.append(json_obj)
        except:
            pass

    # Extract medical records / patient data
    # Look for structured data patterns
    medical_patterns = [
        # JSON-like patient records
        r'patient[:\s]*\{([^}]+)\}',
        r'medical[_\s]*record[:\s]*\{([^}]+)\}',
        # Table-like data
        r'patient[_\s]*(?:id|name|dob|ssn)[:\s]+([^\n]+)',
        r'name[:\s]+([A-Z][a-z]+ [A-Z][a-z]+)',
        r'date[_\s]*of[_\s]*birth[:\s]+([0-9/]+)',
        r'ssn[:\s]+([0-9-]+)',
        # Found X records
        r'found[:\s]+(\d+)[\s]+(?:patient|medical|record)',
        r'(\d+)[\s]+(?:patient|medical|record)[s]?[:\s]+([^\n]+)',
        # Data extraction patterns
        r'extracted[:\s]+([^\n]+)',
        r'retrieved[:\s]+([^\n]+)',
        r'accessed[:\s]+([^\n]+)',
    ]

    for pattern in medical_patterns:
        matches = re.finditer(pattern, output, re.IGNORECASE)
        for match in matches:
            # Get the full context around the match
            start = max(0, match.start() - 200)
            end = min(len(output), match.end() + 500)
            context = output[start:end]

            # Try to extract structured data from context
            data_content = match.group(1) if match.lastindex >= 1 else context

            # Look for key-value pairs in the context
            kv_pattern = r'([a-z_]+)[:\s]+([^\n,}]+)'
            kv_matches = re.finditer(kv_pattern, context, re.IGNORECASE)
            record_data = {}
            for kv in kv_matches:
                key = kv.group(1).strip().lower()
                value = kv.group(2).strip()
                if key in ['patient_id', 'name', 'dob', 'ssn', 'diagnosis', 'medication', 'allergy', 'lab_result']:
                    record_data[key] = value

            # Create record
            if record_data or len(data_content.strip()) > 10:
                record = {
                    'type': 'medical_record',
                    'raw_data': data_content.strip(),
                    'structured_data': record_data if record_data else None,
                    'discovered_at': datetime.now().isoformat(),
                    'source': 'cli_output',
                    'operation_type': operation_context.get('operation_type', 'unknown'),
                    'operation_objective': operation_context.get('objective', ''),
                    'extraction_method': 'regex'
                }
                # Avoid duplicates based on content hash
                content_hash = hash(data_content.strip())
                if not any(hash(r.get('raw_data', '')) == content_hash for r in medusa_state['discovered_data']['data_records']):
                    medusa_state['discovered_data']['data_records'].append(record)

    # Extract vulnerabilities
    vuln_patterns = [
        r'vulnerability[:\s]+([^\n]+)',
        r'vuln[:\s]+([^\n]+)',
        r'security[:\s]+issue[:\s]+([^\n]+)',
        r'exploit[:\s]+([^\n]+)'
    ]

    for pattern in vuln_patterns:
        matches = re.finditer(pattern, output, re.IGNORECASE)
        for match in matches:
            vuln_desc = match.group(1).strip()
            # Clean ANSI codes
            vuln_desc = re.sub(r'\x1b\[[0-9;]*m', '', vuln_desc)
            if vuln_desc and len(vuln_desc) > 5 and 'vulnerabilities detected' not in vuln_desc.lower():
                severity = 'high' if any(word in vuln_desc.lower() for word in ['critical', 'high', 'severe']) else \
                          'medium' if any(word in vuln_desc.lower() for word in ['medium', 'moderate']) else 'low'

                vuln = {
                    'id': f"vuln-{len(medusa_state['discovered_data']['vulnerabilities']) + 1}",
                    'description': vuln_desc,
                    'severity': severity,
                    'discovered_at': datetime.now().isoformat(),
                    'source': 'cli_output',
                    'operation_type': operation_context.get('operation_type', 'unknown'),
                    'operation_objective': operation_context.get('objective', ''),
                    'extraction_method': 'regex'
                }
                # Avoid duplicates
                if not any(v['description'] == vuln_desc for v in medusa_state['discovered_data']['vulnerabilities']):
                    medusa_state['discovered_data']['vulnerabilities'].append(vuln)

    # Extract services and ports
    port_pattern = r'port[\s:]+(\d+)[\s:]+([^\n]+)'
    service_pattern = r'(http|https|ssh|ftp|mysql|redis|ldap|smtp)[\s:]+([^\n]+)'

    for match in re.finditer(port_pattern, output, re.IGNORECASE):
        port = match.group(1)
        service_info = match.group(2).strip()
        service = {
            'port': port,
            'name': service_info.split()[0] if service_info else 'unknown',
            'description': service_info,
            'discovered_at': datetime.now().isoformat()
        }
        if not any(s['port'] == port for s in medusa_state['discovered_data']['services']):
            medusa_state['discovered_data']['services'].append(service)

    # Extract endpoints (clean ANSI codes)
    url_pattern = r'(https?://[^\s\n\x1b]+)'
    for match in re.finditer(url_pattern, output):
        url = match.group(1)
        # Remove ANSI codes
        url = re.sub(r'\x1b\[[0-9;]*m', '', url)
        if url and url.startswith('http'):
            endpoint = {
                'url': url,
                'discovered_at': datetime.now().isoformat()
            }
            if not any(e['url'] == url for e in medusa_state['discovered_data']['endpoints']):
                medusa_state['discovered_data']['endpoints'].append(endpoint)

    # Extract credentials
    cred_patterns = [
        r'username[:\s]+([^\n]+)',
        r'password[:\s]+([^\n]+)',
        r'credential[:\s]+([^\n]+)',
        r'login[:\s]+([^\n]+)',
    ]

    for pattern in cred_patterns:
        matches = re.finditer(pattern, output, re.IGNORECASE)
        for match in matches:
            cred_value = match.group(1).strip()
            cred_value = re.sub(r'\x1b\[[0-9;]*m', '', cred_value)
            if cred_value and len(cred_value) > 2:
                cred = {
                    'type': 'credential',
                    'value': cred_value,
                    'discovered_at': datetime.now().isoformat()
                }
                if not any(c['value'] == cred_value for c in medusa_state['discovered_data']['credentials']):
                    medusa_state['discovered_data']['credentials'].append(cred)

    # Also check if CLI output contains report files or data files
    # Look for file paths that might contain data
    file_pattern = r'(?:report|data|output|result)[:\s]+([/a-zA-Z0-9_.-]+\.(?:json|txt|csv|html))'
    for match in re.finditer(file_pattern, output, re.IGNORECASE):
        file_path = match.group(1)
        # Try to read the file if it exists
        try:
            file_obj = Path(file_path)
            if file_obj.exists() and file_obj.is_file():
                content = file_obj.read_text()
                if 'patient' in content.lower() or 'medical' in content.lower():
                    record = {
                        'type': 'data_file',
                        'file_path': file_path,
                        'content_preview': content[:500],
                        'discovered_at': datetime.now().isoformat()
                    }
                    medusa_state['discovered_data']['data_records'].append(record)
        except:
            pass

def _extract_with_llm(output: str, operation_context: dict = None):
    """Use LLM (Google Gemini or local Ollama) to intelligently extract medical records and data from CLI output

    Works with both:
    - Google Gemini (requires API key)
    - Local Ollama (no API key needed, runs locally)

    IMPORTANT: Extracts REAL data from actual CLI operation output, not mock/test data.

    Uses adaptive method selection based on feedback from past extractions.
    """
    if operation_context is None:
        operation_context = {'operation_type': 'unknown', 'objective': '', 'timestamp': datetime.now().isoformat()}
    try:
        # Get LLM config
        config = Config()
        if not config.exists():
            return

        config_data = config.load()
        llm_config_data = config.get_llm_config()
        provider = llm_config_data.get('provider', 'auto')

        # Use adaptive extraction method selection based on feedback
        from medusa.core.strategy_selector import StrategySelector
        selector = StrategySelector()
        objective = operation_context.get('objective', '')

        # Determine data type from objective
        data_type = 'medical_record'
        if any(kw in objective.lower() for kw in ['password', 'credential', 'login']):
            data_type = 'credential'
        elif any(kw in objective.lower() for kw in ['vulnerability', 'vuln']):
            data_type = 'vulnerability'

        # Get recommended extraction method
        recommended_method, confidence = selector.get_extraction_method_recommendation(data_type, objective)
        logger.info(f"Recommended extraction method for {data_type}: {recommended_method} (confidence: {confidence:.0%})")

        # If confidence is low, try multiple methods
        use_multiple = confidence < 0.6

        # Check if we have a usable LLM provider
        # For local Ollama, we don't need an API key
        # For Google Gemini, we need an API key
        api_key = config_data.get('api_key') or llm_config_data.get('cloud_api_key')

        if provider in ['google', 'gemini'] and not api_key:
            return  # Google Gemini requires API key
        # For local Ollama, we can proceed without API key

        # Create LLM provider (works with both Gemini and Ollama)
        llm_config = LLMConfig(
            provider=provider,
            cloud_api_key=api_key if provider in ['google', 'gemini'] else None,
            cloud_model=llm_config_data.get('cloud_model', 'gemini-1.5-flash-latest'),
            local_model=llm_config_data.get('local_model', 'mistral:7b-instruct'),
            ollama_url=llm_config_data.get('ollama_url', 'http://localhost:11434')
        )

        try:
            provider_instance = create_llm_provider(llm_config)
        except Exception as e:
            add_log_entry('system', f'Failed to create LLM provider for extraction: {e}', 'warning')
            return

        # Create prompt for LLM to extract medical records (works with both Gemini and Ollama)
        prompt = f"""Analyze the following penetration testing CLI output and extract all medical records, patient data, and sensitive information found.

Output to analyze:
{output[:8000]}  # Limit to 8000 chars to avoid token limits

Extract and return a JSON object with this structure:
{{
  "medical_records": [
    {{
      "patient_id": "if found",
      "patient_name": "if found",
      "date_of_birth": "if found",
      "ssn": "if found",
      "diagnosis": "if found",
      "medications": "if found",
      "lab_results": "if found",
      "raw_data": "full extracted text"
    }}
  ],
  "vulnerabilities": [
    {{
      "type": "vulnerability type",
      "severity": "high/medium/low",
      "description": "description"
    }}
  ],
  "credentials": [
    {{
      "username": "if found",
      "password": "if found",
      "type": "credential type"
    }}
  ],
  "services": [
    {{
      "name": "service name",
      "port": "port number",
      "description": "description"
    }}
  ]
}}

If no medical records are found, return empty arrays. Only extract actual data, not metadata or status messages.
Return ONLY valid JSON, no markdown formatting."""

        # Run async LLM call (works with both Gemini and Ollama)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            response = loop.run_until_complete(
                provider_instance.generate(
                    prompt,
                    system_prompt="You are a security analyst extracting sensitive data from penetration testing output. Extract only actual medical records and patient data, not status messages or metadata.",
                    temperature=0.3,  # Lower temperature for more accurate extraction
                    max_tokens=4000,
                    force_json=True
                )
            )
        except Exception as e:
            error_msg = str(e)
            # Log more details about what failed
            if 'Connection' in error_msg or 'Connect' in error_msg:
                add_log_entry('system', f'LLM extraction failed: Cannot connect to Ollama. Is Ollama running? Error: {error_msg}', 'warning')
            elif '404' in error_msg or 'not found' in error_msg.lower():
                add_log_entry('system', f'LLM extraction failed: Model not found. Pull model first: ollama pull {llm_config.local_model}', 'warning')
            else:
                add_log_entry('system', f'LLM extraction call failed: {error_msg}', 'warning')
            loop.close()
            return
        finally:
            loop.close()

        # Parse LLM response (works for both Gemini and Ollama)
        try:
            extracted_data = json.loads(response.content)

            # Store medical records
            for record in extracted_data.get('medical_records', []):
                if record.get('raw_data') or any(record.get(k) for k in ['patient_id', 'patient_name', 'ssn']):
                    stored_record = {
                        'type': 'medical_record',
                        'raw_data': record.get('raw_data', ''),
                        'structured_data': {k: v for k, v in record.items() if k != 'raw_data' and v},
                        'discovered_at': datetime.now().isoformat(),
                        'source': 'llm_extraction',
                        'operation_type': operation_context.get('operation_type', 'unknown'),
                        'operation_objective': operation_context.get('objective', ''),
                        'extraction_method': 'llm'
                    }
                    # Avoid duplicates
                    if not any(r.get('raw_data') == stored_record['raw_data'] for r in medusa_state['discovered_data']['data_records']):
                        medusa_state['discovered_data']['data_records'].append(stored_record)

                        # Record successful extraction for learning
                        feedback = get_feedback_tracker()
                        feedback.record_extraction_method('llm', data_type, success=True)

            # Store vulnerabilities (if not already stored)
            for vuln in extracted_data.get('vulnerabilities', []):
                if vuln.get('description'):
                    stored_vuln = {
                        'id': f"vuln-{len(medusa_state['discovered_data']['vulnerabilities']) + 1}",
                        'description': vuln['description'],
                        'severity': vuln.get('severity', 'low'),
                        'discovered_at': datetime.now().isoformat(),
                        'source': 'llm_extraction',
                        'operation_type': operation_context.get('operation_type', 'unknown'),
                        'operation_objective': operation_context.get('objective', ''),
                        'extraction_method': 'llm'
                    }
                    if not any(v['description'] == stored_vuln['description'] for v in medusa_state['discovered_data']['vulnerabilities']):
                        medusa_state['discovered_data']['vulnerabilities'].append(stored_vuln)

            # Store credentials
            for cred in extracted_data.get('credentials', []):
                if cred.get('username') or cred.get('password'):
                    stored_cred = {
                        'type': 'credential',
                        'username': cred.get('username'),
                        'password': cred.get('password'),
                        'credential_type': cred.get('type', 'unknown'),
                        'discovered_at': datetime.now().isoformat()
                    }
                    if not any(c.get('username') == stored_cred.get('username') for c in medusa_state['discovered_data']['credentials']):
                        medusa_state['discovered_data']['credentials'].append(stored_cred)

            # Store services
            for service in extracted_data.get('services', []):
                if service.get('name') or service.get('port'):
                    stored_service = {
                        'port': service.get('port', 'unknown'),
                        'name': service.get('name', 'unknown'),
                        'description': service.get('description', ''),
                        'discovered_at': datetime.now().isoformat()
                    }
                    if not any(s['port'] == stored_service['port'] for s in medusa_state['discovered_data']['services']):
                        medusa_state['discovered_data']['services'].append(stored_service)

            provider_name = 'Ollama' if provider in ['local', 'auto'] else 'Gemini'
            add_log_entry('system', f'{provider_name} extracted {len(extracted_data.get("medical_records", []))} medical records', 'info')

        except json.JSONDecodeError as e:
            add_log_entry('system', f'Failed to parse LLM JSON response: {e}', 'warning')
        except Exception as e:
            add_log_entry('system', f'Error processing LLM extraction: {e}', 'warning')

    except Exception as e:
        # Silently fail - regex extraction is the fallback
        pass

@app.route('/api/data/clear', methods=['POST'])
def clear_discovered_data():
    """Clear all discovered data (useful for starting fresh)"""
    try:
        medusa_state['discovered_data'] = {
            'vulnerabilities': [],
            'services': [],
            'endpoints': [],
            'credentials': [],
            'data_records': []
        }
        add_log_entry('system', 'Discovered data cleared', 'info')
        return jsonify({'status': 'success', 'message': 'All discovered data cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_demo_data():
    """Generate 12 hours of demo data showing continuous learning"""
    import random
    from datetime import timedelta

    now = datetime.now()
    start_time = now - timedelta(hours=12)

    # Diverse objectives for 12 hours
    objectives = [
        'find passwords', 'find medical records', 'find patient data', 'find credentials',
        'find vulnerabilities', 'find endpoints', 'find login credentials', 'find SSN numbers',
        'find email addresses', 'find phone numbers', 'find insurance information',
        'find prescription data', 'find lab results', 'find appointment records',
        'find user accounts', 'find API keys', 'find database connections',
        'find security misconfigurations', 'find exposed files', 'find backup files',
        'find passwords', 'find medical records', 'find patient data', 'find credentials',
        'find vulnerabilities', 'find endpoints', 'find login credentials', 'find SSN numbers',
        'find email addresses', 'find phone numbers', 'find insurance information',
        'find prescription data', 'find lab results', 'find appointment records',
        'find user accounts', 'find API keys', 'find database connections',
        'find security misconfigurations', 'find exposed files', 'find backup files',
        'find passwords', 'find medical records', 'find patient data', 'find credentials',
        'find vulnerabilities', 'find endpoints', 'find login credentials', 'find SSN numbers',
        'find email addresses', 'find phone numbers', 'find insurance information',
        'find prescription data', 'find lab results', 'find appointment records',
        'find user accounts', 'find API keys', 'find database connections',
        'find security misconfigurations', 'find exposed files', 'find backup files',
        'find passwords', 'find medical records', 'find patient data', 'find credentials',
        'find vulnerabilities', 'find endpoints', 'find login credentials', 'find SSN numbers',
        'find email addresses', 'find phone numbers', 'find insurance information',
        'find prescription data', 'find lab results', 'find appointment records',
        'find user accounts', 'find API keys', 'find database connections',
        'find security misconfigurations', 'find exposed files', 'find backup files',
    ]

    # MITRE ATT&CK techniques
    techniques = [
        'T1046',  # Network Service Scanning
        'T1071',  # Application Layer Protocol
        'T1040',  # Network Sniffing
        'T1005',  # Data from Local System
        'T1110',  # Brute Force
        'T1550',  # Use Alternate Authentication Material
        'T1078',  # Valid Accounts
        'T1190',  # Exploit Public-Facing Application
        'T1592',  # Gather Victim Host Information
        'T1595',  # Active Scanning
        'T1046',  # Network Service Scanning
        'T1071',  # Application Layer Protocol
        'T1040',  # Network Sniffing
        'T1005',  # Data from Local System
        'T1110',  # Brute Force
    ]

    # Generate operation history with improving metrics
    operation_history = []
    cumulative_data_items = 0
    total_operations = len(objectives)

    # Track which techniques work best for which objectives (simulating learning)
    technique_success_rates = {
        'T1110': {'password': 0.85, 'credential': 0.80, 'default': 0.40},  # Brute Force - good for credentials
        'T1550': {'password': 0.75, 'credential': 0.70, 'default': 0.35},  # Alternate Auth - good for credentials
        'T1078': {'password': 0.90, 'credential': 0.85, 'default': 0.50},  # Valid Accounts - excellent for credentials
        'T1005': {'medical': 0.88, 'patient': 0.85, 'default': 0.45},     # Data from Local - good for medical data
        'T1071': {'medical': 0.82, 'patient': 0.80, 'endpoint': 0.75, 'default': 0.55},  # App Layer Protocol - versatile
        'T1040': {'medical': 0.75, 'patient': 0.70, 'default': 0.40},      # Network Sniffing - decent for data
        'T1190': {'vulnerability': 0.92, 'default': 0.35},                # Exploit - excellent for vulnerabilities
        'T1592': {'vulnerability': 0.85, 'endpoint': 0.80, 'default': 0.50},  # Gather Info - good for discovery
        'T1595': {'vulnerability': 0.88, 'endpoint': 0.75, 'default': 0.45},   # Active Scanning - good for vulns
        'T1046': {'endpoint': 0.90, 'default': 0.40},                     # Network Service - excellent for endpoints
    }

    # Track cumulative unique data found (realistic: plateaus after finding most data)
    max_unique_data = 150  # Maximum unique data items in the system
    found_data_types = set()  # Track what types of data have been found

    for i, objective in enumerate(objectives):
        # Operations every ~9 minutes over 12 hours (720 minutes / ~80 operations)
        operation_time = start_time + timedelta(minutes=i * 9)

        # Realistic data discovery: starts high, plateaus, then decreases as most data is found
        # Early operations find more (exploration phase)
        if i < 20:
            # Exploration phase: finding lots of new data (3-8 items per operation)
            base_items = 3 + (i * 0.25) + random.uniform(-0.5, 1.5)
            cumulative_data_items += int(base_items)
        elif i < 50:
            # Plateau phase: finding less new data, more repeats
            # Simulate that we've found most unique data (plateau around 120-140 total)
            remaining_unique = max(0, max_unique_data - cumulative_data_items)
            if remaining_unique > 0:
                # Still some unique data left, but finding less per operation
                base_items = max(0.5, remaining_unique / max(1, (total_operations - i) * 2) + random.uniform(-0.3, 1.0))
                cumulative_data_items += min(int(base_items), remaining_unique)
            else:
                # All unique data found, only finding duplicates
                base_items = random.uniform(0, 1.5)
                cumulative_data_items += int(base_items * 0.3)  # Mostly duplicates, small increments
        else:
            # Saturation phase: very little new data, mostly re-discovery
            # Cumulative should stay around 140-150 (plateau)
            base_items = random.uniform(0, 1.0)
            # Very small increments, mostly maintaining the plateau
            cumulative_data_items += int(base_items * 0.2)
            # Ensure we don't exceed realistic maximum
            cumulative_data_items = min(cumulative_data_items, max_unique_data + 10)
        
        data_items = int(max(0, base_items))  # Can be 0 if no new data

        # Show learning: extraction quality improves over time (but plateaus)
        if i < 30:
            # Learning phase: quality improves rapidly
            base_quality = 20 + (i * 2.0)
        elif i < 60:
            # Refinement phase: slower improvement
            base_quality = 80 + ((i - 30) * 0.5)
        else:
            # Mastery phase: high quality with small variations
            base_quality = 92 + random.uniform(-2, 3)

        structured_percentage = min(98, max(10, base_quality + random.uniform(-4, 4)))

        # Duration decreases over time (getting faster, but plateaus)
        if i < 40:
            duration = 55 - (i * 0.4) + random.uniform(-6, 6)
        else:
            # Optimized: fast but consistent
            duration = 25 + random.uniform(-5, 5)
        duration = max(15, duration)

        # Assign technique based on objective AND learning (better techniques chosen over time)
        objective_key = 'default'
        if 'password' in objective.lower() or 'credential' in objective.lower():
            objective_key = 'password' if 'password' in objective.lower() else 'credential'
            # Over time, learn that T1078 is best for credentials
            if i > 30:
                technique_id = 'T1078' if random.random() > 0.2 else random.choice(['T1110', 'T1550'])
            else:
                technique_id = random.choice(['T1110', 'T1550', 'T1078'])
        elif 'medical' in objective.lower() or 'patient' in objective.lower():
            objective_key = 'medical' if 'medical' in objective.lower() else 'patient'
            # Over time, learn that T1005 is best for medical data
            if i > 25:
                technique_id = 'T1005' if random.random() > 0.25 else random.choice(['T1071', 'T1040'])
            else:
                technique_id = random.choice(['T1005', 'T1071', 'T1040'])
        elif 'vulnerability' in objective.lower():
            objective_key = 'vulnerability'
            # Over time, learn that T1190 is best for vulnerabilities
            if i > 20:
                technique_id = 'T1190' if random.random() > 0.15 else random.choice(['T1592', 'T1595'])
            else:
                technique_id = random.choice(['T1190', 'T1592', 'T1595'])
        elif 'endpoint' in objective.lower():
            objective_key = 'endpoint'
            # Over time, learn that T1046 is best for endpoints
            if i > 35:
                technique_id = 'T1046' if random.random() > 0.2 else random.choice(['T1071', 'T1592'])
            else:
                technique_id = random.choice(['T1046', 'T1071', 'T1592'])
        else:
            # Generic objectives - use versatile techniques
            technique_id = random.choice(['T1071', 'T1592', 'T1046'])

        # Determine success based on technique effectiveness for this objective
        tech_rates = technique_success_rates.get(technique_id, {'default': 0.50})
        success_rate = tech_rates.get(objective_key, tech_rates.get('default', 0.50))

        # Over time, success rate improves (learning to use better techniques)
        if i > 40:
            success_rate = min(0.95, success_rate + 0.1)  # Better technique selection

        operation_success = random.random() < success_rate

        # Adjust data_items based on success
        if not operation_success:
            data_items = max(0, int(data_items * 0.3))  # Failed operations find much less

        operation_history.append({
            'timestamp': operation_time.isoformat(),
            'operation_type': 'find',
            'objective': objective,
            'technique_id': technique_id,
            'vulnerabilities_found': random.randint(0, 3) if 'vulnerability' in objective.lower() and operation_success else 0,
            'data_items_found': data_items,
            'data_items_found_total': cumulative_data_items,
            'data_items_found_incremental': data_items,
            'structured_data_count': int(data_items * structured_percentage / 100) if operation_success else 0,
            'structured_data_count_new': int(data_items * structured_percentage / 100) if operation_success else 0,
            'structured_data_percentage': structured_percentage if operation_success else 0,
            'structured_data_percentage_new': structured_percentage if operation_success else 0,
            'total_data_records': cumulative_data_items,
            'success': operation_success,
            'duration': duration
        })

    # Generate discovered data (more diverse for 12 hours)
    discovered_data = {
        'vulnerabilities': [
            {
                'id': f'vuln_{i}',
                'description': random.choice([
                    f'Security vulnerability {i+1}: SQL injection in /api/search endpoint',
                    f'Security vulnerability {i+1}: XSS vulnerability in user input field',
                    f'Security vulnerability {i+1}: Weak authentication mechanism',
                    f'Security vulnerability {i+1}: Exposed sensitive data in API response',
                    f'Security vulnerability {i+1}: Insecure direct object reference',
                    f'Security vulnerability {i+1}: Missing security headers',
                    f'Security vulnerability {i+1}: Unencrypted data transmission',
                    f'Security vulnerability {i+1}: Broken access control',
                ]),
                'severity': random.choice(['high', 'medium', 'low']),
                'discovered_at': (start_time + timedelta(minutes=random.randint(10, 720))).isoformat(),
                'source': random.choice(['api_scan', 'network_scan', 'code_analysis', 'manual_test'])
            } for i in range(45)
        ],
        'services': [
            {
                'port': str(port),
                'name': name,
                'description': desc,
                'discovered_at': (start_time + timedelta(minutes=random.randint(5, 720))).isoformat()
            } for port, name, desc in [
                ('3001', 'HTTP', 'EHR API Server'),
                ('3306', 'MySQL', 'Database Server'),
                ('22', 'SSH', 'Secure Shell'),
                ('21', 'FTP', 'File Transfer Protocol'),
                ('389', 'LDAP', 'Directory Service'),
                ('8080', 'HTTP', 'EHR Frontend'),
            ]
        ],
        'endpoints': [
            {
                'url': url,
                'discovered_at': (start_time + timedelta(minutes=random.randint(5, 720))).isoformat(),
                'authentication': auth,
                'status_code': 200
            } for url, auth in [
                ('http://localhost:3001/api/patients', 'Bearer Token'),
                ('http://localhost:3001/api/employees', 'Bearer Token'),
                ('http://localhost:3001/api/login', 'None'),
                ('http://localhost:3001/api/medical_records', 'Bearer Token'),
                ('http://localhost:3001/api/credentials', 'Basic Auth'),
                ('http://localhost:3001/api/users', 'Bearer Token'),
                ('http://localhost:3001/api/search', 'None'),
                ('http://localhost:3001/api/health', 'None'),
            ]
        ],
        'credentials': [
            {
                'type': 'credential',
                'value': f'User: {user}, Pass: {pwd}',
                'discovered_at': (start_time + timedelta(minutes=random.randint(30, 720))).isoformat(),
                'source': 'api_endpoint:/api/credentials',
                'username': user,
                'password': pwd
            } for user, pwd in [
                ('admin', 'admin123'),
                ('doctor', 'Welcome123!'),
                ('nurse', 'Password2024'),
                ('receptionist', 'SecurePass!'),
            ]
        ],
        'data_records': [
            {
                'type': random.choice(['medical_record', 'credential', 'patient_data', 'prescription', 'lab_result']),
                'raw_data': None,
                'structured_data': {
                    'id': i+1,
                    'first_name': f'Patient{i+1}',
                    'last_name': random.choice(['Demo', 'Smith', 'Johnson', 'Williams', 'Brown', 'Jones']),
                    'dob': f'{1950 + random.randint(0, 70)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}',
                    'ssn': f'{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}',
                    'diagnosis': random.choice(['Hypertension', 'Diabetes', 'Asthma', 'Arthritis', 'Depression', 'Anxiety']),
                    'medications': random.sample(['Lisinopril', 'Aspirin', 'Metformin', 'Albuterol', 'Ibuprofen', 'Sertraline'], random.randint(1, 3)),
                    'email': f'patient{i+1}@example.com',
                    'phone': f'{random.randint(200, 999)}-{random.randint(100, 999)}-{random.randint(1000, 9999)}',
                } if random.random() > 0.3 else {
                    'username': random.choice(['admin', 'doctor', 'nurse', 'receptionist', f'user{i+1}']),
                    'password': random.choice(['admin123', 'Welcome123!', 'Password2024', 'SecurePass!']),
                    'type': 'credential'
                } if random.random() > 0.5 else {
                    'api_key': f'api_key_{random.randint(1000, 9999)}',
                    'endpoint': random.choice(['/api/patients', '/api/users', '/api/records']),
                    'type': 'api_credential'
                },
                'discovered_at': (start_time + timedelta(minutes=random.randint(10, 720))).isoformat(),
                'source': random.choice(['api_endpoint:/api/patients', 'api_endpoint:/api/users', 'api_endpoint:/api/records', 'file_system', 'database']),
                'operation_id': f'op_{i % total_operations}',
                'operation_objective': objectives[i % len(objectives)],
                'technique_id': techniques[i % len(techniques)],
                'extraction_method': random.choice(['llm_gemini', 'api_query', 'regex', 'llm_ollama']),
                'confidence': 0.75 + random.uniform(-0.15, 0.2)
            } for i in range(min(cumulative_data_items, 200))  # Cap at 200 records for performance
        ]
    }

    return operation_history, discovered_data

if __name__ == '__main__':
    # Initialize with welcome message
    add_log_entry('system', 'Medusa API Server started', 'info')

    # Initialize demo data if no operations have been run
    # This simulates 3 hours of continuous learning for demo purposes
    if medusa_state['metrics']['operations_completed'] == 0:
        # Check if we should load demo data (set DEMO_MODE env var or check for demo flag)
        demo_mode = os.getenv('DEMO_MODE', 'true').lower() == 'true'

        if demo_mode:
            add_log_entry('system', 'Initializing demo data (12 hours of continuous learning)', 'info')
            operation_history, discovered_data = generate_demo_data()
            medusa_state['operation_history'] = operation_history
            medusa_state['discovered_data'] = discovered_data
            medusa_state['metrics']['operations_completed'] = len(operation_history)
            medusa_state['metrics']['data_found'] = sum(op['data_items_found'] for op in operation_history)
            medusa_state['metrics']['time_started'] = operation_history[0]['timestamp'] if operation_history else None
            medusa_state['metrics']['time_completed'] = operation_history[-1]['timestamp'] if operation_history else None
            add_log_entry('system', f'Demo data loaded: {len(operation_history)} operations over 12 hours', 'info')
        else:
            medusa_state['discovered_data'] = {
                'vulnerabilities': [],
                'services': [],
                'endpoints': [],
                'credentials': [],
                'data_records': []
            }

    # Run Flask server
    # Using port 5001 to avoid conflict with macOS AirPlay Receiver on port 5000
    port = int(os.getenv('MEDUSA_API_PORT', '5001'))
    print(f"Starting Medusa API Server on http://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, debug=True)


"""
AFIR-TI Dashboard - Main Flask Application
Autonomous Firewall Incident Response & Threat Intelligence
"""

import os
import json
import csv
import io
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, send_file, Response
from functools import wraps

# Import SIEM Engines
from correlation_engine import CorrelationEngine
from baseline_engine import BaselineEngine
from case_manager import CaseManager
from ueba_engine import UEBAEngine
from playbook_engine import PlaybookEngine
from threat_feed_manager import ThreatFeedManager
from asset_manager import AssetManager

# Import AI-Powered Engines
from explainability_engine import ExplainabilityEngine
from chat_assistant import ChatAssistant
from attack_prediction import AttackPrediction
from threat_narrator import ThreatNarrator
from adaptive_thresholds import AdaptiveThresholdEngine

app = Flask(__name__)

# File paths
BASE_DIR = '/workspace/opt/firewall_irt'
EVENTS_FILE = os.path.join(BASE_DIR, 'events.json')
BLOCKED_FILE = os.path.join(BASE_DIR, 'blocked_ips.json')
WHITELIST_FILE = os.path.join(BASE_DIR, 'whitelist.json')
CONFIG_FILE = os.path.join(BASE_DIR, 'config.json')
CORRELATED_FILE = os.path.join(BASE_DIR, 'correlated_events.json')
BASELINES_FILE = os.path.join(BASE_DIR, 'baselines.json')
CASES_FILE = os.path.join(BASE_DIR, 'cases.json')
ENTITY_PROFILES_FILE = os.path.join(BASE_DIR, 'entity_profiles.json')
PLAYBOOKS_FILE = os.path.join(BASE_DIR, 'playbooks.json')
PLAYBOOK_LOG_FILE = os.path.join(BASE_DIR, 'playbook_log.json')
ASSETS_FILE = os.path.join(BASE_DIR, 'assets.json')
FEED_STATUS_FILE = os.path.join(BASE_DIR, 'feed_status.json')
ALERT_HISTORY_FILE = os.path.join(BASE_DIR, 'alert_history.json')

# Initialize engines
correlation_engine = CorrelationEngine(EVENTS_FILE, CORRELATED_FILE)
baseline_engine = BaselineEngine(EVENTS_FILE, BASELINES_FILE)
case_manager = CaseManager(CASES_FILE, EVENTS_FILE)
ueba_engine = UEBAEngine(ENTITY_PROFILES_FILE, EVENTS_FILE, WHITELIST_FILE)
playbook_engine = PlaybookEngine(PLAYBOOKS_FILE, PLAYBOOK_LOG_FILE, CASES_FILE)
threat_feed_manager = ThreatFeedManager(FEED_STATUS_FILE, EVENTS_FILE)
asset_manager = AssetManager(ASSETS_FILE)

# AI Engines
explainability_engine = ExplainabilityEngine()
chat_assistant = ChatAssistant(CONFIG_FILE)
attack_prediction = AttackPrediction(EVENTS_FILE)
threat_narrator = ThreatNarrator(CONFIG_FILE)
adaptive_thresholds = AdaptiveThresholdEngine(CONFIG_FILE)

def load_json_file(filepath, default=None):
    """Load JSON file with error handling"""
    if default is None:
        default = []
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
    return default

def save_json_file(filepath, data):
    """Save JSON file with error handling"""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception as e:
        print(f"Error saving {filepath}: {e}")
        return False

def get_config():
    """Get current configuration"""
    default_config = {
        "failed_conn_threshold": 10,
        "port_scan_threshold": 20,
        "traffic_volume_threshold": 1000,
        "lstm_anomaly_score": 0.5,
        "block_duration": 3600,
        "ml_weight": 0.7,
        "anthropic_key": "",
        "adaptive_thresholds_enabled": False
    }
    config = load_json_file(CONFIG_FILE, default_config)
    # Merge with defaults
    for key, value in default_config.items():
        if key not in config:
            config[key] = value
    return config

# ==================== Original Endpoints ====================

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/events')
def get_events():
    """Get all events with explanations and narratives"""
    events = load_json_file(EVENTS_FILE, [])
    # Add explanations and narratives
    for event in events:
        if 'event_id' in event:
            event['explanation'] = explainability_engine.get_explanation(event)
            event['narrative'] = threat_narrator.generate_narrative(event)
    return jsonify(events)

@app.route('/api/blocked')
def get_blocked():
    """Get blocked IPs"""
    blocked = load_json_file(BLOCKED_FILE, [])
    return jsonify(blocked)

# ==================== FEATURE 1: Explainability (SHAP) ====================

@app.route('/api/explain/<event_id>')
def get_explanation(event_id):
    """Get detailed SHAP explanation for an event"""
    try:
        events = load_json_file(EVENTS_FILE, [])
        event = next((e for e in events if e.get('event_id') == event_id), None)
        if not event:
            return jsonify({"error": "Event not found"}), 404
        
        explanation = explainability_engine.get_detailed_explanation(event)
        return jsonify(explanation)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== FEATURE 2: Chat Assistant ====================

@app.route('/api/chat', methods=['POST'])
def chat():
    """Chat with AI assistant about threats"""
    try:
        data = request.get_json()
        message = data.get('message', '')
        
        if not message:
            return jsonify({"error": "Message is required"}), 400
        
        # Gather context
        events = load_json_file(EVENTS_FILE, [])[-50:]
        blocked = load_json_file(BLOCKED_FILE, [])
        stats = {
            "total_events": len(load_json_file(EVENTS_FILE, [])),
            "blocked_count": len(blocked),
            "top_techniques": baseline_engine.get_top_techniques()
        }
        
        reply = chat_assistant.chat(message, events, blocked, stats)
        return jsonify({"reply": reply})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== FEATURE 3: Attack Prediction ====================

@app.route('/api/predictions')
def get_predictions():
    """Get AI attack predictions"""
    try:
        predictions = attack_prediction.get_predictions()
        return jsonify(predictions)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== FEATURE 4: Natural Language Summary ====================

@app.route('/api/summary/today')
def get_today_summary():
    """Get natural language summary of today's threats"""
    try:
        events = load_json_file(EVENTS_FILE, [])
        summary = threat_narrator.generate_daily_summary(events)
        return jsonify({"summary": summary})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== FEATURE 5: Adaptive Thresholds ====================

@app.route('/api/adaptation-log')
def get_adaptation_log():
    """Get adaptation history log"""
    try:
        log = adaptive_thresholds.get_log()
        return jsonify(log)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/adaptation/reset', methods=['POST'])
def reset_adaptation():
    """Reset thresholds to defaults"""
    try:
        adaptive_thresholds.reset_to_defaults()
        return jsonify({"success": True, "message": "Thresholds reset to defaults"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== SIEM Feature Endpoints ====================

@app.route('/api/correlated')
def get_correlated():
    """Get correlated attacks"""
    try:
        correlated = correlation_engine.get_correlated_events()
        return jsonify(correlated)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/baselines')
def get_baselines():
    """Get baseline statistics"""
    try:
        baselines = baseline_engine.get_baselines()
        return jsonify(baselines)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cases')
def get_cases():
    """Get cases with optional status filter"""
    try:
        status = request.args.get('status')
        cases = case_manager.get_cases(status)
        return jsonify(cases)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cases/<case_id>', methods=['GET'])
def get_case(case_id):
    """Get single case details"""
    try:
        case = case_manager.get_case(case_id)
        if not case:
            return jsonify({"error": "Case not found"}), 404
        return jsonify(case)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cases/<case_id>/note', methods=['POST'])
def add_case_note(case_id):
    """Add note to case"""
    try:
        data = request.get_json()
        note = data.get('note', '')
        case_manager.add_note(case_id, note)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cases/<case_id>/status', methods=['POST'])
def update_case_status(case_id):
    """Update case status"""
    try:
        data = request.get_json()
        status = data.get('status')
        if not status:
            return jsonify({"error": "Status is required"}), 400
        case_manager.update_status(case_id, status)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/entities')
def get_entities():
    """Get all entity profiles sorted by risk score"""
    try:
        entities = ueba_engine.get_all_entities()
        return jsonify(entities)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/entities/<ip>')
def get_entity(ip):
    """Get single entity profile"""
    try:
        # URL decode the IP
        from urllib.parse import unquote
        ip = unquote(ip.replace('%2E', '.').replace('%2F', '/'))
        entity = ueba_engine.get_entity(ip)
        if not entity:
            return jsonify({"error": "Entity not found"}), 404
        return jsonify(entity)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/playbooks')
def get_playbooks():
    """Get all playbooks"""
    try:
        playbooks = playbook_engine.get_playbooks()
        return jsonify(playbooks)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/playbooks/<name>/toggle', methods=['POST'])
def toggle_playbook(name):
    """Toggle playbook enabled status"""
    try:
        playbook_engine.toggle_playbook(name)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/playbooks/log')
def get_playbook_log():
    """Get playbook execution log"""
    try:
        log = playbook_engine.get_log(limit=20)
        return jsonify(log)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/hunt', methods=['POST'])
def hunt():
    """Threat hunting query interface"""
    try:
        data = request.get_json()
        filters = data.get('filters', {})
        time_range = data.get('time_range', '24h')
        sort_by = data.get('sort_by', 'timestamp')
        limit = data.get('limit', 100)
        
        results = attack_prediction.hunt(filters, time_range, sort_by, limit)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/assets', methods=['GET', 'POST'])
def manage_assets():
    """Get or add assets"""
    try:
        if request.method == 'POST':
            data = request.get_json()
            asset_manager.add_asset(data)
            return jsonify({"success": True})
        else:
            assets = asset_manager.get_assets()
            return jsonify(assets)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/assets/<ip>', methods=['PUT', 'DELETE'])
def update_asset(ip):
    """Update or delete asset"""
    try:
        from urllib.parse import unquote
        ip = unquote(ip.replace('%2E', '.').replace('%2F', '/'))
        
        if request.method == 'PUT':
            data = request.get_json()
            asset_manager.update_asset(ip, data)
            return jsonify({"success": True})
        else:
            asset_manager.delete_asset(ip)
            return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/compliance/<standard>')
def get_compliance(standard):
    """Get compliance report"""
    try:
        report = threat_narrator.generate_compliance_report(standard)
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/export/compliance-pdf')
def export_compliance_pdf():
    """Export compliance report as PDF"""
    try:
        standard = request.args.get('standard', 'basic')
        pdf_data = threat_narrator.generate_compliance_pdf(standard)
        return send_file(
            io.BytesIO(pdf_data),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'compliance_{standard}_{datetime.now().strftime("%Y%m%d")}.pdf'
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/incident-timeline/<ip>')
def get_incident_timeline(ip):
    """Get incident timeline reconstruction for an IP"""
    try:
        from urllib.parse import unquote
        from datetime import datetime
        ip = unquote(ip.replace('%2E', '.').replace('%2F', '/'))
        
        from_ts = request.args.get('from')
        to_ts = request.args.get('to')
        
        timeline = case_manager.reconstruct_incident(ip, from_ts, to_ts)
        return jsonify(timeline)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/feeds/status')
def get_feeds_status():
    """Get threat feeds status"""
    try:
        status = threat_feed_manager.get_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/feeds/update', methods=['POST'])
def update_feeds():
    """Manually update threat feeds"""
    try:
        threat_feed_manager.update_feeds()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== Additional Original Feature Endpoints ====================

@app.route('/api/timeline')
def get_timeline():
    """Get attack timeline for last 24 hours"""
    try:
        events = load_json_file(EVENTS_FILE, [])
        now = datetime.now()
        hours = {}
        
        for i in range(24):
            hour = (now - timedelta(hours=i)).strftime('%H:00')
            hours[hour] = {'total': 0, 'threats': 0}
        
        for event in events:
            try:
                ts = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                hour_key = ts.strftime('%H:00')
                if hour_key in hours:
                    hours[hour_key]['total'] += 1
                    if event.get('threat'):
                        hours[hour_key]['threats'] += 1
            except:
                continue
        
        result = [{'hour': h, 'total': v['total'], 'threats': v['threats']} 
                  for h, v in sorted(hours.items(), reverse=True)[:24]]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/mitre-stats')
def get_mitre_stats():
    """Get MITRE ATT&CK statistics"""
    try:
        events = load_json_file(EVENTS_FILE, [])
        today = datetime.now().date()
        stats = {}
        
        for event in events:
            try:
                ts = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                if ts.date() == today:
                    tactic = event.get('mitre_tactic', 'Unknown')
                    technique = event.get('mitre_technique_id', 'Unknown')
                    key = f"{tactic}:{technique}"
                    if key not in stats:
                        stats[key] = {
                            'tactic': tactic,
                            'technique_id': technique,
                            'count': 0,
                            'last_seen': ts.isoformat()
                        }
                    stats[key]['count'] += 1
                    stats[key]['last_seen'] = ts.isoformat()
            except:
                continue
        
        return jsonify(list(stats.values()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/threat-level')
def get_threat_level():
    """Get current threat level"""
    try:
        events = load_json_file(EVENTS_FILE, [])
        now = datetime.now()
        five_min_ago = now - timedelta(minutes=5)
        
        recent_events = []
        for event in events:
            try:
                ts = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                if ts >= five_min_ago:
                    recent_events.append(event)
            except:
                continue
        
        if not recent_events:
            return jsonify({
                'level': 'LOW',
                'avg_score': 0.0,
                'threat_count': 0,
                'color': '#3fb950'
            })
        
        avg_score = sum(e.get('hybrid_score', 0) for e in recent_events) / len(recent_events)
        threat_count = sum(1 for e in recent_events if e.get('threat'))
        
        if avg_score < 0.3 and threat_count < 3:
            level, color = 'LOW', '#3fb950'
        elif avg_score < 0.5 or threat_count < 10:
            level, color = 'MEDIUM', '#d29922'
        elif avg_score < 0.8 or threat_count < 20:
            level, color = 'HIGH', '#ff8800'
        else:
            level, color = 'CRITICAL', '#f85149'
        
        return jsonify({
            'level': level,
            'avg_score': round(avg_score, 2),
            'threat_count': threat_count,
            'color': color
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/config', methods=['GET', 'POST'])
def manage_config():
    """Get or update configuration"""
    try:
        if request.method == 'POST':
            data = request.get_json()
            config = get_config()
            
            # Validate and update
            validation_rules = {
                'failed_conn_threshold': (1, 1000),
                'port_scan_threshold': (1, 500),
                'traffic_volume_threshold': (1, 100000),
                'lstm_anomaly_score': (0.01, 1.0),
                'block_duration': (60, 86400),
                'ml_weight': (0.1, 0.9)
            }
            
            for key, (min_val, max_val) in validation_rules.items():
                if key in data:
                    val = float(data[key])
                    if val < min_val or val > max_val:
                        return jsonify({
                            'error': f'{key} must be between {min_val} and {max_val}'
                        }), 400
                    config[key] = val
            
            if 'anthropic_key' in data:
                config['anthropic_key'] = data['anthropic_key']
            if 'adaptive_thresholds_enabled' in data:
                config['adaptive_thresholds_enabled'] = data['adaptive_thresholds_enabled']
            
            save_json_file(CONFIG_FILE, config)
            return jsonify({'success': True})
        else:
            return jsonify(get_config())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/export/csv')
def export_csv():
    """Export events as CSV"""
    try:
        events = load_json_file(EVENTS_FILE, [])
        output = io.StringIO()
        fieldnames = ['timestamp', 'src_ip', 'dest_ip', 'threat', 'hybrid_score', 
                      'reason', 'mitre_technique_id', 'mitre_tactic', 'attack_stage']
        
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(events)
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=events.csv'}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/export/pdf')
def export_pdf():
    """Export events as PDF"""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        
        events = load_json_file(EVENTS_FILE, [])
        blocked = load_json_file(BLOCKED_FILE, [])
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        elements.append(Paragraph("AFIR-TI Security Report", styles['Title']))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Summary
        elements.append(Paragraph("Summary", styles['Heading2']))
        elements.append(Paragraph(f"Total Events: {len(events)}", styles['Normal']))
        elements.append(Paragraph(f"Blocked IPs: {len(blocked)}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Events table
        elements.append(Paragraph("Recent Events", styles['Heading2']))
        table_data = [['Timestamp', 'Source IP', 'Threat', 'Score', 'Technique']]
        for event in events[-20:]:
            table_data.append([
                event.get('timestamp', '')[:19],
                event.get('src_ip', ''),
                'Yes' if event.get('threat') else 'No',
                str(event.get('hybrid_score', 0))[:4],
                event.get('mitre_technique_id', '')
            ])
        
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
        ]))
        elements.append(table)
        
        doc.build(elements)
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'afir_report_{datetime.now().strftime("%Y%m%d")}.pdf'
        )
    except ImportError:
        return jsonify({"error": "reportlab not installed. Run: pip install reportlab"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/health')
def get_health():
    """Get system health metrics"""
    try:
        import psutil
        
        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory().percent
        net = psutil.net_io_counters()
        
        return jsonify({
            'cpu_percent': cpu,
            'ram_percent': ram,
            'net_bytes_sent': net.bytes_sent,
            'net_bytes_recv': net.bytes_recv,
            'uptime_seconds': psutil.boot_time()
        })
    except ImportError:
        return jsonify({
            'cpu_percent': 0,
            'ram_percent': 0,
            'net_bytes_sent': 0,
            'net_bytes_recv': 0,
            'uptime_seconds': 0,
            'error': 'psutil not installed'
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """Get log files"""
    try:
        file_map = {
            'firewall_irt': '/tmp/firewall_irt.log',
            'ids_gen': '/tmp/ids_gen.log',
            'dashboard': '/tmp/dashboard.log',
            'suricata': '/var/log/suricata/eve.json'
        }
        
        file_name = request.args.get('file', 'firewall_irt')
        lines = min(int(request.args.get('lines', 100)), 500)
        search = request.args.get('search', '')
        
        if file_name not in file_map:
            return jsonify({"error": "Invalid file name"}), 400
        
        filepath = file_map[file_name]
        if not os.path.exists(filepath):
            return jsonify({"lines": [], "total_lines": 0, "file": file_name, "truncated": False})
        
        with open(filepath, 'r') as f:
            all_lines = f.readlines()
        
        total = len(all_lines)
        filtered = all_lines[-lines:]
        
        if search:
            filtered = [l for l in filtered if search.lower() in l.lower()]
        
        return jsonify({
            'lines': [l.strip() for l in filtered],
            'total_lines': total,
            'file': file_name,
            'truncated': len(filtered) < total
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/whitelist', methods=['GET', 'POST'])
def manage_whitelist():
    """Get or add to whitelist"""
    try:
        whitelist = load_json_file(WHITELIST_FILE, {"whitelist_ips": []})
        
        if request.method == 'POST':
            action = request.args.get('action', 'add')
            data = request.get_json()
            
            if action == 'add':
                ip = data.get('ip', '')
                note = data.get('note', '')
                
                # Simple IP validation
                import re
                ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
                if not re.match(ip_pattern, ip):
                    return jsonify({"error": "Invalid IP format"}), 400
                
                if ip not in whitelist['whitelist_ips']:
                    whitelist['whitelist_ips'].append({'ip': ip, 'note': note, 'added': datetime.now().isoformat()})
                    save_json_file(WHITELIST_FILE, whitelist)
                
                return jsonify({"success": True})
            elif action == 'remove':
                ip = data.get('ip', '')
                whitelist['whitelist_ips'] = [x for x in whitelist['whitelist_ips'] if x.get('ip') != ip]
                save_json_file(WHITELIST_FILE, whitelist)
                return jsonify({"success": True})
        
        return jsonify(whitelist)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/ip-history/<ip>')
def get_ip_history(ip):
    """Get full history for an IP"""
    try:
        from urllib.parse import unquote
        ip = unquote(ip.replace('%2E', '.').replace('%2F', '/'))
        
        events = load_json_file(EVENTS_FILE, [])
        blocked = load_json_file(BLOCKED_FILE, [])
        
        ip_events = [e for e in events if e.get('src_ip') == ip]
        
        if not ip_events:
            return jsonify({"error": "No events found for this IP"}), 404
        
        timestamps = [datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) for e in ip_events]
        scores = [e.get('hybrid_score', 0) for e in ip_events]
        
        return jsonify({
            'ip': ip,
            'first_seen': min(timestamps).isoformat(),
            'last_seen': max(timestamps).isoformat(),
            'total_events': len(ip_events),
            'threat_events': sum(1 for e in ip_events if e.get('threat')),
            'avg_score': round(sum(scores) / len(scores), 2),
            'max_score': max(scores),
            'times_blocked': sum(1 for b in blocked if b.get('ip') == ip),
            'techniques_used': list(set(e.get('mitre_technique_id', '') for e in ip_events)),
            'timeline': [{
                'timestamp': e['timestamp'],
                'score': e.get('hybrid_score', 0),
                'reason': e.get('reason', ''),
                'technique': e.get('mitre_technique_id', '')
            } for e in sorted(ip_events, key=lambda x: x['timestamp'], reverse=True)]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/heatmap')
def get_heatmap():
    """Get attack heatmap (7 days x 24 hours)"""
    try:
        events = load_json_file(EVENTS_FILE, [])
        now = datetime.now()
        
        heatmap = {}
        for day in range(7):
            date = (now - timedelta(days=day)).date()
            heatmap[str(date)] = {str(h): 0 for h in range(24)}
        
        for event in events:
            try:
                ts = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                date_str = str(ts.date())
                hour_str = str(ts.hour)
                if date_str in heatmap and event.get('threat'):
                    heatmap[date_str][hour_str] += 1
            except:
                continue
        
        return jsonify(heatmap)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """Get detection statistics"""
    try:
        events = load_json_file(EVENTS_FILE, [])
        blocked = load_json_file(BLOCKED_FILE, [])
        
        total = len(events)
        threats = sum(1 for e in events if e.get('threat'))
        scores = [e.get('hybrid_score', 0) for e in events]
        
        # Score distribution
        ranges = [(0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.0)]
        distribution = {f"{r[0]}-{r[1]}": 0 for r in ranges}
        for s in scores:
            for r in ranges:
                if r[0] <= s < r[1]:
                    distribution[f"{r[0]}-{r[1]}"] += 1
                    break
        
        # Top techniques
        techniques = {}
        for e in events:
            t = e.get('mitre_technique_id', 'Unknown')
            techniques[t] = techniques.get(t, 0) + 1
        top_techniques = sorted(techniques.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Top attackers
        attackers = {}
        for e in events:
            if e.get('threat'):
                ip = e.get('src_ip', 'Unknown')
                attackers[ip] = attackers.get(ip, 0) + 1
        top_attackers = sorted(attackers.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return jsonify({
            'total_events': total,
            'threat_events': threats,
            'detection_rate': round(threats / total * 100, 1) if total > 0 else 0,
            'avg_hybrid_score': round(sum(scores) / len(scores), 2) if scores else 0,
            'score_distribution': distribution,
            'top_techniques': [{'technique': t, 'count': c} for t, c in top_techniques],
            'top_attackers': [{'ip': ip, 'count': c} for ip, c in top_attackers],
            'blocks_today': len(blocked)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts', methods=['GET', 'POST'])
def manage_alerts():
    """Get or mark alerts as read"""
    try:
        alerts = load_json_file(ALERT_HISTORY_FILE, [])
        
        if request.method == 'POST':
            action = request.args.get('action', 'mark-read')
            if action == 'mark-read':
                for alert in alerts:
                    alert['read'] = True
                save_json_file(ALERT_HISTORY_FILE, alerts)
                return jsonify({"success": True})
        
        limit = int(request.args.get('limit', 50))
        severity = request.args.get('severity')
        
        filtered = alerts
        if severity:
            filtered = [a for a in alerts if a.get('severity') == severity]
        
        return jsonify(filtered[-limit:])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("Starting AFIR-TI Dashboard...")
    print(f"Events file: {EVENTS_FILE}")
    print(f"Blocked IPs file: {BLOCKED_FILE}")
    print(f"Config file: {CONFIG_FILE}")
    
    # Print SIEM features status
    print("\nSIEM Features:")
    print("  Correlation Engine: ✓")
    print("  Baseline Engine: ✓")
    print("  Case Manager: ✓")
    print("  UEBA Engine: ✓")
    print("  Playbook Engine: ✓")
    print("  Threat Feed Manager: ✓")
    print("  Asset Manager: ✓")
    
    # Print AI features status
    print("\nAI-Powered Features:")
    print("  Explainability (SHAP): ✓")
    print("  Chat Assistant: ✓")
    print("  Attack Prediction: ✓")
    print("  Threat Narrator: ✓")
    print("  Adaptive Thresholds: ✓")
    
    app.run(host='0.0.0.0', port=5000, debug=False)

"""
Baseline & Deviation Detection Engine
Learns normal behavior for each IP and detects anomalies
"""

import json
from datetime import datetime, timedelta
from collections import defaultdict

class BaselineEngine:
    """Learn and detect deviations from normal IP behavior"""
    
    def __init__(self, events_file, baselines_file):
        self.events_file = events_file
        self.baselines_file = baselines_file
    
    def get_baselines(self):
        """Get all baseline statistics"""
        try:
            with open(self.baselines_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def update_baselines(self):
        """Update baselines from recent events"""
        try:
            with open(self.events_file, 'r') as f:
                events = json.load(f)
        except:
            return
        
        # Group by IP and hour
        ip_hourly = defaultdict(lambda: defaultdict(list))
        
        for event in events:
            ip = event.get('src_ip', '')
            if not ip:
                continue
            
            try:
                ts = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                hour = ts.hour
                ip_hourly[ip][hour].append(event)
            except:
                pass
        
        baselines = {}
        
        for ip, hours in ip_hourly.items():
            # Calculate stats per hour
            hourly_stats = {}
            for hour, hour_events in hours.items():
                connections = len(hour_events)
                ports = set(e.get('features', {}).get('unique_ports', 0) for e in hour_events)
                protocols = set(e.get('protocol', '') for e in hour_events)
                
                hourly_stats[str(hour)] = {
                    'avg_connections': connections,
                    'avg_unique_ports': sum(ports) / len(ports) if ports else 0,
                    'protocols': list(protocols),
                    'event_count': connections
                }
            
            baselines[ip] = {
                'hourly_patterns': hourly_stats,
                'last_updated': datetime.now().isoformat(),
                'total_events': sum(len(h) for h in hours.values())
            }
        
        try:
            with open(self.baselines_file, 'w') as f:
                json.dump(baselines, f, indent=2)
        except Exception as e:
            print(f"Error saving baselines: {e}")
    
    def check_deviation(self, ip, event):
        """Check if an event deviates from baseline"""
        try:
            with open(self.baselines_file, 'r') as f:
                baselines = json.load(f)
        except:
            return None
        
        if ip not in baselines:
            return None
        
        baseline = baselines[ip]
        hour = datetime.now().hour
        hour_stats = baseline.get('hourly_patterns', {}).get(str(hour), {})
        
        if not hour_stats:
            return None
        
        deviations = []
        features = event.get('features', {})
        
        # Check connection spike
        avg_conn = hour_stats.get('avg_connections', 0)
        current_conn = features.get('conn_count', 0)
        if avg_conn > 0 and current_conn > avg_conn * 3:
            deviations.append({
                'type': 'traffic_spike',
                'message': f'Connections {current_conn} exceeds 200% of normal {avg_conn}',
                'severity': 'high' if current_conn > avg_conn * 5 else 'medium'
            })
        
        # Check new protocol
        known_protocols = hour_stats.get('protocols', [])
        current_protocol = event.get('protocol', '')
        if current_protocol and current_protocol not in known_protocols:
            deviations.append({
                'type': 'new_protocol',
                'message': f'New protocol {current_protocol} not seen before for this IP',
                'severity': 'medium'
            })
        
        # Check unusual time
        if str(hour) not in baseline.get('hourly_patterns', {}):
            deviations.append({
                'type': 'unusual_time',
                'message': f'Activity at hour {hour} when IP is normally inactive',
                'severity': 'low'
            })
        
        return deviations if deviations else None
    
    def get_top_techniques(self):
        """Get top MITRE techniques from today's events"""
        try:
            with open(self.events_file, 'r') as f:
                events = json.load(f)
        except:
            return []
        
        today = datetime.now().date()
        techniques = defaultdict(int)
        
        for event in events:
            try:
                ts = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                if ts.date() == today:
                    tech = event.get('mitre_technique_id', 'Unknown')
                    techniques[tech] += 1
            except:
                pass
        
        return sorted(techniques.items(), key=lambda x: x[1], reverse=True)[:5]

"""
Event Correlation Engine
Correlates events from same IP across different sources/time windows
"""

import json
from datetime import datetime, timedelta
from collections import defaultdict

class CorrelationEngine:
    """Correlate security events to detect coordinated attacks"""
    
    def __init__(self, events_file, correlated_file):
        self.events_file = events_file
        self.correlated_file = correlated_file
    
    def get_correlated_events(self):
        """Get all correlated attack events"""
        try:
            with open(self.events_file, 'r') as f:
                events = json.load(f)
        except:
            return []
        
        # Group events by IP
        ip_events = defaultdict(list)
        for event in events:
            ip = event.get('src_ip', '')
            if ip:
                ip_events[ip].append(event)
        
        correlated = []
        
        for ip, ip_evts in ip_events.items():
            if len(ip_evts) < 3:
                continue
            
            # Sort by timestamp
            ip_evts.sort(key=lambda x: x.get('timestamp', ''))
            
            # Check for correlations in sliding 60-second windows
            for i in range(len(ip_evts)):
                window_start = datetime.fromisoformat(ip_evts[i].get('timestamp', '').replace('Z', '+00:00'))
                window_events = [ip_evts[i]]
                
                for j in range(i + 1, len(ip_evts)):
                    ts = datetime.fromisoformat(ip_evts[j].get('timestamp', '').replace('Z', '+00:00'))
                    if (ts - window_start).total_seconds() <= 60:
                        window_events.append(ip_evts[j])
                
                if len(window_events) >= 3:
                    # Check correlation types
                    corr_type = self._detect_correlation_type(window_events)
                    if corr_type:
                        combined_score = sum(e.get('hybrid_score', 0) for e in window_events) / len(window_events)
                        combined_score += 0.2  # Boost for correlation
                        
                        correlated.append({
                            'correlation_id': f"{ip}_{i}",
                            'timestamp': window_start.isoformat(),
                            'src_ip': ip,
                            'correlation_type': corr_type,
                            'event_count': len(window_events),
                            'combined_score': round(min(combined_score, 1.0), 2),
                            'events': [e.get('event_id', str(idx)) for idx, e in enumerate(window_events)]
                        })
                        break  # One correlation per IP
        
        return correlated
    
    def _detect_correlation_type(self, events):
        """Detect type of correlation"""
        sources = set(e.get('source', '') for e in events)
        techniques = set(e.get('mitre_technique_id', '') for e in events)
        stages = [e.get('attack_stage', '') for e in events]
        
        # Multi-source: same IP in 3+ different sources
        if len(sources) >= 3:
            return 'multi_source'
        
        # Multi-technique: same IP triggered 3+ different MITRE techniques
        if len(techniques) >= 3:
            return 'multi_technique'
        
        # Kill chain: progression through attack stages
        stage_order = ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 
                       'Privilege Escalation', 'Defense Evasion', 'Credential Access', 
                       'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 
                       'Exfiltration', 'Impact']
        
        stage_indices = [stage_order.index(s) for s in stages if s in stage_order]
        if len(stage_indices) >= 2 and max(stage_indices) - min(stage_indices) >= 2:
            return 'kill_chain'
        
        return None

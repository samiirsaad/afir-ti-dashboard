"""
UEBA - User and Entity Behavior Analytics
Builds risk profiles for each IP based on historical behavior
"""

import json
import os
from datetime import datetime
from collections import defaultdict

class UEBAEngine:
    """Entity behavior analytics and risk scoring"""
    
    def __init__(self, profiles_file, events_file, whitelist_file):
        self.profiles_file = profiles_file
        self.events_file = events_file
        self.whitelist_file = whitelist_file
    
    def get_all_entities(self):
        """Get all entity profiles sorted by risk score"""
        self._update_profiles()
        
        try:
            with open(self.profiles_file, 'r') as f:
                profiles = json.load(f)
        except:
            profiles = []
        
        # Sort by risk score descending
        return sorted(profiles, key=lambda x: x.get('risk_score', 0), reverse=True)
    
    def get_entity(self, ip):
        """Get single entity profile"""
        self._update_profiles()
        
        try:
            with open(self.profiles_file, 'r') as f:
                profiles = json.load(f)
        except:
            return None
        
        for profile in profiles:
            if profile.get('ip') == ip:
                return profile
        return None
    
    def _update_profiles(self):
        """Update entity profiles from events"""
        try:
            with open(self.events_file, 'r') as f:
                events = json.load(f)
            with open(self.whitelist_file, 'r') as f:
                whitelist_data = json.load(f)
                whitelist = [w.get('ip', '') for w in whitelist_data.get('whitelist_ips', [])]
        except:
            return
        
        # Group by IP
        ip_events = defaultdict(list)
        for event in events:
            ip = event.get('src_ip', '')
            if ip:
                ip_events[ip].append(event)
        
        profiles = []
        
        for ip, ip_evts in ip_events.items():
            # Calculate risk score
            risk_score = 0
            behavior_tags = []
            
            # Unique techniques used
            techniques = set(e.get('mitre_technique_id', '') for e in ip_evts)
            risk_score += min(len(techniques) * 10, 50)  # +10 per technique, max 50
            
            # Check for specific behaviors
            reasons = ' '.join(e.get('reason', '').lower() for e in ip_evts)
            
            if 'brute' in reasons or 'failed' in reasons:
                behavior_tags.append('brute_forcer')
                risk_score += 20
            
            if 'port scan' in reasons or 'T1046' in techniques:
                behavior_tags.append('port_scanner')
                risk_score += 15
            
            if 'exfil' in reasons or 'T1041' in techniques:
                behavior_tags.append('data_exfiltrator')
                risk_score += 25
            
            # Check for kill chain correlation
            stages = set(e.get('attack_stage', '') for e in ip_evts)
            if len(stages) >= 3:
                risk_score += 30
                behavior_tags.append('kill_chain_actor')
            
            # Whitelist discount
            if ip in whitelist:
                risk_score = max(0, risk_score - 10)
            
            # Cap at 100
            risk_score = min(risk_score, 100)
            
            # Determine trust level
            if risk_score >= 70:
                trust_level = 'malicious'
            elif risk_score >= 50:
                trust_level = 'suspicious'
            elif risk_score >= 20:
                trust_level = 'neutral'
            else:
                trust_level = 'trusted'
            
            # Activity pattern (events per hour)
            activity_pattern = defaultdict(int)
            for e in ip_evts:
                try:
                    ts = datetime.fromisoformat(e.get('timestamp', '').replace('Z', '+00:00'))
                    activity_pattern[str(ts.hour)] += 1
                except:
                    pass
            
            threat_events = sum(1 for e in ip_evts if e.get('threat'))
            last_seen = max((e.get('timestamp', '') for e in ip_evts), default='')
            
            profiles.append({
                'ip': ip,
                'risk_score': risk_score,
                'behavior_tags': list(set(behavior_tags)),
                'trust_level': trust_level,
                'techniques_used': list(techniques),
                'total_events': len(ip_evts),
                'threat_events': threat_events,
                'activity_pattern': dict(activity_pattern),
                'last_seen': last_seen,
                'first_seen': min((e.get('timestamp', '') for e in ip_evts), default=''),
                'in_whitelist': ip in whitelist
            })
        
        try:
            os.makedirs(os.path.dirname(self.profiles_file), exist_ok=True)
            with open(self.profiles_file, 'w') as f:
                json.dump(profiles, f, indent=2)
        except Exception as e:
            print(f"Error saving profiles: {e}")

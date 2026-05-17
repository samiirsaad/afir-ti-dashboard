"""
Adaptive Thresholds Engine
Self-tuning detection thresholds based on performance
"""

import json
import os
from datetime import datetime, timedelta

class AdaptiveThresholdEngine:
    """Automatically adjust detection thresholds based on false positive and miss rates"""
    
    def __init__(self, config_file):
        self.config_file = config_file
        self.log_file = config_file.replace('config.json', 'adaptation_log.json')
        self.last_adaptation = None
        self.min_interval_hours = 1  # Minimum time between adaptations
    
    def get_log(self):
        """Get adaptation history log"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return []
    
    def _log_adaptation(self, threshold, old_value, new_value, reason):
        """Log an adaptation event"""
        log = self.get_log()
        log.append({
            'timestamp': datetime.now().isoformat(),
            'threshold': threshold,
            'old_value': old_value,
            'new_value': new_value,
            'reason': reason
        })
        
        # Keep only last 50 entries
        log = log[-50:]
        
        try:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            with open(self.log_file, 'w') as f:
                json.dump(log, f, indent=2)
        except Exception as e:
            print(f"Error logging adaptation: {e}")
    
    def should_adapt(self):
        """Check if enough time has passed since last adaptation"""
        if self.last_adaptation is None:
            return True
        
        elapsed = datetime.now() - self.last_adaptation
        return elapsed.total_seconds() >= (self.min_interval_hours * 3600)
    
    def analyze_and_adapt(self, events):
        """Analyze recent events and adapt thresholds if needed"""
        if not self.should_adapt():
            return {'adapted': False, 'reason': 'Too soon since last adaptation'}
        
        try:
            config = json.load(open(self.config_file, 'r'))
        except:
            return {'adapted': False, 'reason': 'Config not found'}
        
        # Filter last 24 hours
        cutoff = datetime.now() - timedelta(hours=24)
        recent_events = []
        for e in events:
            try:
                ts = datetime.fromisoformat(e.get('timestamp', '').replace('Z', '+00:00'))
                if ts >= cutoff:
                    recent_events.append(e)
            except:
                pass
        
        if len(recent_events) < 10:
            return {'adapted': False, 'reason': 'Insufficient data'}
        
        # Calculate metrics
        threats = [e for e in recent_events if e.get('threat')]
        false_positives = sum(1 for e in threats if e.get('false_positive', False))
        
        # Estimate miss rate (simplified - would need ground truth in production)
        high_fail_connections = sum(1 for e in recent_events 
                                    if e.get('features', {}).get('fail_count', 0) > 50 
                                    and not e.get('threat'))
        
        fp_rate = false_positives / len(threats) if threats else 0
        miss_rate = high_fail_connections / len(recent_events) if recent_events else 0
        
        adaptations = []
        
        # Adaptation logic
        if fp_rate > 0.2:  # More than 20% false positives
            old_val = config.get('failed_conn_threshold', 10)
            new_val = min(old_val + 2, 1000)  # Raise threshold
            if new_val != old_val:
                config['failed_conn_threshold'] = new_val
                adaptations.append(('failed_conn_threshold', old_val, new_val, f'High FP rate: {fp_rate:.1%}'))
        
        if miss_rate > 0.1:  # More than 10% potential misses
            old_val = config.get('lstm_anomaly_score', 0.5)
            new_val = max(old_val - 0.05, 0.01)  # Lower threshold
            if new_val != old_val:
                config['lstm_anomaly_score'] = new_val
                adaptations.append(('lstm_anomaly_score', old_val, new_val, f'High miss rate: {miss_rate:.1%}'))
        
        # Save if adaptations made
        if adaptations:
            try:
                with open(self.config_file, 'w') as f:
                    json.dump(config, f, indent=2)
                
                self.last_adaptation = datetime.now()
                
                for threshold, old_val, new_val, reason in adaptations:
                    self._log_adaptation(threshold, old_val, new_val, reason)
                
                return {
                    'adapted': True,
                    'adaptations': [
                        {'threshold': t, 'old': o, 'new': n, 'reason': r}
                        for t, o, n, r in adaptations
                    ]
                }
            except Exception as e:
                return {'adapted': False, 'reason': f'Save error: {e}'}
        
        return {'adapted': False, 'reason': 'No adaptation needed'}
    
    def reset_to_defaults(self):
        """Reset all thresholds to default values"""
        defaults = {
            "failed_conn_threshold": 10,
            "port_scan_threshold": 20,
            "traffic_volume_threshold": 1000,
            "lstm_anomaly_score": 0.5,
            "block_duration": 3600,
            "ml_weight": 0.7,
            "anthropic_key": "",
            "adaptive_thresholds_enabled": False
        }
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(defaults, f, indent=2)
            
            self._log_adaptation('ALL', 'various', 'defaults', 'Manual reset to defaults')
            self.last_adaptation = None
            
            return True
        except Exception as e:
            print(f"Error resetting thresholds: {e}")
            return False

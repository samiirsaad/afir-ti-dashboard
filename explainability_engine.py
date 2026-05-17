"""
Explainability Engine using SHAP
Provides explanations for ML model decisions
"""

class ExplainabilityEngine:
    """Generate SHAP-based explanations for threat detection decisions"""
    
    def __init__(self):
        self.feature_names = [
            'conn_count', 'fail_count', 'unique_ports', 'unique_dsts',
            'proto_tcp_ratio', 'proto_udp_ratio', 'avg_interval', 'burst_score'
        ]
    
    def get_explanation(self, event):
        """Get simple explanation for an event"""
        if not event:
            return "No data available"
        
        # Simulate SHAP analysis based on event features
        reasons = []
        
        score = event.get('hybrid_score', 0)
        fail_count = event.get('features', {}).get('fail_count', 0)
        burst_score = event.get('features', {}).get('burst_score', 0)
        unique_ports = event.get('features', {}).get('unique_ports', 0)
        
        if fail_count > 10:
            reasons.append("fail_count was high")
        if burst_score > 0.8:
            reasons.append("burst_score was critical")
        if unique_ports > 20:
            reasons.append("unique_ports was elevated")
        if score > 0.7:
            reasons.append("overall anomaly score exceeded threshold")
        
        if not reasons:
            reasons.append("multiple indicators exceeded normal thresholds")
        
        action = "Blocked" if event.get('threat') else "Monitored"
        return f"{action} because: {' + '.join(reasons[:3])}"
    
    def get_detailed_explanation(self, event):
        """Get detailed SHAP breakdown"""
        features = event.get('features', {})
        
        # Simulate SHAP values (in real implementation, use actual SHAP library)
        shap_values = {}
        for feature in self.feature_names:
            value = features.get(feature, 0)
            # Simulated contribution based on value magnitude
            if feature == 'fail_count':
                shap_values[feature] = min(value / 20, 1.0) * 0.4
            elif feature == 'burst_score':
                shap_values[feature] = value * 0.3
            elif feature == 'unique_ports':
                shap_values[feature] = min(value / 50, 1.0) * 0.2
            else:
                shap_values[feature] = abs(value - 0.5) * 0.1
        
        # Sort by absolute contribution
        sorted_features = sorted(shap_values.items(), key=lambda x: abs(x[1]), reverse=True)
        
        return {
            'event_id': event.get('event_id'),
            'explanation': self.get_explanation(event),
            'shap_breakdown': [
                {'feature': f, 'contribution': round(v, 3), 'impact': 'increased' if v > 0 else 'decreased'}
                for f, v in sorted_features
            ],
            'top_factors': [f for f, v in sorted_features[:3]]
        }

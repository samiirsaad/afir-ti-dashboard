"""
Attack Prediction Engine
Predicts future attacks based on historical patterns
"""

from datetime import datetime, timedelta
import json


class AttackPrediction:
    """Predict upcoming attacks using pattern analysis"""

    def __init__(self, events_file):
        self.events_file = events_file

    def get_predictions(self):
        """Generate attack predictions for IPs with sufficient history"""
        try:
            with open(self.events_file, "r") as f:
                events = json.load(f)
        except:
            return []

        # Group events by IP
        ip_events = {}
        for event in events:
            ip = event.get("src_ip", "")
            if ip:
                if ip not in ip_events:
                    ip_events[ip] = []
                ip_events[ip].append(event)

        predictions = []

        for ip, ip_evts in ip_events.items():
            # Need at least 5 events for prediction
            if len(ip_evts) < 5:
                continue

            # Analyze recent trend
            recent = ip_evts[-10:]
            scores = [e.get("hybrid_score", 0) for e in recent]

            # Calculate trend
            avg_recent = sum(scores[-5:]) / min(5, len(scores))
            avg_older = (
                sum(scores[:5]) / min(5, len(scores[:-5]))
                if len(scores) > 5
                else avg_recent
            )

            trend = avg_recent - avg_older

            # Predict attack type based on features
            pred_type, confidence, action = self._predict_attack_type(recent)

            if confidence > 0.5:  # Only show predictions with >50% confidence
                predictions.append(
                    {
                        "ip": ip,
                        "predicted_attack_type": pred_type,
                        "confidence": round(confidence * 100, 1),
                        "recommended_action": action,
                        "time_window": "next 30 minutes",
                        "trend": (
                            "increasing"
                            if trend > 0.1
                            else "stable" if trend > -0.1 else "decreasing"
                        ),
                        "recent_score_avg": round(avg_recent, 2),
                    }
                )

        # Sort by confidence
        predictions.sort(key=lambda x: x["confidence"], reverse=True)
        return predictions[:10]  # Return top 10 predictions

    def _predict_attack_type(self, recent_events):
        """Predict attack type based on recent event patterns"""

        # Analyze features
        avg_fail_count = sum(
            e.get("features", {}).get("fail_count", 0) for e in recent_events
        ) / len(recent_events)
        avg_unique_ports = sum(
            e.get("features", {}).get("unique_ports", 0) for e in recent_events
        ) / len(recent_events)
        avg_burst = sum(
            e.get("features", {}).get("burst_score", 0) for e in recent_events
        ) / len(recent_events)
        avg_conn = sum(
            e.get("features", {}).get("conn_count", 0) for e in recent_events
        ) / len(recent_events)

        # Determine likely attack type
        if avg_fail_count > 8:
            return (
                "Brute force continuing",
                0.75 + min(avg_fail_count / 50, 0.25),
                "pre-block",
            )

        if avg_unique_ports > 15:
            return (
                "Port scan likely",
                0.7 + min(avg_unique_ports / 100, 0.3),
                "alert only",
            )

        if avg_burst > 0.7 and avg_conn > 100:
            return "DDoS likely", 0.65 + min(avg_burst, 0.35), "pre-block"

        if avg_conn > 50 and avg_burst > 0.5:
            return "Traffic anomaly expected", 0.6, "monitor"

        # Check MITRE techniques
        techniques = [
            e.get("mitre_technique_id", "") for e in recent_events if e.get("threat")
        ]
        if techniques:
            most_common = max(set(techniques), key=techniques.count)
            return f"Continued {most_common} activity", 0.55, "monitor"

        return "No specific attack predicted", 0.3, "monitor"

    def hunt(self, filters, time_range, sort_by, limit):
        """Threat hunting query interface"""
        import time

        start_time = time.time()

        try:
            with open(self.events_file, "r") as f:
                events = json.load(f)
        except:
            return {"results": [], "total": 0, "execution_time_ms": 0}

        # Filter by time range
        now = datetime.now()
        if time_range == "1h":
            cutoff = now - timedelta(hours=1)
        elif time_range == "24h":
            cutoff = now - timedelta(hours=24)
        elif time_range == "7d":
            cutoff = now - timedelta(days=7)
        else:
            cutoff = None

        filtered = events
        if cutoff:
            filtered = []
            for e in events:
                try:
                    ts = datetime.fromisoformat(
                        e.get("timestamp", "").replace("Z", "+00:00")
                    )
                    if ts >= cutoff:
                        filtered.append(e)
                except:
                    pass

        # Apply filters
        for key, value in filters.items():
            if key == "src_ip" and value:
                filtered = [e for e in filtered if e.get("src_ip") == value]
            elif key == "dest_ip" and value:
                filtered = [e for e in filtered if e.get("dest_ip") == value]
            elif key == "threat":
                filtered = [e for e in filtered if e.get("threat") == value]
            elif key == "score_min":
                filtered = [
                    e for e in filtered if e.get("hybrid_score", 0) >= float(value)
                ]
            elif key == "score_max":
                filtered = [
                    e for e in filtered if e.get("hybrid_score", 0) <= float(value)
                ]
            elif key == "mitre_technique" and value:
                filtered = [e for e in filtered if e.get("mitre_technique_id") == value]
            elif key == "mitre_tactic" and value:
                filtered = [e for e in filtered if e.get("mitre_tactic") == value]
            elif key == "reason_contains" and value:
                filtered = [
                    e for e in filtered if value.lower() in e.get("reason", "").lower()
                ]

        # Sort
        if sort_by == "timestamp":
            filtered.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        elif sort_by == "hybrid_score":
            filtered.sort(key=lambda x: x.get("hybrid_score", 0), reverse=True)

        total = len(filtered)
        results = filtered[:limit]

        execution_time = (time.time() - start_time) * 1000

        return {
            "results": results,
            "total": total,
            "execution_time_ms": round(execution_time, 2),
            "filters_applied": filters,
            "time_range": time_range,
        }

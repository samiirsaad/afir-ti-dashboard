"""
Case Management System
Manages security cases for tracked threats
"""

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict


class CaseManager:
    """Manage security incident cases"""

    def __init__(self, cases_file, events_file):
        self.cases_file = cases_file
        self.events_file = events_file

    def get_cases(self, status=None):
        """Get all cases, optionally filtered by status"""
        try:
            with open(self.cases_file, "r") as f:
                cases = json.load(f)
        except:
            cases = []

        if status:
            cases = [c for c in cases if c.get("status") == status]

        return sorted(cases, key=lambda x: x.get("created_at", ""), reverse=True)

    def get_case(self, case_id):
        """Get single case by ID"""
        cases = self.get_cases()
        for case in cases:
            if case.get("id") == case_id:
                return case
        return None

    def create_case(self, event):
        """Create a new case from an event"""
        cases = self.get_cases()

        # Check if case already exists for this IP
        src_ip = event.get("src_ip", "")
        for case in cases:
            if case.get("src_ip") == src_ip and case.get("status") in [
                "open",
                "investigating",
            ]:
                # Add to existing case
                case["related_events"].append(event.get("event_id", ""))
                case["updated_at"] = datetime.now().isoformat()
                self._save_cases(cases)
                return case

        # Create new case
        case_id = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        new_case = {
            "id": case_id,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "title": f"Security Incident - {src_ip}",
            "status": "open",
            "severity": "high" if event.get("hybrid_score", 0) > 0.8 else "medium",
            "src_ip": src_ip,
            "related_events": [event.get("event_id", "")],
            "analyst_notes": [],
            "actions_taken": [],
            "resolution_summary": "",
            "mitre_technique": event.get("mitre_technique_id", ""),
        }

        cases.append(new_case)
        self._save_cases(cases)
        return new_case

    def add_note(self, case_id, note):
        """Add analyst note to case"""
        cases = self.get_cases()
        for case in cases:
            if case.get("id") == case_id:
                case["analyst_notes"].append(
                    {"timestamp": datetime.now().isoformat(), "note": note}
                )
                case["updated_at"] = datetime.now().isoformat()
                self._save_cases(cases)
                return True
        return False

    def update_status(self, case_id, status):
        """Update case status"""
        valid_statuses = ["open", "investigating", "resolved", "false_positive"]
        if status not in valid_statuses:
            return False

        cases = self.get_cases()
        for case in cases:
            if case.get("id") == case_id:
                case["status"] = status
                case["updated_at"] = datetime.now().isoformat()
                if status in ["resolved", "false_positive"]:
                    case["closed_at"] = datetime.now().isoformat()
                self._save_cases(cases)
                return True
        return False

    def _save_cases(self, cases):
        """Save cases to file"""
        try:
            os.makedirs(os.path.dirname(self.cases_file), exist_ok=True)
            with open(self.cases_file, "w") as f:
                json.dump(cases, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving cases: {e}")

    def reconstruct_incident(self, ip, from_ts=None, to_ts=None):
        """Reconstruct incident timeline for an IP"""
        try:
            with open(self.events_file, "r") as f:
                events = json.load(f)
        except:
            return {"error": "Events not found"}

        # Filter by IP
        ip_events = [e for e in events if e.get("src_ip") == ip]

        # Filter by time range
        if from_ts:
            try:
                from_dt = datetime.fromisoformat(from_ts.replace("Z", "+00:00"))
                ip_events = [
                    e
                    for e in ip_events
                    if datetime.fromisoformat(
                        e.get("timestamp", "").replace("Z", "+00:00")
                    )
                    >= from_dt
                ]
            except:
                pass

        if to_ts:
            try:
                to_dt = datetime.fromisoformat(to_ts.replace("Z", "+00:00"))
                ip_events = [
                    e
                    for e in ip_events
                    if datetime.fromisoformat(
                        e.get("timestamp", "").replace("Z", "+00:00")
                    )
                    <= to_dt
                ]
            except:
                pass

        # Sort by timestamp
        ip_events.sort(key=lambda x: x.get("timestamp", ""))

        if not ip_events:
            return {"timeline": [], "summary": {}}

        # Build timeline with phases
        phase_order = [
            "Reconnaissance",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ]

        timeline = []
        for i, event in enumerate(ip_events):
            stage = event.get("attack_stage", "Unknown")
            phase_idx = phase_order.index(stage) if stage in phase_order else -1

            timeline.append(
                {
                    "index": i,
                    "timestamp": event.get("timestamp"),
                    "phase": stage,
                    "phase_index": phase_idx,
                    "technique": event.get("mitre_technique_id", ""),
                    "score": event.get("hybrid_score", 0),
                    "threat": event.get("threat", False),
                    "reason": event.get("reason", ""),
                }
            )

        # Summary
        first_seen = ip_events[0].get("timestamp")
        last_seen = ip_events[-1].get("timestamp")
        first_alert = next(
            (e.get("timestamp") for e in ip_events if e.get("threat")), None
        )

        return {
            "ip": ip,
            "timeline": timeline,
            "summary": {
                "first_seen": first_seen,
                "last_seen": last_seen,
                "first_alert": first_alert,
                "total_events": len(ip_events),
                "threat_events": sum(1 for e in ip_events if e.get("threat")),
                "phases_observed": list(
                    set(e.get("attack_stage", "") for e in ip_events)
                ),
                "duration_minutes": self._calculate_duration(first_seen, last_seen),
            },
        }

    def _calculate_duration(self, start, end):
        """Calculate duration in minutes between two timestamps"""
        try:
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
            return int((end_dt - start_dt).total_seconds() / 60)
        except:
            return 0

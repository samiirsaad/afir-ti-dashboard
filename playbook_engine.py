"""
Playbook Automation Engine
Automated response playbooks for different attack types
"""

import json
import os
from datetime import datetime


class PlaybookEngine:
    """Automated security response playbooks"""

    def __init__(self, playbooks_file, log_file, cases_file):
        self.playbooks_file = playbooks_file
        self.log_file = log_file
        self.cases_file = cases_file
        self._init_default_playbooks()

    def _init_default_playbooks(self):
        """Initialize default playbooks if not exist"""
        try:
            with open(self.playbooks_file, "r") as f:
                json.load(f)
                return
        except:
            pass

        default_playbooks = {
            "brute_force_playbook": {
                "name": "Brute Force Response",
                "description": "Automated response to brute force attacks",
                "trigger": {
                    "reason_contains": ["failed connections", "brute"],
                    "score_min": 0.7,
                },
                "actions": ["block_ip", "create_case", "send_alert"],
                "enabled": True,
            },
            "port_scan_playbook": {
                "name": "Port Scan Response",
                "description": "Automated response to port scanning",
                "trigger": {"mitre_technique": "T1046"},
                "actions": ["block_ip", "create_case", "tag_entity"],
                "enabled": True,
            },
            "critical_score_playbook": {
                "name": "Critical Threat Response",
                "description": "Maximum response for critical threats",
                "trigger": {"score_min": 0.9},
                "actions": [
                    "block_ip_24h",
                    "create_critical_case",
                    "alert_all_channels",
                ],
                "enabled": True,
            },
        }

        try:
            os.makedirs(os.path.dirname(self.playbooks_file), exist_ok=True)
            with open(self.playbooks_file, "w") as f:
                json.dump(default_playbooks, f, indent=2)
        except Exception as e:
            print(f"Error initializing playbooks: {e}")

    def get_playbooks(self):
        """Get all playbooks"""
        try:
            with open(self.playbooks_file, "r") as f:
                return json.load(f)
        except:
            return {}

    def toggle_playbook(self, name):
        """Toggle playbook enabled status"""
        try:
            with open(self.playbooks_file, "r") as f:
                playbooks = json.load(f)

            if name in playbooks:
                playbooks[name]["enabled"] = not playbooks[name].get("enabled", True)

                with open(self.playbooks_file, "w") as f:
                    json.dump(playbooks, f, indent=2)
                return True
            return False
        except Exception as e:
            print(f"Error toggling playbook: {e}")
            return False

    def execute_playbook(self, event):
        """Execute matching playbooks for an event"""
        try:
            with open(self.playbooks_file, "r") as f:
                playbooks = json.load(f)
        except:
            return []

        executed = []

        for name, playbook in playbooks.items():
            if not playbook.get("enabled", True):
                continue

            # Check trigger conditions
            if self._matches_trigger(event, playbook.get("trigger", {})):
                # Execute actions
                actions_taken = []
                for action in playbook.get("actions", []):
                    result = self._execute_action(action, event)
                    actions_taken.append(result)

                # Log execution
                self._log_execution(name, event, actions_taken)
                executed.append({"playbook": name, "actions": actions_taken})

        return executed

    def _matches_trigger(self, event, trigger):
        """Check if event matches playbook trigger"""
        score = event.get("hybrid_score", 0)
        reason = event.get("reason", "").lower()
        technique = event.get("mitre_technique_id", "")

        if "score_min" in trigger and score < trigger["score_min"]:
            return False

        if "reason_contains" in trigger:
            if not any(t.lower() in reason for t in trigger["reason_contains"]):
                return False

        if "mitre_technique" in trigger:
            if technique != trigger["mitre_technique"]:
                return False

        return True

    def _execute_action(self, action, event):
        """Execute a single playbook action"""
        # In real implementation, these would call actual systems
        return f"Executed {action} for {event.get('src_ip', 'unknown')}"

    def _log_execution(self, playbook_name, event, actions):
        """Log playbook execution"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "playbook": playbook_name,
            "trigger_ip": event.get("src_ip", ""),
            "trigger_score": event.get("hybrid_score", 0),
            "actions": actions,
        }

        try:
            log = self.get_log(limit=100)
            log.append(log_entry)
            log = log[-100:]  # Keep last 100

            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            with open(self.log_file, "w") as f:
                json.dump(log, f, indent=2)
        except Exception as e:
            print(f"Error logging playbook execution: {e}")

    def get_log(self, limit=20):
        """Get playbook execution log"""
        try:
            with open(self.log_file, "r") as f:
                log = json.load(f)
            return log[-limit:]
        except:
            return []

"""
Threat Feed Manager
Integrates external threat intelligence feeds
"""

import json
import os
from datetime import datetime, timedelta
import urllib.request


class ThreatFeedManager:
    """Manage external threat intelligence feeds"""

    def __init__(self, status_file, events_file):
        self.status_file = status_file
        self.events_file = events_file
        self.feeds_dir = "/workspace/opt/firewall_irt/threat_feeds"
        self._init_status()

    def _init_status(self):
        """Initialize feed status tracking"""
        try:
            with open(self.status_file, "r") as f:
                json.load(f)
                return
        except:
            pass

        default_status = {
            "feodo_tracker": {
                "name": "Feodo Tracker",
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "last_update": None,
                "ip_count": 0,
                "enabled": True,
            }
        }

        try:
            os.makedirs(os.path.dirname(self.status_file), exist_ok=True)
            os.makedirs(self.feeds_dir, exist_ok=True)
            with open(self.status_file, "w") as f:
                json.dump(default_status, f, indent=2)
        except Exception as e:
            print(f"Error initializing feed status: {e}")

    def get_status(self):
        """Get status of all feeds"""
        try:
            with open(self.status_file, "r") as f:
                return json.load(f)
        except:
            return {}

    def update_feeds(self):
        """Update all enabled feeds"""
        try:
            with open(self.status_file, "r") as f:
                status = json.load(f)
        except:
            return {"error": "Status file not found"}

        results = {}

        for feed_name, feed_info in status.items():
            if not feed_info.get("enabled", True):
                continue

            try:
                # Download feed
                url = feed_info.get("url", "")
                if url:
                    req = urllib.request.Request(
                        url, headers={"User-Agent": "AFIR-TI/1.0"}
                    )
                    with urllib.request.urlopen(req, timeout=30) as response:
                        content = response.read().decode("utf-8")

                    # Parse IPs (skip comments)
                    ips = [
                        line.strip()
                        for line in content.split("\n")
                        if line.strip() and not line.startswith("#")
                    ]

                    # Save to file
                    feed_file = os.path.join(self.feeds_dir, f"{feed_name}.txt")
                    with open(feed_file, "w") as f:
                        f.write("\n".join(ips))

                    # Update status
                    status[feed_name]["last_update"] = datetime.now().isoformat()
                    status[feed_name]["ip_count"] = len(ips)

                    results[feed_name] = {"success": True, "ips_loaded": len(ips)}
            except Exception as e:
                results[feed_name] = {"success": False, "error": str(e)}

        # Save updated status
        try:
            with open(self.status_file, "w") as f:
                json.dump(status, f, indent=2)
        except:
            pass

        return results

    def check_ip_in_feeds(self, ip):
        """Check if an IP is in any threat feed"""
        try:
            with open(self.status_file, "r") as f:
                status = json.load(f)
        except:
            return None

        for feed_name, feed_info in status.items():
            if not feed_info.get("enabled", True):
                continue

            feed_file = os.path.join(self.feeds_dir, f"{feed_name}.txt")
            try:
                with open(feed_file, "r") as f:
                    feed_ips = [line.strip() for line in f.readlines()]

                if ip in feed_ips:
                    return {
                        "match": True,
                        "feed_name": feed_info.get("name", feed_name),
                    }
            except:
                continue

        return {"match": False}

    def enhance_event(self, event):
        """Enhance event with threat feed information"""
        src_ip = event.get("src_ip", "")
        feed_match = self.check_ip_in_feeds(src_ip)

        if feed_match and feed_match.get("match"):
            event["feed_match"] = True
            event["feed_name"] = feed_match.get("feed_name", "")
            # Boost score for known threats
            event["hybrid_score"] = min(event.get("hybrid_score", 0) + 0.3, 1.0)

        return event

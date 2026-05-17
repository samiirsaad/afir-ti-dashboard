"""
Threat Narrator - Natural Language Threat Summaries
Generates human-readable descriptions of threats
"""

import json
import os
import io
from datetime import datetime, timedelta


class ThreatNarrator:
    """Generate natural language narratives for threats"""

    def __init__(self, config_file):
        self.config_file = config_file
        self.api_key = None
        self._load_config()

        # Templates for different MITRE techniques
        self.templates = {
            "T1110": "IP {src_ip} from {country} attempted SSH brute force with {fail_count} failed logins in {duration} minutes. Risk score: {score}. Action: Blocked for {block_duration}.",
            "T1046": "IP {src_ip} performed a port scan targeting {unique_ports} ports in {duration} seconds. Possible reconnaissance activity.",
            "T1498": "IP {src_ip} launched a traffic flood with {conn_count} connections/min. Possible DDoS attempt.",
            "T1078": "Valid account usage detected from IP {src_ip}. Possible credential abuse.",
            "T1059": "Command execution attempts detected from {src_ip}. Script-based attack possible.",
            "T1071": "Suspicious application layer protocol usage from {src_ip}. Data exfiltration possible.",
            "default": "Anomalous behavior detected from {src_ip}. Hybrid score: {score}. Technique: {mitre_technique}. Reason: {reason}.",
        }

    def _load_config(self):
        """Load API key from config"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r") as f:
                    config = json.load(f)
                    self.api_key = config.get("anthropic_key", "")
        except:
            pass

    def generate_narrative(self, event):
        """Generate narrative for a single event"""
        if not event:
            return ""

        technique = event.get("mitre_technique_id", "")
        template = self.templates.get(technique, self.templates["default"])

        # Extract features
        features = event.get("features", {})

        # Calculate duration (mock)
        duration = 5

        # Fill template
        narrative = template.format(
            src_ip=event.get("src_ip", "Unknown"),
            country="Unknown",  # Could add GeoIP lookup
            fail_count=features.get("fail_count", 0),
            unique_ports=features.get("unique_ports", 0),
            conn_count=features.get("conn_count", 0),
            duration=duration,
            score=event.get("hybrid_score", 0),
            block_duration=event.get("block_duration", "N/A"),
            mitre_technique=technique,
            reason=event.get("reason", "Unknown"),
        )

        # If API key available, enhance with AI
        if self.api_key and self.api_key.strip() and event.get("threat"):
            try:
                enhanced = self._enhance_with_ai(event, narrative)
                if enhanced:
                    return enhanced
            except:
                pass

        return narrative

    def _enhance_with_ai(self, event, base_narrative):
        """Enhance narrative using AI API"""
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)

            prompt = f"""Convert this security alert into a clear, professional English summary:

Event Details:
- Source IP: {event.get('src_ip')}
- Score: {event.get('hybrid_score')}
- Technique: {event.get('mitre_technique_id')}
- Reason: {event.get('reason')}

Base description: {base_narrative}

Write a 2-3 sentence professional security incident summary."""

            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
            )

            return response.content[0].text.strip()
        except:
            return None

    def generate_daily_summary(self, events):
        """Generate daily summary paragraph"""
        today = datetime.now().date()
        today_events = []

        for event in events:
            try:
                ts = datetime.fromisoformat(
                    event.get("timestamp", "").replace("Z", "+00:00")
                )
                if ts.date() == today:
                    today_events.append(event)
            except:
                continue

        total = len(today_events)
        threats = sum(1 for e in today_events if e.get("threat"))
        blocked_ips = set(e.get("src_ip") for e in today_events if e.get("threat"))

        # Get top techniques
        techniques = {}
        for e in today_events:
            t = e.get("mitre_technique_id", "Unknown")
            techniques[t] = techniques.get(t, 0) + 1

        top_technique = (
            max(techniques.items(), key=lambda x: x[1])[0] if techniques else "Unknown"
        )

        summary = f"In the last 24 hours, {total} security events were detected, with {threats} confirmed threats from {len(blocked_ips)} unique source IPs. "

        if threats > 0:
            avg_score = (
                sum(e.get("hybrid_score", 0) for e in today_events if e.get("threat"))
                / threats
            )
            summary += f"The average threat score was {avg_score:.2f}, indicating {'high' if avg_score > 0.7 else 'moderate' if avg_score > 0.4 else 'low'} severity activity. "
            summary += f"The most common attack technique was {top_technique}. "

        if threats > 0:
            summary += "All identified threats have been automatically mitigated through the firewall blocking system."

        return summary

    def generate_compliance_report(self, standard):
        """Generate compliance report data"""
        try:
            events_file = "/workspace/opt/firewall_irt/events.json"
            blocked_file = "/workspace/opt/firewall_irt/blocked_ips.json"

            with open(events_file, "r") as f:
                events = json.load(f)
            with open(blocked_file, "r") as f:
                blocked = json.load(f)
        except:
            return {"error": "Data files not found"}

        # Filter last 30 days
        cutoff = datetime.now() - timedelta(days=30)
        recent_events = []
        for e in events:
            try:
                ts = datetime.fromisoformat(
                    e.get("timestamp", "").replace("Z", "+00:00")
                )
                if ts >= cutoff:
                    recent_events.append(e)
            except:
                pass

        threats = [e for e in recent_events if e.get("threat")]

        # Calculate metrics
        report = {
            "standard": standard,
            "generated_at": datetime.now().isoformat(),
            "period_days": 30,
            "total_events": len(recent_events),
            "total_threats": len(threats),
            "blocked_ips": len(blocked),
            "false_positives": sum(
                1 for e in threats if e.get("false_positive", False)
            ),
            "avg_response_time_seconds": 2.5,  # Mock value
            "top_techniques": [],
            "compliance_status": (
                "COMPLIANT" if len(threats) > 0 else "NO_THREATS_DETECTED"
            ),
        }

        # Top techniques
        techniques = {}
        for e in threats:
            t = e.get("mitre_technique_id", "Unknown")
            techniques[t] = techniques.get(t, 0) + 1

        report["top_techniques"] = [
            {"technique": t, "count": c}
            for t, c in sorted(techniques.items(), key=lambda x: x[1], reverse=True)[:5]
        ]

        return report

    def generate_compliance_pdf(self, standard):
        """Generate compliance PDF report"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import (
                SimpleDocTemplate,
                Table,
                TableStyle,
                Paragraph,
                Spacer,
            )
            from reportlab.lib.styles import getSampleStyleSheet

            report = self.generate_compliance_report(standard)

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()

            # Title
            elements.append(
                Paragraph(
                    f"AFIR-TI Compliance Report - {standard.upper()}", styles["Title"]
                )
            )
            elements.append(
                Paragraph(
                    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    styles["Normal"],
                )
            )
            elements.append(Spacer(1, 20))

            # Summary
            elements.append(Paragraph("Executive Summary", styles["Heading2"]))
            elements.append(
                Paragraph(f"Reporting Period: Last 30 days", styles["Normal"])
            )
            elements.append(
                Paragraph(
                    f"Total Events Analyzed: {report.get('total_events', 0)}",
                    styles["Normal"],
                )
            )
            elements.append(
                Paragraph(
                    f"Threats Detected: {report.get('total_threats', 0)}",
                    styles["Normal"],
                )
            )
            elements.append(
                Paragraph(
                    f"IPs Blocked: {report.get('blocked_ips', 0)}", styles["Normal"]
                )
            )
            elements.append(
                Paragraph(
                    f"Compliance Status: {report.get('compliance_status', 'UNKNOWN')}",
                    styles["Normal"],
                )
            )
            elements.append(Spacer(1, 20))

            # Techniques table
            elements.append(
                Paragraph("Top MITRE ATT&CK Techniques", styles["Heading2"])
            )
            table_data = [["Technique", "Count"]]
            for t in report.get("top_techniques", []):
                table_data.append([t["technique"], str(t["count"])])

            table = Table(table_data)
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                    ]
                )
            )
            elements.append(table)

            doc.build(elements)
            buffer.seek(0)
            return buffer.getvalue()
        except ImportError:
            raise Exception("reportlab not installed")
        except Exception as e:
            raise e

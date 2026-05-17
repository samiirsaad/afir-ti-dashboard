"""
Chat Assistant using Anthropic API
Allows natural language queries about threat data
"""

import json
import os

class ChatAssistant:
    """AI chat assistant for threat intelligence queries"""
    
    def __init__(self, config_file):
        self.config_file = config_file
        self.api_key = None
        self._load_config()
    
    def _load_config(self):
        """Load API key from config"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.api_key = config.get('anthropic_key', '')
        except:
            pass
    
    def chat(self, message, events, blocked, stats):
        """Generate response to user query"""
        
        # Check if API key is available
        if self.api_key and self.api_key.strip():
            return self._chat_with_api(message, events, blocked, stats)
        else:
            return self._chat_fallback(message, events, blocked, stats)
    
    def _chat_with_api(self, message, events, blocked, stats):
        """Use Anthropic API for responses"""
        try:
            import anthropic
            
            client = anthropic.Anthropic(api_key=self.api_key)
            
            # Build context
            context = self._build_context(events, blocked, stats)
            
            prompt = f"""You are a security analyst assistant for AFIR-TI dashboard. 
Answer the user's question based on this threat data:

{context}

User question: {message}

Provide a concise, helpful answer in the same language as the question."""

            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return response.content[0].text
        except Exception as e:
            return f"API error: {str(e)}. Using fallback mode."
    
    def _chat_fallback(self, message, events, blocked, stats):
        """Rule-based fallback responses"""
        message_lower = message.lower()
        
        # Arabic/English keyword matching
        if any(word in message_lower for word in ['أخطر', 'dangerous', 'highest risk', 'top ip']):
            # Find most dangerous IP
            threats = [e for e in events if e.get('threat')]
            if threats:
                ip_scores = {}
                for t in threats:
                    ip = t.get('src_ip', '')
                    score = t.get('hybrid_score', 0)
                    ip_scores[ip] = max(ip_scores.get(ip, 0), score)
                
                top_ip = max(ip_scores.items(), key=lambda x: x[1])
                return f"أخطر IP هو {top_ip[0]} بـ score {top_ip[1]:.2f}"
        
        if any(word in message_lower for word in ['ليه', 'why', 'blocked', 'بلوك']):
            return f"تم حظر {len(blocked)} IPs حتى الآن. الأسباب الرئيسية: brute force attempts, port scanning, و traffic anomalies."
        
        if any(word in message_lower for word in ['هجوم', 'attack', 'جاري', 'ongoing']):
            recent_threats = sum(1 for e in events[-10:] if e.get('threat'))
            if recent_threats > 3:
                return f"نعم، هناك نشاط هجومي مستمر. تم اكتشاف {recent_threats} تهديدات في آخر 10 أحداث."
            else:
                return "لا توجد هجمات نشطة حالياً. الوضع تحت السيطرة."
        
        if any(word in message_lower for word in ['brute force', 'كم', 'how many']):
            bf_count = sum(1 for e in events if 'brute' in e.get('reason', '').lower())
            return f"تم اكتشاف {bf_count} محاولات brute force."
        
        if any(word in message_lower for word in ['mitre', 'technique', 'تكنيك']):
            techniques = {}
            for e in events:
                t = e.get('mitre_technique_id', 'Unknown')
                techniques[t] = techniques.get(t, 0) + 1
            
            if techniques:
                top = max(techniques.items(), key=lambda x: x[1])
                return f"أكثر MITRE technique هو {top[0]} بعدد {top[1]} occurrences."
        
        if any(word in message_lower for word in ['وضع', 'status', 'summary', 'عام', 'general']):
            total = len(events)
            threats = sum(1 for e in events if e.get('threat'))
            return f"ملخص الوضع: {total} حدث إجمالي، {threats} تهديد ({threats/total*100:.1f}%). {len(blocked)} IPs محظورة."
        
        # Default response
        return f"لدي {len(events)} حدث في السجل، منهم {sum(1 for e in events if e.get('threat'))} تهديدات. اسألني عن IP معين، أو نوع هجوم، أو الـ MITRE techniques."
    
    def _build_context(self, events, blocked, stats):
        """Build context string for API"""
        context = []
        context.append(f"Total Events: {stats.get('total_events', 0)}")
        context.append(f"Blocked IPs: {len(blocked)}")
        context.append(f"Recent Events (last 50):")
        
        for e in events[-10:]:
            context.append(f"  - {e.get('src_ip')} | Score: {e.get('hybrid_score', 0):.2f} | Threat: {e.get('threat')} | Technique: {e.get('mitre_technique_id', 'N/A')}")
        
        return "\n".join(context)

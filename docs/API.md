# AFIR-TI API Documentation

Complete API reference for all endpoints.

## Base URL
```
http://localhost:5000/api
```

## Authentication
Currently, no authentication is required. For production deployments, implement API key or JWT authentication.

---

## Core Endpoints

### GET /events
Retrieve all detected security events.

**Response:**
```json
[
  {
    "id": "evt_001",
    "timestamp": "2024-01-15T10:30:00Z",
    "src_ip": "192.168.1.100",
    "dest_ip": "10.0.0.5",
    "threat": true,
    "hybrid_score": 0.85,
    "reason": "High failed connection count",
    "mitre_technique_id": "T1110",
    "mitre_tactic": "Credential Access",
    "attack_stage": "Initial Access",
    "explanation": "burst_score was critical + fail_count was high"
  }
]
```

### GET /blocked
Get currently blocked IP addresses.

**Response:**
```json
{
  "blocked_ips": [
    {"ip": "192.168.1.100", "blocked_at": "2024-01-15T10:30:00Z", "reason": "Brute force"}
  ]
}
```

### GET /timeline
Get 24-hour attack timeline data.

**Response:**
```json
[
  {"hour": "00:00", "threats": 5, "total": 12},
  {"hour": "01:00", "threats": 3, "total": 8}
]
```

---

## SIEM Features

### GET /correlated
Get correlated attack events.

### GET /baselines
Get behavioral baselines for all IPs.

### GET /cases
Get incident cases with optional status filter.

**Query Parameters:**
- `status` (optional): open, investigating, resolved, false_positive

### POST /cases/{id}/note
Add a note to an incident case.

**Request Body:**
```json
{"note": "Investigating suspicious activity"}
```

### POST /cases/{id}/status
Update case status.

**Request Body:**
```json
{"status": "resolved", "resolution_summary": "False positive confirmed"}
```

### GET /entities
Get UEBA entity profiles sorted by risk score.

### GET /entities/{ip}
Get specific entity profile.

### GET /playbooks
List all automation playbooks.

### POST /playbooks/{name}/toggle
Enable/disable a playbook.

### POST /hunt
Threat hunting query interface.

**Request Body:**
```json
{
  "filters": {"src_ip": "192.168.1.100", "threat": true},
  "time_range": "24h",
  "sort_by": "timestamp",
  "limit": 100
}
```

---

## AI Features

### GET /explain/{event_id}
Get SHAP explanation for an event.

### POST /chat
AI chat assistant.

**Request Body:**
```json
{"message": "What's the most dangerous IP today?"}
```

**Response:**
```json
{"reply": "The most dangerous IP is 192.168.1.100 with a risk score of 85..."}
```

### GET /predictions
Get attack predictions.

### GET /summary/today
Get daily threat summary.

### GET /adaptation-log
Get threshold adaptation history.

---

## Configuration

### GET /config
Get current system configuration.

### POST /config
Update configuration.

**Request Body:**
```json
{
  "failed_conn_threshold": 15,
  "port_scan_threshold": 20
}
```

### GET /whitelist
Get whitelisted IPs.

### POST /whitelist/add
Add IP to whitelist.

**Request Body:**
```json
{"ip": "192.168.1.50", "note": "Admin workstation"}
```

### POST /whitelist/remove
Remove IP from whitelist.

---

## Export

### GET /export/csv
Export events as CSV file.

### GET /export/pdf
Export PDF report.

### GET /export/compliance-pdf
Export compliance report PDF.

**Query Parameters:**
- `standard`: iso27001, basic

---

## Error Responses

All endpoints return errors in this format:

```json
{
  "error": "Error message description"
}
```

**HTTP Status Codes:**
- `200`: Success
- `400`: Bad Request
- `404`: Not Found
- `500`: Internal Server Error

---

## Rate Limiting
Currently no rate limiting. For production, implement rate limiting per IP.

## CORS
CORS is enabled for all origins. Restrict in production.

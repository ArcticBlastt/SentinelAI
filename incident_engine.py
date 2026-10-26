"""
SentinelAI Incident Engine
===========================

Turns raw detections (from the existing RF / Isolation Forest / port-scan
heuristic pipeline) into structured incidents, and runs an AI Incident
Response Copilot (Google Gemini, free tier, tool-calling) that investigates
each incident using only real evidence pulled from SentinelAI's own SQLite
event log — never fabricated telemetry.

Golden path this supports:
  Nmap scan -> detection -> INC-00N created -> Copilot investigates
  -> evidence + timeline -> classified as Network Service Scanning (T1046)
  -> severity assigned -> containment recommended -> human approves/rejects
"""

import json
import os
import sqlite3
import threading
import time
from datetime import datetime

import requests

DB_PATH = "sentinelai_history.db"   # same DB the main dashboard already writes events to

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
# gemini-2.0-flash is what caused the 404: Google's current model catalog
# (checked live against ai.google.dev/gemini-api/docs/pricing) no longer
# lists it, and a brand-new API key has no grandfathered access to it either
# way — the generateContent endpoint returns 404 for a model name a given
# key can't resolve, which looks identical to a typo at the HTTP level.
# gemini-3.5-flash-lite is in the current free-tier lineup and supports
# generateContent + function calling. If this ever stops being served,
# check the free-tier table at the URL above and swap the name in.
GEMINI_MODEL = "gemini-3.5-flash-lite"
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

MAX_AGENT_STEPS = 6   # cap tool-calling loop iterations (cost + safety)

db_lock = threading.Lock()


# ============================================================
# STATIC MITRE REFERENCE (kept intentionally small — only what
# the existing detector can actually produce)
# ============================================================

MITRE_TECHNIQUES = {
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery",
              "description": "Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation."},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact",
              "description": "Adversaries may perform Network Denial of Service attacks to degrade or block the availability of targeted resources to users."},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact",
              "description": "Adversaries may perform Endpoint Denial of Service attacks to degrade or block the availability of services to users."},
    "T1212": {"name": "Exploitation for Credential Access", "tactic": "Credential Access",
              "description": "Adversaries may exploit software vulnerabilities to collect credentials."},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control",
              "description": "Adversaries may communicate using application layer protocols to blend in with normal traffic."},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access",
              "description": "Adversaries may exploit a weakness in an internet-facing host or application."},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access",
              "description": "Adversaries may use brute force techniques to gain access to accounts."},
    "T1059": {"name": "Command and Scripting Injection", "tactic": "Execution",
              "description": "Adversaries may abuse command/script interpreters to execute commands."},
    "TA0043": {"name": "Unclassified Anomalous Behavior", "tactic": "Reconnaissance",
               "description": "Traffic that statistically deviates from established baseline behavior without matching a known attack signature."}
}


# ============================================================
# DB SETUP
# ============================================================

def init_incident_db():
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                source_ip TEXT,
                flow TEXT,
                attack_type TEXT,
                mitre_id TEXT,
                mitre_name TEXT,
                severity TEXT,
                confidence INTEGER,
                raw_detail TEXT,
                timeline_json TEXT,
                evidence_json TEXT,
                ai_assessment TEXT,
                recommended_action TEXT,
                human_decision TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS containment_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                action_taken TEXT NOT NULL,
                simulated INTEGER NOT NULL DEFAULT 1,
                outcome TEXT
            )
        """)
        conn.commit()
        conn.close()


init_incident_db()


def _next_incident_id():
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        conn.close()
    return f"INC-{count + 1:03d}"


# ============================================================
# INCIDENT CREATION
# ============================================================

def create_incident(event_type, flow_label, detail, source_ip, attack_type=None,
                     mitre_id=None, mitre_name=None, severity=None):
    """Called by the main detection pipeline whenever an attack/zero-day fires."""

    incident_id = _next_incident_id()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO incidents (id, created_at, updated_at, status, source_ip, flow, "
            "attack_type, mitre_id, mitre_name, severity, raw_detail) "
            "VALUES (?, ?, ?, 'NEW', ?, ?, ?, ?, ?, ?, ?)",
            (incident_id, now, now, source_ip, flow_label, attack_type, mitre_id, mitre_name, severity, detail)
        )
        conn.commit()
        conn.close()

    return incident_id


def _update_incident(incident_id, **fields):
    if not fields:
        return

    fields["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [incident_id]

    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(f"UPDATE incidents SET {set_clause} WHERE id = ?", values)
        conn.commit()
        conn.close()


def get_incident(incident_id):
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        conn.close()
    return dict(row) if row else None


def list_incidents(limit=50):
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            # created_at only has second resolution, so a fast scan can create several
            # incidents within the same second; rowid DESC breaks the tie so the
            # truly-last-created incident always sorts first, not an arbitrary one.
            "SELECT * FROM incidents ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
    return [dict(r) for r in rows]


def clear_all_incidents():
    """Wipes all incidents + containment log rows. Used by the dashboard's
    Clear button so repeated test runs don't pile up stale incidents."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM containment_log")
        conn.commit()
        conn.close()


def approve_incident(incident_id):
    _update_incident(incident_id, status="CONTAINED", human_decision="approved")


def reject_incident(incident_id):
    _update_incident(incident_id, status="CLOSED", human_decision="rejected")


# ============================================================
# INVESTIGATION TOOLS
# (These read ONLY real data already captured by the existing
#  detection pipeline. Nothing here is fabricated.)
# ============================================================

def get_network_activity(source_ip, minutes=60):
    """All flows involving this IP in the last N minutes."""
    cutoff = time.time() - (minutes * 60)

    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT timestamp, type, flow, detail FROM events "
            "WHERE source_ip = ? AND epoch >= ? ORDER BY epoch ASC",
            (source_ip, cutoff)
        ).fetchall()
        conn.close()

    flows = [dict(r) for r in rows]
    distinct_ports = set()
    for f in flows:
        if "->" in f["flow"]:
            dest_part = f["flow"].split("->")[-1].strip()
            if ":" in dest_part:
                distinct_ports.add(dest_part.split(":")[-1])

    return {
        "source_ip": source_ip,
        "window_minutes": minutes,
        "total_flows": len(flows),
        "distinct_destination_ports": len(distinct_ports),
        "ports_touched": sorted(distinct_ports),
        "flows": flows[-50:]   # cap payload size
    }


def get_previous_alerts(source_ip):
    """Prior attack/zero-day alerts from this same source IP."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT timestamp, type, detail, severity FROM events "
            "WHERE source_ip = ? AND type IN ('attacks','zero_day') "
            "ORDER BY epoch DESC LIMIT 20",
            (source_ip,)
        ).fetchall()
        conn.close()

    return {"source_ip": source_ip, "previous_alerts": [dict(r) for r in rows]}


def get_incident_details(incident_id):
    incident = get_incident(incident_id)
    if not incident:
        return {"error": f"No incident found with id {incident_id}"}
    return incident


def search_network_events(source_ip=None, event_type=None, limit=30):
    query = "SELECT timestamp, type, flow, source_ip, detail, severity FROM events WHERE 1=1"
    params = []

    if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)
    if event_type:
        query += " AND type = ?"
        params.append(event_type)

    query += " ORDER BY epoch DESC LIMIT ?"
    params.append(limit)

    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()
        conn.close()

    return {"matches": [dict(r) for r in rows]}


def get_host_information(ip):
    """Limited to what's actually derivable from captured traffic — no
    fabricated asset inventory, OS fingerprinting, etc."""

    is_private = (
        ip.startswith("192.168.") or ip.startswith("10.") or
        any(ip.startswith(f"172.{i}.") for i in range(16, 32))
    )

    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        total_seen = conn.execute(
            "SELECT COUNT(*) FROM events WHERE source_ip = ?", (ip,)
        ).fetchone()[0]
        conn.close()

    return {
        "ip": ip,
        "network_scope": "private/internal" if is_private else "external/public",
        "total_flows_seen_from_this_ip": total_seen,
        "note": "Limited to telemetry already captured by SentinelAI. No external asset inventory or threat intel is connected."
    }


def lookup_mitre_technique(technique_id):
    info = MITRE_TECHNIQUES.get(technique_id)
    if not info:
        return {"error": f"Unknown technique id {technique_id}"}
    return {"technique_id": technique_id, **info}


TOOL_FUNCTIONS = {
    "get_network_activity": get_network_activity,
    "get_previous_alerts": get_previous_alerts,
    "get_incident_details": get_incident_details,
    "search_network_events": search_network_events,
    "get_host_information": get_host_information,
    "lookup_mitre_technique": lookup_mitre_technique,
}

# Gemini's function-calling schema uses the same shape OpenAI/DeepSeek's does
# minus the "type":"function"/"function" wrapper, with JSON-Schema types
# written in uppercase (OBJECT/STRING/INTEGER/...) per Gemini's Schema proto.
GEMINI_TOOLS = [{
    "functionDeclarations": [
        {
            "name": "get_network_activity",
            "description": "Get all network flows involving a given source IP within a recent time window. Use this to see connection volume, ports touched, and timing.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "source_ip": {"type": "STRING", "description": "The IP address to investigate"},
                    "minutes": {"type": "INTEGER", "description": "How many minutes back to look (default 60)"}
                },
                "required": ["source_ip"]
            }
        },
        {
            "name": "get_previous_alerts",
            "description": "Get prior attack or zero-day alerts previously raised for this same source IP, to check if this is a repeat offender.",
            "parameters": {
                "type": "OBJECT",
                "properties": {"source_ip": {"type": "STRING"}},
                "required": ["source_ip"]
            }
        },
        {
            "name": "get_incident_details",
            "description": "Get the full stored details of a specific incident by its ID.",
            "parameters": {
                "type": "OBJECT",
                "properties": {"incident_id": {"type": "STRING"}},
                "required": ["incident_id"]
            }
        },
        {
            "name": "search_network_events",
            "description": "Search the raw event log with optional filters (source IP, event type) to find related activity.",
            "parameters": {
                "type": "OBJECT",
                "properties": {
                    "source_ip": {"type": "STRING"},
                    "event_type": {"type": "STRING", "description": "One of: attacks, zero_day, normal, skipped"},
                    "limit": {"type": "INTEGER"}
                }
            }
        },
        {
            "name": "get_host_information",
            "description": "Get what little is known about a host IP from captured traffic (private vs public, total flows seen). Does not fabricate OS/asset data.",
            "parameters": {
                "type": "OBJECT",
                "properties": {"ip": {"type": "STRING"}},
                "required": ["ip"]
            }
        },
        {
            "name": "lookup_mitre_technique",
            "description": "Look up the name, tactic, and description of a MITRE ATT&CK technique ID.",
            "parameters": {
                "type": "OBJECT",
                "properties": {"technique_id": {"type": "STRING"}},
                "required": ["technique_id"]
            }
        }
    ]
}]


# ============================================================
# GEMINI CLIENT
# ============================================================

def call_gemini(contents, system_instruction=None, tools=None):
    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY environment variable is not set.")

    payload = {"contents": contents}
    if system_instruction:
        payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}
    if tools:
        payload["tools"] = tools

    try:
        response = requests.post(
            GEMINI_URL,
            # Documented auth method for the Gemini API — the key travels in a
            # header, not the URL, so it never ends up in request logs.
            headers={"Content-Type": "application/json", "x-goog-api-key": GEMINI_API_KEY},
            json=payload,
            timeout=60
        )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Could not reach the Gemini API ({type(e).__name__}). Check your network connection.") from e

    if response.ok:
        data = response.json()
        # A blocked prompt (safety filters) returns HTTP 200 with no candidates —
        # this must not be treated as a normal "no tool calls" final answer.
        if not data.get("candidates"):
            block_reason = (data.get("promptFeedback") or {}).get("blockReason")
            if block_reason:
                raise RuntimeError(f"Gemini blocked this request (reason: {block_reason}).")
            raise RuntimeError("Gemini returned an empty response with no candidates.")
        return data

    # Non-2xx: pull Google's own error message/status out of the JSON body
    # (never the raw response text, so nothing stray — including the key,
    # which Google never echoes back anyway — leaks into the log).
    try:
        err = response.json().get("error", {})
        google_message = err.get("message", "")
        google_status = err.get("status", "")
    except ValueError:
        google_message, google_status = "", ""

    detail = f"{google_status}: {google_message}" if google_message else "no further detail from Google"

    if response.status_code == 401 or response.status_code == 403:
        raise RuntimeError(f"Gemini rejected the API key (HTTP {response.status_code}, {detail}). "
                            f"Check GEMINI_API_KEY is a valid, active Google AI Studio key.")
    if response.status_code == 404:
        raise RuntimeError(f"Gemini model '{GEMINI_MODEL}' was not found or not available to this key "
                            f"(HTTP 404, {detail}). Check the current free-tier model list at "
                            f"ai.google.dev/gemini-api/docs/pricing and update GEMINI_MODEL if needed.")
    if response.status_code == 429:
        raise RuntimeError(f"Gemini rate limit/quota exceeded (HTTP 429, {detail}). Wait a bit and retry.")
    if response.status_code == 400:
        raise RuntimeError(f"Gemini rejected the request as malformed (HTTP 400, {detail}).")

    raise RuntimeError(f"Gemini API error (HTTP {response.status_code}, {detail}).")


# ============================================================
# AI INCIDENT RESPONSE COPILOT (tool-calling agent loop)
# ============================================================

SYSTEM_PROMPT = """You are SentinelAI's AI Incident Response Copilot, assisting a SOC analyst.

You investigate security incidents using ONLY the tools provided. Never invent evidence,
IPs, timestamps, or activity that the tools did not return. If a tool returns no data,
say so plainly rather than guessing.

Your job for each incident:
1. Investigate the source IP's activity and history using the tools.
2. Correlate the evidence you gather.
3. Build a short chronological timeline of what happened.
4. Confirm or refine the attack classification and its MITRE ATT&CK technique.
5. Assign a severity (Critical/High/Medium/Low) and a confidence percentage (0-100),
   justified by the evidence you actually collected.
6. Recommend ONE specific containment action (e.g. "Block source IP at firewall",
   "Monitor only — insufficient evidence for containment", "Isolate host").

When you are done investigating, respond with ONLY a JSON object (no markdown, no
extra text) in exactly this shape:

{
  "timeline": [{"time": "...", "event": "..."}],
  "classification": "...",
  "mitre_id": "...",
  "mitre_name": "...",
  "severity": "Critical|High|Medium|Low",
  "confidence": 0-100,
  "explanation": "...",
  "recommended_action": "..."
}
"""


def investigate_incident(incident_id):
    """Runs the full tool-calling agent loop for one incident and persists the result."""

    incident = get_incident(incident_id)
    if not incident:
        return

    _update_incident(incident_id, status="INVESTIGATING")

    user_prompt = (
        f"Investigate incident {incident_id}.\n"
        f"Initial detection: source_ip={incident['source_ip']}, "
        f"flow={incident['flow']}, attack_type={incident['attack_type']}, "
        f"detail={incident['raw_detail']}\n\n"
        f"Use the tools to gather real evidence before concluding anything."
    )

    contents = [
        {"role": "user", "parts": [{"text": user_prompt}]}
    ]

    tool_log = []   # keeps a record of what evidence was actually pulled, for the evidence_json field

    try:
        for step in range(MAX_AGENT_STEPS):
            result = call_gemini(contents, system_instruction=SYSTEM_PROMPT, tools=GEMINI_TOOLS)

            candidates = result.get("candidates") or []
            if not candidates:
                raise RuntimeError(f"Gemini returned no candidates: {result}")

            candidate = candidates[0]
            model_content = candidate.get("content", {})
            parts = model_content.get("parts", [])
            finish_reason = candidate.get("finishReason", "")

            if not parts:
                # No usable content at all — e.g. finishReason SAFETY/RECITATION/
                # MAX_TOKENS/OTHER with nothing generated. Not a valid final
                # answer, so this must not be finalized as CLASSIFIED.
                raise RuntimeError(
                    f"Gemini returned no content (finishReason: {finish_reason or 'unknown'})."
                )

            function_calls = [p["functionCall"] for p in parts if "functionCall" in p]

            if not function_calls:
                # final answer — concatenate any text parts
                final_text = "".join(p.get("text", "") for p in parts).strip()
                if not final_text:
                    raise RuntimeError(
                        f"Gemini returned no text and no tool calls (finishReason: {finish_reason or 'unknown'})."
                    )
                _finalize_incident(incident_id, final_text, tool_log)
                return

            # record the model's turn (its function-call request) in history
            contents.append({"role": "model", "parts": parts})

            response_parts = []
            for call in function_calls:
                fn_name = call.get("name")
                fn_args = call.get("args") or {}

                fn = TOOL_FUNCTIONS.get(fn_name)
                if fn:
                    try:
                        tool_result = fn(**fn_args)
                    except Exception as e:
                        tool_result = {"error": str(e)}
                else:
                    tool_result = {"error": f"Unknown tool {fn_name}"}

                # sanitize to plain JSON-safe data before it goes back to Gemini
                safe_result = json.loads(json.dumps(tool_result, default=str))

                tool_log.append({"tool": fn_name, "args": fn_args, "result": safe_result})

                response_parts.append({
                    "functionResponse": {
                        "name": fn_name,
                        "response": {"result": safe_result}
                    }
                })

            # function results go back as a "user" turn, per Gemini's contents format
            contents.append({"role": "user", "parts": response_parts})

        # hit step cap without a final answer
        _update_incident(
            incident_id,
            status="CLASSIFIED",
            ai_assessment="Investigation stopped after reaching the maximum number of steps without a conclusive answer.",
            evidence_json=json.dumps(tool_log, default=str)
        )

    except Exception as e:
        _update_incident(
            incident_id,
            status="NEW",
            ai_assessment=f"Investigation failed: {e}",
            evidence_json=json.dumps(tool_log, default=str)
        )


def _finalize_incident(incident_id, final_text, tool_log):
    try:
        # strip accidental markdown fencing if the model adds it anyway
        cleaned = final_text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        _update_incident(
            incident_id,
            status="CLASSIFIED",
            ai_assessment=final_text,
            evidence_json=json.dumps(tool_log, default=str)
        )
        return

    _update_incident(
        incident_id,
        status="RESPONSE_RECOMMENDED",
        attack_type=parsed.get("classification"),
        mitre_id=parsed.get("mitre_id"),
        mitre_name=parsed.get("mitre_name"),
        severity=parsed.get("severity"),
        confidence=parsed.get("confidence"),
        timeline_json=json.dumps(parsed.get("timeline", []), default=str),
        evidence_json=json.dumps(tool_log, default=str),
        ai_assessment=parsed.get("explanation", ""),
        recommended_action=parsed.get("recommended_action", "")
    )


def investigate_incident_async(incident_id):
    """Fire-and-forget so the Flask request/detection loop isn't blocked."""
    thread = threading.Thread(target=investigate_incident, args=(incident_id,), daemon=True)
    thread.start()
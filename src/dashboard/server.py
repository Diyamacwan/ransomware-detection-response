"""
Flask dashboard server for the Ransomware Detection & Response System.

Endpoints
---------
  GET /                     → dashboard HTML page
  GET /api/events           → last N filesystem events (JSON)
  GET /api/alerts           → all alerts (JSON)
  GET /api/stats            → live summary stats (JSON)
  GET /api/stream/events    → SSE stream — one event per line
  GET /api/stream/alerts    → SSE stream — one alert per line
"""

import json
import time

from flask import Flask, Response, jsonify, render_template, request

from src.dashboard.store import alert_store, event_store

app = Flask(__name__, template_folder="templates")
app.config["JSON_SORT_KEYS"] = False


# ── page ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── REST endpoints ────────────────────────────────────────────────────────

@app.route("/api/events")
def api_events():
    n = min(int(request.args.get("n", 100)), 500)
    return jsonify(event_store.since(n))


@app.route("/api/alerts")
def api_alerts():
    return jsonify(alert_store.all())


@app.route("/api/stats")
def api_stats():
    events = event_store.all()
    alerts = alert_store.all()

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev = a.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Last 60 seconds of events for sparkline
    now = time.time()
    recent = [
        e for e in events
        if now - e.get("_ts", 0) <= 60
    ]

    avg_entropy = 0.0
    if recent:
        entropies = [e.get("entropy", 0.0) for e in recent]
        avg_entropy = round(sum(entropies) / len(entropies), 4)

    max_risk = 0
    if alerts:
        max_risk = max(a.get("risk_score", 0) for a in alerts)

    return jsonify({
        "total_events": event_store.count(),
        "total_alerts": alert_store.count(),
        "severity_counts": severity_counts,
        "avg_entropy_60s": avg_entropy,
        "max_risk_score": max_risk,
    })


# ── SSE helpers ───────────────────────────────────────────────────────────

def _sse_stream(store):
    """Generator that yields SSE-formatted messages from a store."""
    q = store.subscribe()
    try:
        # Send a heartbeat first so the browser connection opens.
        yield "data: {\"type\":\"ping\"}\n\n"
        while True:
            try:
                item = q.get(timeout=20)
                payload = json.dumps(item, default=str)
                yield f"data: {payload}\n\n"
            except Exception:
                # Timeout — send keep-alive ping.
                yield "data: {\"type\":\"ping\"}\n\n"
    finally:
        store.unsubscribe(q)


@app.route("/api/stream/events")
def stream_events():
    return Response(
        _sse_stream(event_store),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/stream/alerts")
def stream_alerts():
    return Response(
        _sse_stream(alert_store),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── standalone runner ─────────────────────────────────────────────────────

def start_server(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    """Start the Flask development server (blocking)."""
    app.run(host=host, port=port, debug=debug, use_reloader=False, threaded=True)

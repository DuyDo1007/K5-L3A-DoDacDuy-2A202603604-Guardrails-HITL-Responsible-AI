"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import time
import uuid


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store an input event and return its correlation ID."""
        correlation_id = request_id or uuid.uuid4().hex
        self._open[correlation_id] = {
            "request_id": correlation_id,
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "started_monotonic": time.perf_counter(),
        }
        return correlation_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete an audit event with the response and security decision."""
        correlation_id = request_id
        if correlation_id is None:
            matches = [
                key for key, entry in self._open.items()
                if entry.get("user_id") == user_id
            ]
            correlation_id = matches[-1] if matches else uuid.uuid4().hex

        pending = self._open.pop(correlation_id, None)
        now = time.perf_counter()
        entry = pending or {
            "request_id": correlation_id,
            "user_id": user_id,
            "input": None,
            "started_at": None,
            "started_monotonic": now,
        }
        started = entry.pop("started_monotonic", now)
        entry.update({
            "completed_at": utc_now_iso(),
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "latency_ms": round(max(0.0, now - started) * 1000, 3),
        })
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

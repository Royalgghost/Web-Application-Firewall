"""
ModSecurity Audit Logger
Generates standard ModSecurity SecAuditLog format sections (A, B, C, F, H, Z)
and maintains an in-memory/file-based log of transactions.
"""
from datetime import datetime
import json
from typing import Dict, List, Optional
from .models import AuditLogEntry, Transaction


class AuditLogger:
    """Manages audit logging for inspected transactions."""

    def __init__(self, max_entries: int = 500):
        self.max_entries = max_entries
        self.entries: List[AuditLogEntry] = []

    def log_transaction(self, tx: Transaction) -> AuditLogEntry:
        """Creates an audit log entry for a transaction and adds it to the log list."""
        raw_log = self.format_modsecurity_sec_audit_log(tx)

        matched_rules_data = []
        for m in tx.matches:
            matched_rules_data.append({
                "rule_id": m.rule_id,
                "variable_name": m.variable_name,
                "matched_data": m.matched_data,
                "message": m.message,
                "severity": m.severity,
                "anomaly_score": m.anomaly_score,
                "phase": m.phase,
            })

        entry = AuditLogEntry(
            transaction_id=tx.id,
            timestamp=tx.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            client_ip=tx.client_ip,
            method=tx.method,
            uri=tx.uri,
            headers=dict(tx.headers),
            body=tx.raw_body,
            response_status=tx.response_status,
            is_blocked=tx.is_blocked,
            anomaly_score=tx.anomaly_score,
            matched_rules=matched_rules_data,
            raw_audit_log=raw_log,
        )

        self.entries.insert(0, entry)
        if len(self.entries) > self.max_entries:
            self.entries.pop()

        return entry

    def format_modsecurity_sec_audit_log(self, tx: Transaction) -> str:
        """
        Formats a transaction into standard ModSecurity SecAuditLog format.
        Sections:
          --uuid-A-- (Header)
          --uuid-B-- (Request Headers)
          --uuid-C-- (Request Body)
          --uuid-F-- (Response Headers)
          --uuid-H-- (Audit Log Trailer with Rule Messages)
          --uuid-Z-- (End Marker)
        """
        boundary = tx.id
        lines = []

        # Section A: Header
        now_str = tx.timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(f"--{boundary}-A--")
        lines.append(f"[{now_str}] {tx.id} {tx.client_ip} {tx.client_port} 127.0.0.1 80")

        # Section B: Request Headers
        lines.append(f"--{boundary}-B--")
        lines.append(f"{tx.method} {tx.uri} {tx.http_version}")
        for k, v in tx.headers.items():
            lines.append(f"{k}: {v}")

        # Section C: Request Body (if any)
        if tx.raw_body:
            lines.append(f"--{boundary}-C--")
            lines.append(tx.raw_body)

        # Section F: Response Headers
        lines.append(f"--{boundary}-F--")
        status_text = "OK" if tx.response_status == 200 else ("Forbidden" if tx.response_status == 403 else "Response")
        lines.append(f"{tx.http_version} {tx.response_status} {status_text}")
        lines.append("Server: ModSecurity-Simulator/3.0 (Python-WSGI)")
        lines.append("Content-Type: text/html; charset=utf-8")

        # Section H: Audit Log Trailer
        lines.append(f"--{boundary}-H--")
        for m in tx.matches:
            rule_detail = (
                f'Message: [file "rules"] [line "N/A"] [id "{m.rule_id}"] '
                f'[msg "{m.message}"] [severity "{m.severity}"] '
                f'[data "Matched Data: {m.matched_data} found within {m.variable_name}"]'
            )
            lines.append(rule_detail)

        if tx.is_blocked:
            lines.append(
                f'Action: Intercepted (eval code 403) [reason "{tx.block_reason}"]'
            )
        lines.append(
            f"Stopwatch: 127.0.0.1 {int(tx.execution_time_ms * 1000)} (- - -)"
        )
        lines.append(f"Inbound Anomaly Score: {tx.anomaly_score}")

        # Section Z: Final Boundary
        lines.append(f"--{boundary}-Z--\n")

        return "\n".join(lines)

    def get_entries(self, limit: int = 50, filter_blocked_only: bool = False) -> List[AuditLogEntry]:
        """Returns recent audit log entries."""
        results = self.entries
        if filter_blocked_only:
            results = [e for e in results if e.is_blocked]
        return results[:limit]

    def clear(self):
        """Clears all audit log entries."""
        self.entries.clear()

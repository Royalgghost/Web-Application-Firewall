"""
ModSecurity WAF Models
Data structures representing rules, actions, transactions, match results, and audit logs.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class Transformation:
    """Represents a transformation function (e.g. t:urlDecode, t:lowercase)."""
    name: str

    def __str__(self) -> str:
        return f"t:{self.name}"


@dataclass
class RuleAction:
    """Represents an action associated with a SecRule or SecAction."""
    id: Optional[int] = None
    phase: int = 2  # default ModSecurity phase is 2 (request body)
    block: bool = False
    deny: bool = False
    pass_action: bool = False
    status: int = 403
    msg: str = ""
    log: bool = True
    auditlog: bool = True
    tag: List[str] = field(default_factory=list)
    severity: str = "WARNING"  # CRITICAL, HIGH, WARNING, NOTICE, INFO
    setvars: List[str] = field(default_factory=list)  # e.g. ["tx.anomaly_score=+5"]
    transformations: List[Transformation] = field(default_factory=list)
    raw_actions_str: str = ""


@dataclass
class SecRule:
    """Represents a parsed ModSecurity SecRule directive."""
    id: int
    variables: List[str]  # e.g. ["ARGS", "REQUEST_HEADERS:User-Agent", "REQUEST_URI"]
    operator: str  # e.g. "@rx", "!@rx", "@contains", "@pm", "@ipMatch"
    pattern: str  # regex pattern or argument string
    actions: RuleAction
    raw_directive: str = ""
    category: str = "custom"
    file_origin: str = "runtime"
    enabled: bool = True


@dataclass
class MatchResult:
    """Details of a single variable match against a rule operator."""
    rule_id: int
    variable_name: str
    variable_value: Any
    transformed_value: str
    transformations_applied: List[str]
    matched_pattern: str
    matched_data: str
    message: str
    severity: str
    anomaly_score: int = 0
    phase: int = 2


@dataclass
class Transaction:
    """Represents an HTTP transaction being inspected by the WAF."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    client_ip: str = "127.0.0.1"
    client_port: int = 8080
    method: str = "GET"
    uri: str = "/"
    path: str = "/"
    query_string: str = ""
    http_version: str = "HTTP/1.1"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    body_params: Dict[str, List[str]] = field(default_factory=dict)
    raw_body: str = ""
    json_body: Optional[Any] = None

    # Transaction variables (TX dictionary in ModSecurity)
    tx_vars: Dict[str, Any] = field(default_factory=dict)

    # Inspection results
    matches: List[MatchResult] = field(default_factory=list)
    is_blocked: bool = False
    block_reason: str = ""
    block_rule_id: Optional[int] = None
    response_status: int = 200
    execution_time_ms: float = 0.0

    # Inspection trace steps for visualizer
    trace_steps: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def anomaly_score(self) -> int:
        return int(self.tx_vars.get("anomaly_score", 0))

    @property
    def sql_injection_score(self) -> int:
        return int(self.tx_vars.get("sql_injection_score", 0))

    @property
    def xss_score(self) -> int:
        return int(self.tx_vars.get("xss_score", 0))

    @property
    def rce_score(self) -> int:
        return int(self.tx_vars.get("rce_score", 0))

    @property
    def lfi_score(self) -> int:
        return int(self.tx_vars.get("lfi_score", 0))

    @property
    def ssrf_score(self) -> int:
        return int(self.tx_vars.get("ssrf_score", 0))


@dataclass
class AuditLogEntry:
    """Represents a ModSecurity SecAuditLog entry."""
    transaction_id: str
    timestamp: str
    client_ip: str
    method: str
    uri: str
    headers: Dict[str, str]
    body: str
    response_status: int
    is_blocked: bool
    anomaly_score: int
    matched_rules: List[Dict[str, Any]]
    raw_audit_log: str = ""

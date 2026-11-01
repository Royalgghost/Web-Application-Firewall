"""
WAF Simulator REST APIs
Endpoints for request simulation, real-time statistics, rule management,
audit logging, configuration, and security benchmark execution.
"""
from flask import Blueprint, current_app, jsonify, request
import urllib.parse
from waf_core.models import Transaction

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/simulate", methods=["POST"])
def simulate():
    """Simulates an incoming HTTP request through the WAF engine."""
    engine = current_app.waf_engine
    data = request.get_json(force=True, silent=True) or {}

    method = data.get("method", "GET").upper()
    raw_uri = data.get("uri", "/")
    if not raw_uri.startswith("/"):
        raw_uri = "/" + raw_uri

    # Parse URI and query params
    parsed_url = urllib.parse.urlsplit(raw_uri)
    path = parsed_url.path or "/"
    query_string = parsed_url.query
    query_params = urllib.parse.parse_qs(query_string, keep_blank_values=True)

    # Headers
    headers = data.get("headers", {})
    if "Host" not in headers and "host" not in headers:
        headers["Host"] = "waf-simulator.local"
    if "User-Agent" not in headers and "user-agent" not in headers:
        headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WAF-Client/1.0"

    # Body
    raw_body = data.get("body", "")
    body_params = {}
    content_type = headers.get("Content-Type", headers.get("content-type", ""))

    if "application/x-www-form-urlencoded" in content_type:
        body_params = urllib.parse.parse_qs(raw_body, keep_blank_values=True)
    elif "application/json" in content_type:
        try:
            import json
            j_data = json.loads(raw_body)
            if isinstance(j_data, dict):
                for jk, jv in j_data.items():
                    body_params[jk] = [str(jv)]
        except Exception:
            pass

    client_ip = data.get("client_ip", "192.168.1.100")

    # Build and process Transaction
    tx = Transaction(
        client_ip=client_ip,
        method=method,
        uri=raw_uri,
        path=path,
        query_string=query_string,
        headers=headers,
        query_params=query_params,
        body_params=body_params,
        raw_body=raw_body,
    )

    engine.process_transaction(tx)

    # Format response
    matches_data = []
    for m in tx.matches:
        matches_data.append({
            "rule_id": m.rule_id,
            "variable_name": m.variable_name,
            "matched_data": m.matched_data,
            "message": m.message,
            "severity": m.severity,
            "anomaly_score": m.anomaly_score,
            "phase": m.phase,
            "transformations": m.transformations_applied,
            "transformed_value": m.transformed_value,
        })

    return jsonify({
        "transaction_id": tx.id,
        "is_blocked": tx.is_blocked,
        "status": tx.response_status,
        "block_reason": tx.block_reason,
        "anomaly_score": tx.anomaly_score,
        "threshold": engine.inbound_anomaly_score_threshold,
        "engine_mode": engine.engine_mode,
        "blocking_mode": engine.blocking_mode,
        "execution_time_ms": tx.execution_time_ms,
        "breakdown": {
            "sqli": tx.sql_injection_score,
            "xss": tx.xss_score,
            "rce": tx.rce_score,
            "lfi": tx.lfi_score,
            "ssrf": tx.ssrf_score,
        },
        "matches": matches_data,
        "trace_steps": tx.trace_steps,
        "sec_audit_log": engine.audit_logger.format_modsecurity_sec_audit_log(tx),
    })


@api_bp.route("/stats", methods=["GET"])
def get_stats():
    """Returns current real-time statistics of the WAF."""
    engine = current_app.waf_engine
    total = engine.stats["total_requests"]
    blocked = engine.stats["blocked_requests"]
    allowed = engine.stats["allowed_requests"]
    block_rate = round((blocked / total * 100), 1) if total > 0 else 0.0

    return jsonify({
        "total_requests": total,
        "blocked_requests": blocked,
        "allowed_requests": allowed,
        "block_rate": block_rate,
        "engine_mode": engine.engine_mode,
        "blocking_mode": engine.blocking_mode,
        "threshold": engine.inbound_anomaly_score_threshold,
        "attack_categories": engine.stats["attack_categories"],
        "active_rules_count": len([r for r in engine.rules.values() if r.enabled]),
        "total_rules_count": len(engine.rules),
    })


@api_bp.route("/rules", methods=["GET"])
def list_rules():
    """Lists all registered rules."""
    engine = current_app.waf_engine
    return jsonify({
        "rules": engine.get_rules_summary(),
        "total": len(engine.rules),
    })


@api_bp.route("/rules/<int:rule_id>/toggle", methods=["POST"])
def toggle_rule(rule_id: int):
    """Enables or disables an individual rule."""
    engine = current_app.waf_engine
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", True)
    if rule_id in engine.rules:
        engine.set_rule_enabled(rule_id, enabled)
        return jsonify({"success": True, "rule_id": rule_id, "enabled": enabled})
    return jsonify({"error": "Rule not found"}), 404


@api_bp.route("/rules/category/toggle", methods=["POST"])
def toggle_category():
    """Enables or disables an entire category of rules."""
    engine = current_app.waf_engine
    data = request.get_json(silent=True) or {}
    category = data.get("category", "")
    enabled = data.get("enabled", True)
    engine.set_category_enabled(category, enabled)
    return jsonify({"success": True, "category": category, "enabled": enabled})


@api_bp.route("/rules/custom", methods=["POST"])
def add_custom_rule():
    """Creates a new custom ModSecurity SecRule."""
    engine = current_app.waf_engine
    data = request.get_json(silent=True) or {}
    directive = data.get("directive", "").strip()

    if not directive.startswith("SecRule"):
        return jsonify({"error": "Directive must start with 'SecRule'"}), 400

    parsed_rules = engine.parser.parse_string(directive, file_origin="custom")
    if not parsed_rules:
        return jsonify({"error": "Failed to parse SecRule directive. Check syntax."}), 400

    new_rule = parsed_rules[0]
    engine.add_rule(new_rule)
    return jsonify({
        "success": True,
        "rule_id": new_rule.id,
        "msg": new_rule.actions.msg,
    })


@api_bp.route("/logs", methods=["GET"])
def get_logs():
    """Fetches audit logs with optional filtering."""
    engine = current_app.waf_engine
    blocked_only = request.args.get("blocked_only", "false").lower() == "true"
    limit = int(request.args.get("limit", 50))
    entries = engine.audit_logger.get_entries(limit=limit, filter_blocked_only=blocked_only)

    return jsonify({
        "logs": [
            {
                "transaction_id": e.transaction_id,
                "timestamp": e.timestamp,
                "client_ip": e.client_ip,
                "method": e.method,
                "uri": e.uri,
                "response_status": e.response_status,
                "is_blocked": e.is_blocked,
                "anomaly_score": e.anomaly_score,
                "matched_rules_count": len(e.matched_rules),
                "matched_rules": e.matched_rules,
                "raw_audit_log": e.raw_audit_log,
            }
            for e in entries
        ]
    })


@api_bp.route("/logs", methods=["DELETE"])
def clear_logs():
    """Clears all stored audit logs."""
    engine = current_app.waf_engine
    engine.audit_logger.clear()
    return jsonify({"success": True, "message": "Audit logs cleared"})


@api_bp.route("/config", methods=["GET", "POST"])
def config():
    """Gets or updates WAF configuration settings."""
    engine = current_app.waf_engine
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        if "engine_mode" in data and data["engine_mode"] in ("On", "DetectionOnly", "Off"):
            engine.engine_mode = data["engine_mode"]
        if "blocking_mode" in data and data["blocking_mode"] in ("anomaly_score", "immediate"):
            engine.blocking_mode = data["blocking_mode"]
        if "threshold" in data:
            try:
                engine.inbound_anomaly_score_threshold = int(data["threshold"])
            except ValueError:
                pass

    return jsonify({
        "engine_mode": engine.engine_mode,
        "blocking_mode": engine.blocking_mode,
        "inbound_anomaly_score_threshold": engine.inbound_anomaly_score_threshold,
    })


@api_bp.route("/benchmark", methods=["POST"])
def run_benchmark():
    """
    Executes an automated battery of tests (benign and malicious payloads)
    and computes sensitivity, specificity, accuracy, and confusion matrix.
    """
    engine = current_app.waf_engine

    # Ensure engine is On for benchmark
    orig_mode = engine.engine_mode
    engine.engine_mode = "On"

    test_cases = [
        # Benign Cases (Expect: ALLOWED)
        {"id": 1, "type": "Benign", "name": "Homepage Visit", "method": "GET", "uri": "/index.html", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": False},
        {"id": 2, "type": "Benign", "name": "Normal Search Query", "method": "GET", "uri": "/search?q=laptop+gaming+16gb", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": False},
        {"id": 3, "type": "Benign", "name": "Legitimate User Login", "method": "POST", "uri": "/login", "headers": {"Host": "app.local", "Content-Type": "application/x-www-form-urlencoded"}, "body": "username=alice&password=SecurePassword2026!", "expected_blocked": False},
        {"id": 4, "type": "Benign", "name": "Standard JSON API Post", "method": "POST", "uri": "/api/profile", "headers": {"Host": "app.local", "Content-Type": "application/json"}, "body": '{"name": "John Doe", "email": "john@example.com"}', "expected_blocked": False},
        {"id": 5, "type": "Benign", "name": "Normal Document Access", "method": "GET", "uri": "/view-file?file=report_2026.pdf", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": False},
        {"id": 6, "type": "Benign", "name": "External URL Preview", "method": "GET", "uri": "/fetch-url?url=https://news.ycombinator.com", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": False},
        {"id": 7, "type": "Benign", "name": "Benign IP Ping", "method": "POST", "uri": "/ping", "headers": {"Host": "app.local", "Content-Type": "application/x-www-form-urlencoded"}, "body": "ip=8.8.8.8", "expected_blocked": False},
        {"id": 8, "type": "Benign", "name": "Product Filter by ID", "method": "GET", "uri": "/products?category_id=42&sort=asc", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": False},
        {"id": 9, "type": "Benign", "name": "Standard Contact Form", "method": "POST", "uri": "/contact", "headers": {"Host": "app.local", "Content-Type": "application/x-www-form-urlencoded"}, "body": "subject=Billing+Question&msg=Hello+support+team", "expected_blocked": False},
        {"id": 10, "type": "Benign", "name": "Image Asset Request", "method": "GET", "uri": "/static/images/logo.png", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": False},

        # SQL Injection Cases (Expect: BLOCKED)
        {"id": 11, "type": "SQLi", "name": "Classic Boolean Auth Bypass", "method": "POST", "uri": "/login", "headers": {"Host": "app.local", "Content-Type": "application/x-www-form-urlencoded"}, "body": "username=admin'+OR+'1'='1&password=foo", "expected_blocked": True},
        {"id": 12, "type": "SQLi", "name": "Union-Based Database Extraction", "method": "GET", "uri": "/search?q=phone+UNION+SELECT+null,username,password+FROM+users", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},
        {"id": 13, "type": "SQLi", "name": "Time-Based Blind Probe (SLEEP)", "method": "GET", "uri": "/items?id=1+AND+(SELECT+SLEEP(5))", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},
        {"id": 14, "type": "SQLi", "name": "Destructive Stacked DROP TABLE", "method": "POST", "uri": "/items", "headers": {"Host": "app.local", "Content-Type": "application/x-www-form-urlencoded"}, "body": "name=test;+DROP+TABLE+users", "expected_blocked": True},
        {"id": 15, "type": "SQLi", "name": "Information Schema Query", "method": "GET", "uri": "/data?filter=1+UNION+SELECT+table_name+FROM+information_schema.tables", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},

        # Cross-Site Scripting (XSS) (Expect: BLOCKED)
        {"id": 16, "type": "XSS", "name": "Classic Script Tag Injection", "method": "GET", "uri": "/search?q=<script>alert(document.cookie)</script>", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},
        {"id": 17, "type": "XSS", "name": "Image Element Onerror Event", "method": "POST", "uri": "/comments", "headers": {"Host": "app.local", "Content-Type": "application/x-www-form-urlencoded"}, "body": 'comment=<img+src="nonexistent.jpg"+onerror="alert(1)">', "expected_blocked": True},
        {"id": 18, "type": "XSS", "name": "JavaScript Pseudo-Protocol", "method": "GET", "uri": "/redirect?target=javascript:alert(window.origin)", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},
        {"id": 19, "type": "XSS", "name": "SVG Onload Payload", "method": "POST", "uri": "/profile", "headers": {"Host": "app.local", "Content-Type": "application/x-www-form-urlencoded"}, "body": 'bio=<svg+onload=eval("alert(1)")>', "expected_blocked": True},
        {"id": 20, "type": "XSS", "name": "Iframe Source Vector", "method": "GET", "uri": "/embed?url=<iframe+src=//evil.com>", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},

        # Remote Code Execution (RCE) (Expect: BLOCKED)
        {"id": 21, "type": "RCE", "name": "Semicolon Shell Command Chaining", "method": "POST", "uri": "/ping", "headers": {"Host": "app.local", "Content-Type": "application/x-www-form-urlencoded"}, "body": "ip=127.0.0.1;+whoami", "expected_blocked": True},
        {"id": 22, "type": "RCE", "name": "Pipe Command Execution", "method": "POST", "uri": "/ping", "headers": {"Host": "app.local", "Content-Type": "application/x-www-form-urlencoded"}, "body": "ip=127.0.0.1|+cat+/etc/passwd", "expected_blocked": True},
        {"id": 23, "type": "RCE", "name": "PowerShell Command Launch", "method": "GET", "uri": "/exec?cmd=powershell+-command+Get-Process", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},
        {"id": 24, "type": "RCE", "name": "Unix /bin/sh Direct Path Execution", "method": "POST", "uri": "/run", "headers": {"Host": "app.local", "Content-Type": "application/x-www-form-urlencoded"}, "body": "prog=/bin/bash+-c+id", "expected_blocked": True},

        # Local File Inclusion (LFI) (Expect: BLOCKED)
        {"id": 25, "type": "LFI", "name": "Directory Traversal /etc/passwd", "method": "GET", "uri": "/view-file?file=../../../../etc/passwd", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},
        {"id": 26, "type": "LFI", "name": "Windows System File (win.ini)", "method": "GET", "uri": "/view-file?file=..\\..\\windows\\win.ini", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},
        {"id": 27, "type": "LFI", "name": "Dangerous PHP Filter Wrapper", "method": "GET", "uri": "/load?page=php://filter/convert.base64-encode/resource=index.php", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},

        # SSRF (Expect: BLOCKED)
        {"id": 28, "type": "SSRF", "name": "AWS Instance Metadata Endpoint", "method": "GET", "uri": "/fetch-url?url=http://169.254.169.254/latest/meta-data/", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},
        {"id": 29, "type": "SSRF", "name": "Localhost Port Scanning via SSRF", "method": "GET", "uri": "/fetch-url?url=http://127.0.0.1:8080/admin", "headers": {"Host": "app.local"}, "body": "", "expected_blocked": True},

        # Security Scanner / Protocol (Expect: BLOCKED)
        {"id": 30, "type": "Scanner", "name": "Automated Scanner (sqlmap)", "method": "GET", "uri": "/test", "headers": {"Host": "app.local", "User-Agent": "sqlmap/1.6#stable"}, "body": "", "expected_blocked": True},
    ]

    results = []
    tp = fp = tn = fn = 0

    for tc in test_cases:
        parsed_url = urllib.parse.urlsplit(tc["uri"])
        q_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
        b_params = {}
        if tc["body"]:
            b_params = urllib.parse.parse_qs(tc["body"], keep_blank_values=True)

        tx = Transaction(
            client_ip="10.0.0.50",
            method=tc["method"],
            uri=tc["uri"],
            path=parsed_url.path,
            query_string=parsed_url.query,
            headers=tc["headers"],
            query_params=q_params,
            body_params=b_params,
            raw_body=tc["body"],
        )
        engine.process_transaction(tx)

        actual_blocked = tx.is_blocked
        expected_blocked = tc["expected_blocked"]
        passed = (actual_blocked == expected_blocked)

        if expected_blocked:
            if actual_blocked:
                tp += 1
                classification = "True Positive"
            else:
                fn += 1
                classification = "False Negative"
        else:
            if not actual_blocked:
                tn += 1
                classification = "True Negative"
            else:
                fp += 1
                classification = "False Positive"

        results.append({
            "id": tc["id"],
            "type": tc["type"],
            "name": tc["name"],
            "method": tc["method"],
            "uri": tc["uri"],
            "expected_blocked": expected_blocked,
            "actual_blocked": actual_blocked,
            "passed": passed,
            "classification": classification,
            "anomaly_score": tx.anomaly_score,
            "matches_count": len(tx.matches),
            "latency_ms": tx.execution_time_ms,
        })

    # Restore original mode
    engine.engine_mode = orig_mode

    total_tests = len(test_cases)
    accuracy = round(((tp + tn) / total_tests) * 100, 1)
    sensitivity = round((tp / (tp + fn)) * 100, 1) if (tp + fn) > 0 else 0.0
    specificity = round((tn / (tn + fp)) * 100, 1) if (tn + fp) > 0 else 0.0
    precision = round((tp / (tp + fp)) * 100, 1) if (tp + fp) > 0 else 0.0

    return jsonify({
        "metrics": {
            "total_tests": total_tests,
            "accuracy": accuracy,
            "sensitivity": sensitivity,
            "specificity": specificity,
            "precision": precision,
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
        },
        "results": results,
    })

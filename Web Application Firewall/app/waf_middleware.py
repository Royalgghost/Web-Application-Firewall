"""
Flask WAF Middleware
Intercepts incoming HTTP requests, converts them into WAF Transactions,
and evaluates them against the ModSecurityEngine.
"""
from flask import Request, Response, g, render_template, request, jsonify
from typing import Optional
from waf_core.engine import ModSecurityEngine
from waf_core.models import Transaction


class WAFMiddleware:
    """WSGI / Flask Request Interceptor for ModSecurity WAF."""

    def __init__(self, engine: ModSecurityEngine):
        self.engine = engine

    def inspect_request(self) -> Optional[Response]:
        """
        Flask before_request hook.
        Inspects requests targeting the protected application routes.
        Returns 403 Response if blocked, or None to proceed.
        """
        # Only inspect /app/ routes or when explicit header is passed
        # Allow dashboard and management API routes to function without blocking themselves
        if not request.path.startswith("/app"):
            return None

        # Build Transaction from Flask request
        tx = self.build_transaction_from_request(request)

        # Run inspection through ModSecurity engine
        self.engine.process_transaction(tx)
        g.waf_transaction = tx

        if tx.is_blocked:
            # Check if JSON was requested
            if request.headers.get("Accept") == "application/json" or request.is_json:
                return jsonify({
                    "error": "Forbidden by Web Application Firewall (ModSecurity)",
                    "status": 403,
                    "transaction_id": tx.id,
                    "anomaly_score": tx.anomaly_score,
                    "reason": tx.block_reason,
                    "matches": [
                        {
                            "rule_id": m.rule_id,
                            "msg": m.message,
                            "severity": m.severity,
                            "matched_data": m.matched_data,
                            "variable": m.variable_name,
                        }
                        for m in tx.matches
                    ],
                }), 403

            # Render authentic ModSecurity 403 Forbidden page
            return render_template(
                "block_page.html",
                tx=tx,
                client_ip=tx.client_ip,
                anomaly_score=tx.anomaly_score,
                threshold=self.engine.inbound_anomaly_score_threshold,
                block_reason=tx.block_reason,
                rule_id=tx.block_rule_id or (tx.matches[0].rule_id if tx.matches else 949110),
                matches=tx.matches,
            ), 403

        return None

    def build_transaction_from_request(self, req: Request) -> Transaction:
        """Converts a Flask Request object into a WAF Transaction."""
        # Query parameters
        query_params = {}
        for k, v in req.args.lists():
            query_params[k] = list(v)

        # Body parameters (form)
        body_params = {}
        if req.form:
            for k, v in req.form.lists():
                body_params[k] = list(v)

        # Raw body
        try:
            raw_body = req.get_data(as_text=True)
        except Exception:
            raw_body = ""

        # JSON body handling
        json_body = None
        if req.is_json:
            try:
                json_body = req.get_json(silent=True)
                if isinstance(json_body, dict):
                    for jk, jv in json_body.items():
                        body_params.setdefault(jk, []).append(str(jv))
            except Exception:
                pass

        # Headers
        headers = dict(req.headers)

        # Cookies
        cookies = dict(req.cookies)

        tx = Transaction(
            client_ip=req.remote_addr or "127.0.0.1",
            method=req.method,
            uri=req.full_path.rstrip("?"),
            path=req.path,
            query_string=req.query_string.decode("utf-8", errors="ignore"),
            http_version=req.environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
            headers=headers,
            cookies=cookies,
            query_params=query_params,
            body_params=body_params,
            raw_body=raw_body,
            json_body=json_body,
        )
        return tx

"""
ModSecurity WAF Engine
Core engine executing ModSecurity rule phases, variable extraction, transformations,
anomaly scoring, and block/pass decisions.
"""
import glob
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from .audit_logger import AuditLogger
from .models import MatchResult, RuleAction, SecRule, Transaction
from .operators import OperatorEvaluator
from .parser import ModSecurityParser
from .transformations import apply_transformations


class ModSecurityEngine:
    """The central WAF engine."""

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: Dict[int, SecRule] = {}
        self.rules_phase1: List[SecRule] = []
        self.rules_phase2: List[SecRule] = []

        self.operator_evaluator = OperatorEvaluator()
        self.parser = ModSecurityParser()
        self.audit_logger = AuditLogger()

        # Engine settings
        self.engine_mode = "On"  # "On", "DetectionOnly", "Off"
        self.blocking_mode = "anomaly_score"  # "anomaly_score" or "immediate"
        self.inbound_anomaly_score_threshold = 5

        # Statistics
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "allowed_requests": 0,
            "attack_categories": {
                "SQL Injection": 0,
                "Cross-Site Scripting (XSS)": 0,
                "Remote Code Execution (RCE)": 0,
                "Local File Inclusion (LFI)": 0,
                "SSRF": 0,
                "Scanner Detection": 0,
                "Protocol Enforcement": 0,
                "Custom Rule": 0,
            },
        }

        if rules_dir and os.path.exists(rules_dir):
            self.load_rules_directory(rules_dir)

    def load_rules_directory(self, rules_dir: str):
        """Loads all .conf files from the specified directory in sorted order."""
        conf_files = sorted(glob.glob(os.path.join(rules_dir, "*.conf")))
        for conf_file in conf_files:
            parsed = self.parser.parse_file(conf_file)
            for rule in parsed:
                self.add_rule(rule)

    def add_rule(self, rule: SecRule):
        """Adds a rule and organizes it into phase lists."""
        self.rules[rule.id] = rule
        self._rebuild_phase_lists()

    def remove_rule(self, rule_id: int):
        """Removes a rule by ID."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            self._rebuild_phase_lists()

    def set_rule_enabled(self, rule_id: int, enabled: bool):
        """Enables or disables an individual rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = enabled

    def set_category_enabled(self, category: str, enabled: bool):
        """Enables or disables all rules in a category."""
        for rule in self.rules.values():
            if rule.category.lower() == category.lower():
                rule.enabled = enabled

    def _rebuild_phase_lists(self):
        """Rebuilds sorted phase 1 and phase 2 rule lists."""
        self.rules_phase1 = [
            r for r in self.rules.values() if r.actions.phase == 1
        ]
        self.rules_phase2 = [
            r for r in self.rules.values() if r.actions.phase >= 2
        ]
        # Sort so initialization rules run first and blocking evaluation runs last
        self.rules_phase1.sort(key=lambda r: r.id)
        self.rules_phase2.sort(key=lambda r: r.id)

    def process_transaction(self, tx: Transaction) -> Transaction:
        """
        Runs the full ModSecurity inspection lifecycle on a transaction:
        1. Initialization
        2. Phase 1 (Request Headers & URI)
        3. Phase 2 (Request Body & Parameters)
        4. Blocking evaluation (Anomaly scoring)
        5. Decision determination
        6. Audit logging & Statistics update
        """
        start_time = time.perf_counter()
        self.stats["total_requests"] += 1

        # Check if WAF engine is Off
        if self.engine_mode == "Off":
            tx.is_blocked = False
            tx.response_status = 200
            tx.execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
            tx.trace_steps.append({
                "phase": "Bypass",
                "title": "WAF Disabled (SecRuleEngine Off)",
                "details": "Traffic allowed through without perimeter inspection.",
                "status": "bypassed",
            })
            self.stats["allowed_requests"] += 1
            self.audit_logger.log_transaction(tx)
            return tx

        # Initialize Transaction variables (TX)
        tx.tx_vars["anomaly_score"] = 0
        tx.tx_vars["inbound_anomaly_score_threshold"] = self.inbound_anomaly_score_threshold
        tx.tx_vars["sql_injection_score"] = 0
        tx.tx_vars["xss_score"] = 0
        tx.tx_vars["rce_score"] = 0
        tx.tx_vars["lfi_score"] = 0
        tx.tx_vars["ssrf_score"] = 0

        # Phase 1: Headers & Request Line Inspection
        phase1_matches = self._execute_phase(tx, self.rules_phase1, phase_num=1)
        tx.trace_steps.append({
            "phase": "Phase 1: Request Headers & URI",
            "title": "Inspecting URI, Headers, Method",
            "evaluated_rules_count": len(self.rules_phase1),
            "matches_count": len(phase1_matches),
            "matches": [
                {
                    "rule_id": m.rule_id,
                    "msg": m.message,
                    "target": m.variable_name,
                    "score": m.anomaly_score,
                }
                for m in phase1_matches
            ],
            "status": "warning" if phase1_matches else "pass",
        })

        # Check for immediate block in Phase 1 if in immediate blocking mode
        if self.blocking_mode == "immediate" and any(m for m in phase1_matches if self.rules[m.rule_id].actions.block or self.rules[m.rule_id].actions.deny):
            if self.engine_mode == "On":
                tx.is_blocked = True
                tx.response_status = 403
                tx.block_reason = phase1_matches[0].message
                tx.block_rule_id = phase1_matches[0].rule_id

        # Phase 2: Request Body & Arguments Inspection (if not already blocked)
        if not tx.is_blocked:
            phase2_matches = self._execute_phase(tx, self.rules_phase2, phase_num=2)
            tx.trace_steps.append({
                "phase": "Phase 2: Request Body & Parameters",
                "title": "Inspecting Query Params, POST Body, Cookies",
                "evaluated_rules_count": len(self.rules_phase2),
                "matches_count": len(phase2_matches),
                "matches": [
                    {
                        "rule_id": m.rule_id,
                        "msg": m.message,
                        "target": m.variable_name,
                        "score": m.anomaly_score,
                    }
                    for m in phase2_matches
                ],
                "status": "warning" if phase2_matches else "pass",
            })

            # Check for immediate block in Phase 2 if in immediate blocking mode
            if self.blocking_mode == "immediate" and any(m for m in phase2_matches if self.rules[m.rule_id].actions.block or self.rules[m.rule_id].actions.deny):
                if self.engine_mode == "On":
                    tx.is_blocked = True
                    tx.response_status = 403
                    blocking_m = next(m for m in phase2_matches if self.rules[m.rule_id].actions.block or self.rules[m.rule_id].actions.deny)
                    tx.block_reason = blocking_m.message
                    tx.block_rule_id = blocking_m.rule_id

        # Anomaly Score Blocking Evaluation (CRS Phase 2 Evaluation)
        current_score = tx.anomaly_score
        threshold = tx.tx_vars.get("inbound_anomaly_score_threshold", self.inbound_anomaly_score_threshold)

        if self.blocking_mode == "anomaly_score":
            if current_score >= threshold:
                if self.engine_mode == "On":
                    tx.is_blocked = True
                    tx.response_status = 403
                    tx.block_rule_id = 949110
                    tx.block_reason = f"Inbound Anomaly Score Exceeded (Total Score: {current_score}, Threshold: {threshold})"
                elif self.engine_mode == "DetectionOnly":
                    tx.block_reason = f"[DetectionOnly] Inbound Anomaly Score Exceeded (Total Score: {current_score}, Threshold: {threshold})"

        # Final Decision Trace
        tx.trace_steps.append({
            "phase": "Decision & Scoring",
            "title": f"Final Decision: {'BLOCKED (403)' if tx.is_blocked else 'ALLOWED (200)'}",
            "anomaly_score": current_score,
            "threshold": threshold,
            "blocking_mode": self.blocking_mode,
            "engine_mode": self.engine_mode,
            "status": "blocked" if tx.is_blocked else "allowed",
            "reason": tx.block_reason if tx.is_blocked else "Request passed all inspection criteria.",
        })

        # Update stats
        if tx.is_blocked:
            self.stats["blocked_requests"] += 1
        else:
            self.stats["allowed_requests"] += 1

        for m in tx.matches:
            rule = self.rules.get(m.rule_id)
            if rule and rule.category in self.stats["attack_categories"]:
                self.stats["attack_categories"][rule.category] += 1

        tx.execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        self.audit_logger.log_transaction(tx)
        return tx

    def _execute_phase(self, tx: Transaction, rules: List[SecRule], phase_num: int) -> List[MatchResult]:
        """Evaluates a list of rules for a specific phase."""
        phase_matches: List[MatchResult] = []

        for rule in rules:
            if not rule.enabled:
                continue

            # Special case for SecAction (unconditional actions)
            if rule.variables == ["TX"] and rule.pattern == ".*":
                self._execute_rule_actions(rule, tx, matched_data="", target_name="TX")
                continue

            # Extract target variables
            targets = self._extract_variables(tx, rule.variables)
            rule_matched = False

            for target_name, target_value in targets:
                # Apply transformations
                trans_names = [t.name for t in rule.actions.transformations]
                transformed = apply_transformations(target_value, trans_names)

                # Evaluate operator
                matched, matched_data = self.operator_evaluator.evaluate(
                    rule.operator,
                    rule.pattern,
                    transformed,
                    tx_vars=tx.tx_vars,
                )

                if matched:
                    rule_matched = True
                    match_result = MatchResult(
                        rule_id=rule.id,
                        variable_name=target_name,
                        variable_value=target_value,
                        transformed_value=transformed,
                        transformations_applied=trans_names,
                        matched_pattern=rule.pattern,
                        matched_data=matched_data,
                        message=rule.actions.msg,
                        severity=rule.actions.severity,
                        anomaly_score=self._calculate_rule_anomaly_points(rule),
                        phase=phase_num,
                    )
                    tx.matches.append(match_result)
                    phase_matches.append(match_result)

                    # Execute actions (setvars, score increments)
                    self._execute_rule_actions(rule, tx, matched_data, target_name)
                    # Only match once per rule to prevent duplicate score inflation
                    break

        return phase_matches

    def _calculate_rule_anomaly_points(self, rule: SecRule) -> int:
        """Determines the anomaly score points added by this rule."""
        for sv in rule.actions.setvars:
            if "anomaly_score=+" in sv.lower():
                try:
                    return int(sv.split("+")[1].strip())
                except Exception:
                    pass
        # Fallback based on severity
        sev = rule.actions.severity.upper()
        if sev == "CRITICAL":
            return 5
        elif sev == "HIGH":
            return 4
        elif sev == "WARNING":
            return 3
        elif sev == "NOTICE":
            return 2
        return 1

    def _execute_rule_actions(self, rule: SecRule, tx: Transaction, matched_data: str, target_name: str):
        """Applies actions such as setvar to update transaction variables."""
        for sv in rule.actions.setvars:
            # Format: 'tx.anomaly_score=+5' or 'tx.sql_injection_score=+5' or 'tx.var=val'
            clean_sv = sv.strip().replace("'", "").replace('"', "")
            if "=" in clean_sv:
                var_key, var_val = clean_sv.split("=", 1)
                var_key = var_key.strip()
                if var_key.lower().startswith("tx."):
                    var_name = var_key[3:].strip()
                    if var_val.startswith("+"):
                        # Increment integer
                        try:
                            inc = int(var_val[1:])
                            curr = int(tx.tx_vars.get(var_name, 0))
                            tx.tx_vars[var_name] = curr + inc
                        except (ValueError, TypeError):
                            pass
                    else:
                        # Auto-convert numeric strings to int/float if possible
                        try:
                            tx.tx_vars[var_name] = int(var_val)
                        except ValueError:
                            try:
                                tx.tx_vars[var_name] = float(var_val)
                            except ValueError:
                                tx.tx_vars[var_name] = var_val

    def _extract_variables(self, tx: Transaction, variable_specs: List[str]) -> List[Tuple[str, Any]]:
        """
        Extracts variable values from the transaction based on ModSecurity variable names:
        - REQUEST_URI
        - REQUEST_FILENAME / REQUEST_PATH
        - QUERY_STRING
        - REQUEST_METHOD
        - REMOTE_ADDR
        - REQUEST_HEADERS, REQUEST_HEADERS:Header-Name, REQUEST_HEADERS_NAMES
        - REQUEST_COOKIES, REQUEST_COOKIES:CookieName
        - ARGS, ARGS_GET, ARGS_POST, ARGS_NAMES
        - REQUEST_BODY
        - TX:var_name
        """
        targets: List[Tuple[str, Any]] = []

        for spec in variable_specs:
            spec = spec.strip()
            if not spec:
                continue

            # Sub-key access (e.g. REQUEST_HEADERS:User-Agent)
            sub_key = None
            main_var = spec
            if ":" in spec:
                main_var, sub_key = spec.split(":", 1)
                main_var = main_var.strip().upper()
                sub_key = sub_key.strip()
            else:
                main_var = main_var.upper()

            if main_var == "REQUEST_URI":
                targets.append(("REQUEST_URI", tx.uri))
            elif main_var in ("REQUEST_FILENAME", "REQUEST_PATH"):
                targets.append(("REQUEST_FILENAME", tx.path))
            elif main_var == "QUERY_STRING":
                targets.append(("QUERY_STRING", tx.query_string))
            elif main_var == "REQUEST_METHOD":
                targets.append(("REQUEST_METHOD", tx.method))
            elif main_var == "REMOTE_ADDR":
                targets.append(("REMOTE_ADDR", tx.client_ip))
            elif main_var == "REQUEST_BODY":
                if tx.raw_body:
                    targets.append(("REQUEST_BODY", tx.raw_body))

            elif main_var == "REQUEST_HEADERS":
                if sub_key:
                    # Look up specific header case-insensitively
                    for hk, hv in tx.headers.items():
                        if hk.lower() == sub_key.lower():
                            targets.append((f"REQUEST_HEADERS:{hk}", hv))
                            break
                else:
                    for hk, hv in tx.headers.items():
                        targets.append((f"REQUEST_HEADERS:{hk}", hv))

            elif main_var == "REQUEST_HEADERS_NAMES":
                for hk in tx.headers.keys():
                    targets.append(("REQUEST_HEADERS_NAMES", hk))

            elif main_var == "REQUEST_COOKIES":
                if sub_key:
                    if sub_key in tx.cookies:
                        targets.append((f"REQUEST_COOKIES:{sub_key}", tx.cookies[sub_key]))
                else:
                    for ck, cv in tx.cookies.items():
                        targets.append((f"REQUEST_COOKIES:{ck}", cv))

            elif main_var in ("ARGS", "ARGS_GET", "ARGS_POST"):
                # Collect params
                pool: Dict[str, List[str]] = {}
                if main_var in ("ARGS", "ARGS_GET"):
                    for k, vals in tx.query_params.items():
                        pool.setdefault(k, []).extend(vals)
                if main_var in ("ARGS", "ARGS_POST"):
                    for k, vals in tx.body_params.items():
                        pool.setdefault(k, []).extend(vals)

                if sub_key:
                    if sub_key in pool:
                        for item in pool[sub_key]:
                            targets.append((f"{main_var}:{sub_key}", item))
                else:
                    for k, val_list in pool.items():
                        for item in val_list:
                            targets.append((f"{main_var}:{k}", item))

            elif main_var == "ARGS_NAMES":
                all_keys = set(tx.query_params.keys()) | set(tx.body_params.keys())
                for k in all_keys:
                    targets.append(("ARGS_NAMES", k))

            elif main_var == "TX":
                if sub_key:
                    sub_key_clean = sub_key.lower().replace("tx.", "")
                    val = tx.tx_vars.get(sub_key_clean, "")
                    targets.append((f"TX:{sub_key}", str(val)))
                else:
                    targets.append(("TX:anomaly_score", str(tx.anomaly_score)))

        return targets

    def get_rules_summary(self) -> List[Dict[str, Any]]:
        """Returns metadata for all registered rules for UI display."""
        summary = []
        for r in sorted(self.rules.values(), key=lambda x: x.id):
            summary.append({
                "id": r.id,
                "category": r.category,
                "variables": ", ".join(r.variables),
                "operator": r.operator,
                "pattern": r.pattern,
                "phase": r.actions.phase,
                "severity": r.actions.severity,
                "msg": r.actions.msg,
                "enabled": r.enabled,
                "file_origin": r.file_origin,
                "points": self._calculate_rule_anomaly_points(r),
                "raw_directive": r.raw_directive,
            })
        return summary

"""
ModSecurity Operators Implementation
Supports @rx, @pm, @contains, @streq, @beginsWith, @endsWith, @gt, @ge, @lt, @le, @eq, @ipMatch, and their negations (!@...).
"""
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple


class OperatorEvaluator:
    """Evaluates ModSecurity operators against input values."""

    def __init__(self):
        self._compiled_regexes: Dict[str, re.Pattern] = {}

    def get_or_compile_regex(self, pattern: str) -> Optional[re.Pattern]:
        if pattern in self._compiled_regexes:
            return self._compiled_regexes[pattern]
        try:
            # ModSecurity patterns often expect case-insensitive or multiline behavior
            compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
            self._compiled_regexes[pattern] = compiled
            return compiled
        except re.error as err:
            # If pattern has syntax issues with Python regex, attempt fallback
            try:
                # Sometimes patterns have escaped slashes \/ or POSIX classes [:alnum:]
                cleaned = pattern.replace(r"\/", "/")
                compiled = re.compile(cleaned, re.IGNORECASE | re.DOTALL)
                self._compiled_regexes[pattern] = compiled
                return compiled
            except Exception:
                return None

    def evaluate(
        self,
        operator: str,
        pattern: str,
        value: Any,
        tx_vars: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Evaluates operator against the given value.
        Returns:
            (matched: bool, matched_data: str)
        """
        op = operator.strip()
        is_negated = False
        if op.startswith("!"):
            is_negated = True
            op = op[1:].strip()

        # Default operator in ModSecurity is @rx if omitted
        if not op:
            op = "@rx"

        op_lower = op.lower()

        # Convert value to string for text operators
        str_val = "" if value is None else str(value)

        matched = False
        matched_data = ""

        # Resolve pattern if referencing tx variables (e.g. @ge %{tx.inbound_anomaly_score_threshold})
        resolved_pattern = pattern
        if tx_vars and "%{tx." in resolved_pattern.lower():
            for k, v in tx_vars.items():
                macro = f"%{{tx.{k}}}"
                if macro.lower() in resolved_pattern.lower():
                    # Case-insensitive replacement
                    pattern_re = re.compile(re.escape(macro), re.IGNORECASE)
                    resolved_pattern = pattern_re.sub(str(v), resolved_pattern)

        if op_lower == "@rx":
            regex = self.get_or_compile_regex(resolved_pattern)
            if regex:
                match = regex.search(str_val)
                if match:
                    matched = True
                    matched_data = match.group(0)

        elif op_lower == "@pm":
            # Parallel match against space/comma separated list of terms
            terms = [t.strip().lower() for t in re.split(r"[\s,]+", resolved_pattern) if t.strip()]
            val_lower = str_val.lower()
            for term in terms:
                if term and term in val_lower:
                    matched = True
                    matched_data = term
                    break

        elif op_lower == "@contains":
            pattern_lower = resolved_pattern.lower()
            if pattern_lower in str_val.lower():
                matched = True
                matched_data = resolved_pattern

        elif op_lower == "@streq":
            if str_val.lower() == resolved_pattern.lower():
                matched = True
                matched_data = str_val

        elif op_lower == "@beginswith":
            if str_val.lower().startswith(resolved_pattern.lower()):
                matched = True
                matched_data = resolved_pattern

        elif op_lower == "@endswith":
            if str_val.lower().endswith(resolved_pattern.lower()):
                matched = True
                matched_data = resolved_pattern

        elif op_lower in ("@gt", "@ge", "@lt", "@le", "@eq"):
            try:
                num_val = float(str_val)
                # target threshold
                target_val = float(resolved_pattern.strip())
                if op_lower == "@gt" and num_val > target_val:
                    matched = True
                elif op_lower == "@ge" and num_val >= target_val:
                    matched = True
                elif op_lower == "@lt" and num_val < target_val:
                    matched = True
                elif op_lower == "@le" and num_val <= target_val:
                    matched = True
                elif op_lower == "@eq" and num_val == target_val:
                    matched = True
                if matched:
                    matched_data = f"{num_val} {op_lower} {target_val}"
            except (ValueError, TypeError):
                matched = False

        elif op_lower == "@ipmatch":
            # Match client IP against single IP or CIDR (e.g. 192.168.1.0/24 or 127.0.0.1)
            try:
                client_ip_obj = ipaddress.ip_address(str_val.strip())
                targets = [t.strip() for t in resolved_pattern.split(",") if t.strip()]
                for target in targets:
                    try:
                        if "/" in target:
                            net = ipaddress.ip_network(target, strict=False)
                            if client_ip_obj in net:
                                matched = True
                                matched_data = f"{client_ip_obj} in {net}"
                                break
                        else:
                            single_ip = ipaddress.ip_address(target)
                            if client_ip_obj == single_ip:
                                matched = True
                                matched_data = str(single_ip)
                                break
                    except ValueError:
                        continue
            except ValueError:
                matched = False

        else:
            # Fallback to regex match
            regex = self.get_or_compile_regex(resolved_pattern)
            if regex:
                match = regex.search(str_val)
                if match:
                    matched = True
                    matched_data = match.group(0)

        if is_negated:
            matched = not matched
            if matched and not matched_data:
                matched_data = f"Not match ({op} {resolved_pattern})"

        return matched, matched_data

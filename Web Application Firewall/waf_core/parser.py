"""
ModSecurity Configuration Parser
Parses authentic ModSecurity configuration files (.conf) and SecRule / SecAction directives.
"""
import os
import re
import shlex
from typing import List, Optional, Tuple
from .models import RuleAction, SecRule, Transformation


class ModSecurityParser:
    """Parses ModSecurity directives from strings or .conf files."""

    def __init__(self):
        self.default_action = RuleAction(phase=2, log=True, auditlog=True, pass_action=True)

    def parse_file(self, filepath: str) -> List[SecRule]:
        """Parses a .conf file and returns a list of SecRules."""
        if not os.path.exists(filepath):
            return []
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return self.parse_string(content, file_origin=os.path.basename(filepath))

    def parse_string(self, content: str, file_origin: str = "runtime") -> List[SecRule]:
        """Parses a string containing ModSecurity configuration directives."""
        lines = self._preprocess_lines(content)
        rules: List[SecRule] = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("SecRule "):
                rule = self._parse_sec_rule(line, file_origin)
                if rule:
                    rules.append(rule)
            elif line.startswith("SecAction "):
                rule = self._parse_sec_action(line, file_origin)
                if rule:
                    rules.append(rule)

        return rules

    def _preprocess_lines(self, content: str) -> List[str]:
        """Handles comments and line continuations (\\ at end of line)."""
        raw_lines = content.splitlines()
        processed_lines: List[str] = []
        current_buffer = ""

        for line in raw_lines:
            stripped = line.strip()
            if not current_buffer and (not stripped or stripped.startswith("#")):
                continue

            # Strip inline comment if not in quotes (simple check)
            if stripped.endswith("\\"):
                current_buffer += " " + stripped[:-1].strip()
            else:
                if current_buffer:
                    current_buffer += " " + stripped
                    processed_lines.append(current_buffer.strip())
                    current_buffer = ""
                else:
                    processed_lines.append(stripped)

        if current_buffer:
            processed_lines.append(current_buffer.strip())

        return processed_lines

    def _parse_sec_rule(self, line: str, file_origin: str) -> Optional[SecRule]:
        """
        Parses a single SecRule line:
        SecRule VARIABLES "OPERATOR PATTERN" "ACTIONS"
        or
        SecRule VARIABLES "PATTERN" "ACTIONS"
        """
        # Strip 'SecRule' keyword
        rest = line[len("SecRule"):].strip()
        tokens = self._tokenize_directive(rest)
        if len(tokens) < 3:
            return None

        var_spec = tokens[0]
        operator_and_pattern = tokens[1]
        actions_spec = tokens[2]

        variables = [v.strip() for v in var_spec.split("|") if v.strip()]
        operator, pattern = self._extract_operator_and_pattern(operator_and_pattern)
        actions = self._parse_actions(actions_spec)

        rule_id = actions.id if actions.id is not None else 999999
        category = self._infer_category(file_origin, actions)

        return SecRule(
            id=rule_id,
            variables=variables,
            operator=operator,
            pattern=pattern,
            actions=actions,
            raw_directive=line,
            category=category,
            file_origin=file_origin,
            enabled=True,
        )

    def _parse_sec_action(self, line: str, file_origin: str) -> Optional[SecRule]:
        """
        Parses a SecAction line (executes unconditionally on phase).
        SecAction "id:...,phase:...,setvar:..."
        """
        rest = line[len("SecAction"):].strip()
        tokens = self._tokenize_directive(rest)
        if not tokens:
            return None

        actions_spec = tokens[0]
        actions = self._parse_actions(actions_spec)
        rule_id = actions.id if actions.id is not None else 999998
        category = self._infer_category(file_origin, actions)

        # Represent SecAction as a rule that matches everything on variable TX (dummy)
        return SecRule(
            id=rule_id,
            variables=["TX"],
            operator="@rx",
            pattern=".*",
            actions=actions,
            raw_directive=line,
            category=category,
            file_origin=file_origin,
            enabled=True,
        )

    def _tokenize_directive(self, text: str) -> List[str]:
        """Tokenizes directive arguments respecting single and double quotes."""
        tokens = []
        try:
            # shlex handles quotes well, but we need POSIX mode without escaping escapes
            lexer = shlex.shlex(text, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            tokens = list(lexer)
        except Exception:
            # Fallback regex tokenization if shlex encounters unescaped symbols
            matches = re.findall(r'"([^"]*)"|\'([^\']*)\'|(\S+)', text)
            tokens = [m[0] or m[1] or m[2] for m in matches]
        return tokens

    def _extract_operator_and_pattern(self, op_pat: str) -> Tuple[str, str]:
        """Splits operator and pattern. E.g. '@rx ^admin' -> ('@rx', '^admin')."""
        op_pat = op_pat.strip()
        if op_pat.startswith("@") or op_pat.startswith("!@"):
            parts = op_pat.split(" ", 1)
            op = parts[0]
            pat = parts[1] if len(parts) > 1 else ""
            return op, pat
        # Default operator is @rx
        return "@rx", op_pat

    def _parse_actions(self, actions_str: str) -> RuleAction:
        """Parses comma-separated action list, preserving quoted arguments."""
        action = RuleAction(raw_actions_str=actions_str)

        # Split actions by comma, but not commas inside quotes
        action_parts = self._split_actions(actions_str)

        for part in action_parts:
            part = part.strip()
            if not part:
                continue

            if part == "block":
                action.block = True
            elif part == "deny":
                action.deny = True
            elif part == "pass":
                action.pass_action = True
            elif part == "log":
                action.log = True
            elif part == "nolog":
                action.log = False
            elif part == "auditlog":
                action.auditlog = True
            elif part.startswith("id:"):
                try:
                    action.id = int(part[3:].strip("'\""))
                except ValueError:
                    pass
            elif part.startswith("phase:"):
                try:
                    action.phase = int(part[6:].strip("'\""))
                except ValueError:
                    pass
            elif part.startswith("status:"):
                try:
                    action.status = int(part[7:].strip("'\""))
                except ValueError:
                    pass
            elif part.startswith("msg:"):
                action.msg = part[4:].strip("'\"")
            elif part.startswith("tag:"):
                action.tag.append(part[4:].strip("'\""))
            elif part.startswith("severity:"):
                action.severity = part[9:].strip("'\"").upper()
            elif part.startswith("setvar:"):
                action.setvars.append(part[7:].strip("'\""))
            elif part.startswith("t:"):
                t_name = part[2:].strip("'\"")
                action.transformations.append(Transformation(t_name))

        return action

    def _split_actions(self, text: str) -> List[str]:
        """Splits a comma-delimited action string, taking quotes into account."""
        items = []
        buf = []
        in_quote = False
        quote_char = ""

        for char in text:
            if char in ("'", '"'):
                if in_quote and char == quote_char:
                    in_quote = False
                elif not in_quote:
                    in_quote = True
                    quote_char = char
                buf.append(char)
            elif char == "," and not in_quote:
                items.append("".join(buf).strip())
                buf = []
            else:
                buf.append(char)

        if buf:
            items.append("".join(buf).strip())
        return items

    def _infer_category(self, filename: str, actions: RuleAction) -> str:
        """Infers the vulnerability category from filename or tags."""
        name_lower = filename.lower()
        if "protocol" in name_lower:
            return "Protocol Enforcement"
        if "sqli" in name_lower:
            return "SQL Injection"
        if "xss" in name_lower:
            return "Cross-Site Scripting (XSS)"
        if "-rce" in name_lower or "attack-rce" in name_lower or "rce." in name_lower:
            return "Remote Code Execution (RCE)"
        if "lfi" in name_lower:
            return "Local File Inclusion (LFI)"
        if "ssrf" in name_lower:
            return "SSRF"
        if "scanner" in name_lower:
            return "Scanner Detection"
        if "blocking" in name_lower:
            return "Blocking Evaluation"

        # Check tags
        for tag in actions.tag:
            tag_l = tag.lower()
            if "attack-protocol" in tag_l or "protocol" in tag_l:
                return "Protocol Enforcement"
            if "sqli" in tag_l:
                return "SQL Injection"
            if "xss" in tag_l:
                return "Cross-Site Scripting (XSS)"
            if "attack-rce" in tag_l or "command-injection" in tag_l:
                return "Remote Code Execution (RCE)"
            if "lfi" in tag_l or "traversal" in tag_l:
                return "Local File Inclusion (LFI)"
            if "ssrf" in tag_l:
                return "SSRF"
            if "scanner" in tag_l:
                return "Scanner Detection"
        return "Custom Rule"

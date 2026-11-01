# Web Application Firewall (WAF) Simulator

A full-featured, interactive Web Application Firewall (WAF) Simulator designed to simulate, visualize, and demonstrate how a WAF filters, inspects, and blocks malicious web requests in a controlled environment. Built using **Python**, **Flask**, and an authentic **ModSecurity Core Rule Set (CRS)** rule engine.

## User Review Required

> [!IMPORTANT]
> **ModSecurity Engine Architecture**: ModSecurity C/C++ libraries (`libmodsecurity3`) typically require Linux shared objects or Docker containers. To ensure native, zero-friction execution directly on Windows without requiring Docker Desktop to be running, we will build a pure-Python ModSecurity engine that parses and executes authentic ModSecurity `.conf` SecRule directives (OWASP CRS format) with 100% syntax and behavioral fidelity. We will also include ready-to-run `.conf` rule files and sample configurations.

> [!NOTE]
> All core dependencies (`flask`, `requests`, `jinja2`) are already installed in your Python 3.12 environment. No complex system configuration or admin privileges are required.

---

## Proposed Architecture

```
Web Application Firewall/
├── run.py                           # CLI & Web Server startup script
├── requirements.txt                 # Project dependencies (Flask, requests)
├── README.md                        # Complete project manual & educational guide
├── waf_core/                        # ModSecurity Core Engine
│   ├── __init__.py
│   ├── models.py                    # Transaction, Rule, Action, MatchResult models
│   ├── parser.py                    # ModSecurity SecRule / SecAction directive parser (.conf files)
│   ├── operators.py                 # ModSecurity operators (@rx, @pm, @contains, @streq, @ipMatch, etc.)
│   ├── transformations.py           # Transformations (t:urlDecode, t:lowercase, t:removeWhitespace, etc.)
│   ├── engine.py                    # WAF Engine (Phases 1 & 2, Anomaly Scoring, Decision logic)
│   └── audit_logger.py              # ModSecurity SecAuditLog generator (JSON and native format)
├── rules/                           # Authentic ModSecurity OWASP Core Rule Set (CRS) configs
│   ├── crs-setup.conf               # Anomaly threshold & global engine configuration
│   ├── REQUEST-901-INITIALIZATION.conf
│   ├── REQUEST-913-SCANNER-DETECTION.conf  # sqlmap, Nikto, nmap, automated vulnerability scanners
│   ├── REQUEST-920-PROTOCOL-ENFORCEMENT.conf # Missing host headers, disallowed HTTP methods
│   ├── REQUEST-930-APPLICATION-ATTACK-LFI.conf # Directory traversal, /etc/passwd, win.ini
│   ├── REQUEST-932-APPLICATION-ATTACK-RCE.conf # Command injection (; ls, | whoami, bash, cmd.exe)
│   ├── REQUEST-941-APPLICATION-ATTACK-XSS.conf # Cross-Site Scripting (<script>, onerror, javascript:)
│   ├── REQUEST-942-APPLICATION-ATTACK-SQLI.conf # SQL Injection (' OR 1=1, UNION SELECT, SLEEP)
│   ├── REQUEST-944-APPLICATION-ATTACK-JAVA-SSRF.conf # SSRF (AWS/cloud metadata, localhost)
│   └── REQUEST-949-BLOCKING-EVALUATION.conf  # Evaluates inbound anomaly score and blocks if >= threshold
├── app/                             # Flask Web Application & Interactive UI
│   ├── __init__.py
│   ├── server.py                    # Flask application factory
│   ├── waf_middleware.py            # WSGI / Flask request interceptor & reverse proxy logic
│   ├── vulnerable_app.py            # Mock backend app with vulnerable endpoints (Login, Search, Ping, File Viewer)
│   ├── api.py                       # REST APIs for request tester, statistics, rules, and benchmark
│   ├── static/
│   │   ├── css/
│   │   │   └── dashboard.css        # Modern cybersecurity dark-theme styling
│   │   └── js/
│   │       ├── dashboard.js         # Interactive charts, real-time metrics
│   │       ├── simulator.js         # Request builder, preset payloads, animated inspection pipeline
│   │       ├── rules_manager.js     # SecRule viewer, editor, and toggles
│   │       └── benchmark.js         # Automated security evaluation test suite runner
│   └── templates/
│       ├── base.html                # Base layout with navigation and theme
│       ├── index.html               # Main Dashboard (Metrics, charts, event feed)
│       ├── simulator.html           # Attack Sandbox / Request Builder with Preset library
│       ├── rules.html               # ModSecurity Rule Set Manager & Custom Rule Editor
│       ├── logs.html                # Audit Log Inspector (ModSecurity section breakdown)
│       ├── vulnerable_demo.html     # Live Side-by-Side Demo (WAF On vs Off against target app)
│       ├── benchmark.html           # One-Click Security Benchmark (Accuracy, Recall, Precision)
│       └── block_page.html          # Custom 403 Forbidden ModSecurity interception page
└── tests/                           # Comprehensive test suite (Python unittest)
    ├── __init__.py
    ├── test_parser.py               # SecRule parsing tests
    ├── test_operators.py            # Operators unit tests
    ├── test_transformations.py      # Transformation function unit tests
    ├── test_crs_rules.py            # Attack vector detection tests (SQLi, XSS, RCE, LFI, SSRF, Scanners)
    └── test_flask_waf.py            # Flask WAF middleware integration tests
```

---

## Detailed Component Breakdown

### 1. `waf_core`: ModSecurity Engine & OWASP CRS Logic
- **Directives Supported**:
  - `SecRuleEngine [On | DetectionOnly | Off]`
  - `SecDefaultAction "phase:1,log,auditlog,pass"`
  - `SecRule [VARIABLES] "[OPERATOR]" "[ACTIONS]"`
  - `SecAction "[ACTIONS]"`
- **Target Variables**:
  - `REQUEST_URI`, `REQUEST_FILENAME`, `QUERY_STRING`, `REQUEST_METHOD`, `REQUEST_HEADERS`, `REQUEST_COOKIES`, `ARGS`, `ARGS_GET`, `ARGS_POST`, `REQUEST_BODY`, `REMOTE_ADDR`, `TX` (transaction variables).
- **Operators**:
  - `@rx` (regular expression), `@pm` (pattern match list), `@contains`, `@streq`, `@beginsWith`, `@endsWith`, `@gt`, `@ge`, `@lt`, `@le`, `@eq`, `@ipMatch` (CIDR IP ranges), with negation `!`.
- **Transformations**:
  - `t:none`, `t:lowercase`, `t:urlDecode`, `t:htmlEntityDecode`, `t:removeWhitespace`, `t:compressWhitespace`, `t:base64Decode`, `t:trim`.
- **Modes**:
  - **OWASP CRS Anomaly Scoring Mode**: Each triggered rule adds points to `tx.anomaly_score`. In phase 2, if score $\ge$ threshold (default: 5), request is denied with 403 Forbidden.
  - **Traditional Immediate Blocking Mode**: First matching rule with `deny` or `block` action stops processing and returns 403.
  - **Detection Only Mode**: Inspects, logs, and increments scores without blocking.

### 2. ModSecurity OWASP Core Rule Sets (`rules/*.conf`)
- Authentic ModSecurity configuration files loaded at runtime.
- Covers:
  - **SQL Injection (942xxx)**: Union selects, comment evasion, time-based, boolean-based.
  - **Cross-Site Scripting (941xxx)**: `<script>`, javascript: pseudo-protocol, event attributes (`onload=`, `onerror=`), encoded payloads.
  - **Remote Code Execution (932xxx)**: Shell metacharacters (`;`, `|`, `&&`, `` ` ``), powershell, bash commands, system binaries.
  - **Local File Inclusion / Path Traversal (930xxx)**: `../`, `..\`, `/etc/passwd`, `win.ini`, `system32`.
  - **SSRF (944xxx)**: Requests to cloud metadata (`169.254.169.254`), localhost/loopback interfaces.
  - **Automated Scanners (913xxx)**: `sqlmap`, `nikto`, `nmap`, `acunetix`, `nessus`, headless browsers.
  - **Protocol Enforcement (920xxx)**: Missing Host header, illegal characters, abnormal request lengths.

### 3. Flask Interactive Web Dashboard & Simulator
- **Live Request Sandbox**:
  - Full HTTP request constructor (Method, URL, Headers, Query parameters, Cookies, JSON / Form body).
  - Built-in library of 25+ attack payloads and legitimate requests.
  - Step-by-step visual inspection pipeline: Header inspection $\to$ Body transformation $\to$ Rule matching $\to$ Anomaly scoring $\to$ Allow / Block decision.
- **Rule Set Manager**:
  - Filterable table of all loaded rules with ID, category, severity, and status.
  - Toggle individual rules or entire categories on/off in real-time.
  - Custom rule creator with syntax checking.
- **Live Side-by-Side Target Application Demo**:
  - Toggle WAF ON / OFF to see actual vulnerability behavior in the mock application (e.g. SQL Injection login bypass vs 403 WAF Block).
- **Security Benchmark Suite**:
  - Automated test runner testing clean requests (benign) and attack payloads.
  - Generates a security score matrix: True Positives, False Positives, Detection Rate, and False Positive Rate.
- **Audit Log Inspector**:
  - Complete request & response log with triggered rule details, matched strings, and ModSecurity SecAuditLog format viewer.

---

## Verification Plan

### Automated Testing
- Run test suite with Python's built-in `unittest`:
  ```powershell
  python -m unittest discover tests -v
  ```
- Tests include:
  1. Unit tests for parser, operators, and transformations.
  2. CRS detection tests across all attack classes (SQLi, XSS, RCE, LFI, SSRF, Scanners).
  3. False positive verification for valid benign traffic.
  4. Flask middleware end-to-end tests (verifying 403 Forbidden with custom block page on attacks, and 200 OK on benign traffic).

### Interactive Testing & Verification
- Start the application with `python run.py`.
- Verify the web UI loads at `http://127.0.0.1:5000`.
- Run automated benchmarks from the UI and CLI.
- Test preset attack payloads in the Simulator and observe real-time pipeline visualization and audit logging.

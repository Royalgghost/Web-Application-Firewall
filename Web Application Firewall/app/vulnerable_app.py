"""
Simulated Target Application
Provides vulnerable endpoints demonstrating how exploits behave when unprotected,
and how the ModSecurity WAF effectively protects the application when enabled.
"""
from flask import Blueprint, render_template, request, jsonify, g
import re

vulnerable_bp = Blueprint("vulnerable_app", __name__, url_prefix="/app")


@vulnerable_bp.route("/")
def home():
    """Target app landing page."""
    tx = getattr(g, "waf_transaction", None)
    return render_template("vulnerable_demo.html", page="home", tx=tx)


@vulnerable_bp.route("/login", methods=["GET", "POST"])
def login():
    """Vulnerable Login Endpoint (SQL Injection Demo)."""
    tx = getattr(g, "waf_transaction", None)
    message = None
    success = False
    exploited = False

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Simulated vulnerable SQL query:
        # SELECT * FROM users WHERE username = '{username}' AND password = '{password}'
        # If username contains SQL tautology ' OR 1=1 or ' OR '1'='1:
        sqli_pattern = re.compile(r"('|\")\s*(?:or|union)", re.IGNORECASE)
        if sqli_pattern.search(username) or sqli_pattern.search(password):
            success = True
            exploited = True
            message = "AUTHENTICATION BYPASS EXPLOITED! Welcome, Administrator! Secret Flag: FLAG{MODSEC_SQLI_DEMO_PASSED}"
        elif username == "admin" and password == "SuperSecurePassword123!":
            success = True
            message = "Legitimate login successful! Welcome, Administrator."
        else:
            message = "Invalid username or password. Access Denied."

    return render_template(
        "vulnerable_demo.html",
        page="login",
        message=message,
        success=success,
        exploited=exploited,
        tx=tx,
    )


@vulnerable_bp.route("/search", methods=["GET"])
def search():
    """Vulnerable Search Endpoint (Reflected XSS Demo)."""
    tx = getattr(g, "waf_transaction", None)
    query = request.args.get("q", "")
    exploited = False
    if "<script" in query.lower() or "onerror=" in query.lower() or "javascript:" in query.lower():
        exploited = True

    return render_template(
        "vulnerable_demo.html",
        page="search",
        query=query,
        exploited=exploited,
        tx=tx,
    )


@vulnerable_bp.route("/ping", methods=["GET", "POST"])
def ping():
    """Vulnerable Network Tool (Remote Code Execution Demo)."""
    tx = getattr(g, "waf_transaction", None)
    output = None
    exploited = False

    if request.method == "POST":
        ip = request.form.get("ip", "")
        # Check if chained commands were passed
        if any(sep in ip for sep in (";", "|", "&&", "`")):
            exploited = True
            output = (
                f"Simulated RCE Output for injected command:\n"
                f"root:x:0:0:root:/root:/bin/bash\n"
                f"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                f"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                f"[!] Application compromised via Command Injection in: {ip}"
            )
        else:
            output = f"PING {ip} (56 data bytes)\n64 bytes from {ip}: icmp_seq=1 ttl=64 time=0.034 ms\n1 packets transmitted, 1 received, 0% packet loss"

    return render_template(
        "vulnerable_demo.html",
        page="ping",
        output=output,
        exploited=exploited,
        tx=tx,
    )


@vulnerable_bp.route("/view-file", methods=["GET"])
def view_file():
    """Vulnerable File Viewer (Path Traversal / LFI Demo)."""
    tx = getattr(g, "waf_transaction", None)
    filename = request.args.get("file", "welcome.txt")
    content = ""
    exploited = False

    if ".." in filename or "/etc/" in filename or "win.ini" in filename.lower():
        exploited = True
        content = (
            "[!] SENSITIVE SYSTEM FILE ACCESSED VIA PATH TRAVERSAL:\n\n"
            "; for 16-bit app support\n"
            "[fonts]\n"
            "[extensions]\n"
            "[mci extensions]\n"
            "[files]\n"
            "root:x:0:0:root:/root:/bin/bash\n"
            "admin:$6$rounds=5000$saltsalt$hackedpasswordhash:18000:0:99999:7:::\n"
        )
    else:
        content = f"Welcome to the internal document viewer.\nReading file: {filename}\nContent: System operating normally."

    return render_template(
        "vulnerable_demo.html",
        page="view-file",
        filename=filename,
        content=content,
        exploited=exploited,
        tx=tx,
    )


@vulnerable_bp.route("/fetch-url", methods=["GET"])
def fetch_url():
    """Vulnerable URL fetcher (SSRF Demo)."""
    tx = getattr(g, "waf_transaction", None)
    target_url = request.args.get("url", "https://api.github.com/zen")
    response_data = ""
    exploited = False

    if "169.254.169.254" in target_url or "localhost" in target_url or "127.0.0.1" in target_url:
        exploited = True
        response_data = (
            "{\n"
            '  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",\n'
            '  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n'
            '  "Token": "AQoDYXdzEJr1...EXAMPLETOKEN...",\n'
            '  "Expiration": "2026-11-01T12:00:00Z"\n'
            "}\n"
            "[!] Cloud IAM Instance Credentials Leaked via SSRF!"
        )
    else:
        response_data = f"Fetched data from {target_url}: 200 OK. Content preview: 'Practicality beats purity.'"

    return render_template(
        "vulnerable_demo.html",
        page="fetch-url",
        target_url=target_url,
        response_data=response_data,
        exploited=exploited,
        tx=tx,
    )

"""
Web Application Firewall (WAF) Simulator - Startup Entry Point
Usage:
  python run.py                   # Run interactive Flask web app (http://127.0.0.1:5000)
  python run.py --benchmark       # Run 30-case automated security benchmark in terminal
  python run.py --cli             # Run interactive CLI attack test bench
"""
import argparse
import sys
from app import create_app
from waf_core.engine import ModSecurityEngine
from waf_core.models import Transaction


def run_terminal_benchmark():
    """Runs the 30-case benchmark in the terminal and outputs a formatted report."""
    print("=" * 70)
    print("  MODSECURITY WAF SIMULATOR - SECURITY BENCHMARK SUITE")
    print("=" * 70)

    app = create_app()
    with app.app_context():
        client = app.test_client()
        resp = client.post("/api/benchmark")
        data = resp.get_json()

    metrics = data["metrics"]
    results = data["results"]

    print("\n[+] DETAILED TEST RESULTS:")
    print("-" * 70)
    print(f"{'#':<4} {'STATUS':<7} {'TYPE':<10} {'TEST NAME':<32} {'SCORE':<7} {'LATENCY'}")
    print("-" * 70)
    for r in results:
        status_sym = "[PASS]" if r["passed"] else "[FAIL]"
        print(f"{r['id']:<4} {status_sym:<7} {r['type']:<10} {r['name'][:30]:<32} {r['anomaly_score']} pts   {r['latency_ms']}ms")

    print("-" * 70)
    print("\n[+] DETECTION BENCHMARK SUMMARY:")
    print(f"  * Total Tests Run:      {metrics['total_tests']}")
    print(f"  * Detection Accuracy:   {metrics['accuracy']}%")
    print(f"  * Sensitivity (Recall): {metrics['sensitivity']}% (Attacks Caught: {metrics['tp']}/{metrics['tp'] + metrics['fn']})")
    print(f"  * Specificity:          {metrics['specificity']}% (Clean Traffic Passed: {metrics['tn']}/{metrics['tn'] + metrics['fp']})")
    print(f"  * Precision:            {metrics['precision']}%")
    print("\n[+] CONFUSION MATRIX:")
    print(f"  * True Positives  (TP): {metrics['tp']} (Malicious blocked)")
    print(f"  * True Negatives  (TN): {metrics['tn']} (Benign allowed)")
    print(f"  * False Positives (FP): {metrics['fp']} (Benign blocked - Error)")
    print(f"  * False Negatives (FN): {metrics['fn']} (Malicious bypassed - Error)")
    print("=" * 70)


def run_terminal_cli():
    """Interactive command-line attack simulator."""
    print("=" * 70)
    print("  MODSECURITY WAF SIMULATOR - INTERACTIVE CLI TEST BENCH")
    print("=" * 70)
    engine = ModSecurityEngine(rules_dir="rules")
    print(f"[+] Loaded {len(engine.rules)} ModSecurity Core Rule Set directives.")
    print("[+] Anomaly score threshold: 5 points.")
    print("Type a payload to test (e.g., \"' OR 1=1 --\" or \"<script>alert(1)</script>\"), or 'exit':\n")

    while True:
        try:
            val = input("Payload > ").strip()
            if not val or val.lower() in ("exit", "quit"):
                break

            tx = Transaction(
                method="GET",
                uri=f"/search?q={val}",
                path="/search",
                query_string=f"q={val}",
                query_params={"q": [val]},
                headers={"Host": "localhost", "User-Agent": "WAF-CLI-Tester"},
            )
            engine.process_transaction(tx)

            print(f"\n[-] Transaction ID: {tx.id}")
            if tx.is_blocked:
                print(f"    Decision:      [BLOCKED] HTTP 403 Forbidden")
                print(f"    Anomaly Score: {tx.anomaly_score} / 5 pts (Threshold Exceeded)")
                print(f"    Reason:        {tx.block_reason}")
                print(f"    Triggered Rules ({len(tx.matches)}):")
                for m in tx.matches:
                    print(f"      - Rule #{m.rule_id} [{m.severity}]: {m.message} (Matched: '{m.matched_data}')")
            else:
                print(f"    Decision:      [ALLOWED] HTTP 200 OK")
                print(f"    Anomaly Score: {tx.anomaly_score} / 5 pts")
                print(f"    Status:        Clean request passed perimeter inspection.")
            print("-" * 50)
        except (KeyboardInterrupt, EOFError):
            break
    print("\nExiting CLI.")


def main():
    parser = argparse.ArgumentParser(description="Web Application Firewall (WAF) Simulator")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--benchmark", action="store_true", help="Execute automated security benchmark in terminal")
    parser.add_argument("--cli", action="store_true", help="Launch interactive CLI attack test bench")

    args = parser.parse_args()

    if args.benchmark:
        run_terminal_benchmark()
        return

    if args.cli:
        run_terminal_cli()
        return

    print("=" * 70)
    print("  MODSECURITY WEB APPLICATION FIREWALL (WAF) SIMULATOR")
    print("=" * 70)
    print(f"  * Web Dashboard:      http://{args.host}:{args.port}/")
    print(f"  * Attack Sandbox:     http://{args.host}:{args.port}/simulator")
    print(f"  * Target App Demo:    http://{args.host}:{args.port}/app/")
    print(f"  * ModSecurity Rules:  http://{args.host}:{args.port}/rules")
    print(f"  * SecAuditLog Viewer: http://{args.host}:{args.port}/logs")
    print(f"  * Security Benchmark: http://{args.host}:{args.port}/benchmark")
    print("=" * 70)
    print("  Starting Flask server... Press Ctrl+C to stop.\n")

    app = create_app()
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()

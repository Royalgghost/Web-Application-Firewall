"""
Flask Server Application Factory
Mounts ModSecurity engine, WAF middleware, API routes, and UI dashboard templates.
"""
import os
from flask import Flask, render_template
from waf_core.engine import ModSecurityEngine
from .api import api_bp
from .vulnerable_app import vulnerable_bp
from .waf_middleware import WAFMiddleware


def create_app(rules_dir: str = None) -> Flask:
    """Application factory for WAF Simulator."""
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = "waf-simulator-secret-2026"

    # Locate rules directory
    if not rules_dir:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        rules_dir = os.path.join(base_dir, "rules")

    # Initialize ModSecurity Engine
    engine = ModSecurityEngine(rules_dir=rules_dir)
    app.waf_engine = engine

    # Attach WAF Middleware
    waf_middleware = WAFMiddleware(engine)
    app.before_request(waf_middleware.inspect_request)

    # Register Blueprints
    app.register_blueprint(api_bp)
    app.register_blueprint(vulnerable_bp)

    # UI Dashboard Routes
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/simulator")
    def simulator():
        return render_template("simulator.html")

    @app.route("/rules")
    def rules():
        return render_template("rules.html")

    @app.route("/logs")
    def logs():
        return render_template("logs.html")

    @app.route("/benchmark")
    def benchmark():
        return render_template("benchmark.html")

    return app

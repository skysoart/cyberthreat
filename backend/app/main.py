"""
backend/app/main.py  — Team 1
FastAPI application: mounts static files, serves demo-site HTML,
includes all API routers, adds telemetry middleware.
"""
import os

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from backend.app.database import engine
from backend.app.models.tables import Base
from backend.app.middleware import TelemetryMiddleware
from backend.app.api import store, telemetry, dashboard

# ---------------------------------------------------------------------------
# Create all tables on startup (idempotent)
# ---------------------------------------------------------------------------
Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Adamantine",
    description="Cybersecurity detection platform — local demo",
    version="1.0.0",
)

# CORS — local origin only per contract §7
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Server-side telemetry — must be added AFTER CORS so it sees real IPs
app.add_middleware(TelemetryMiddleware)

# ---------------------------------------------------------------------------
# API Routers
# ---------------------------------------------------------------------------
app.include_router(store.router)
app.include_router(telemetry.router)
app.include_router(dashboard.router)


# ---------------------------------------------------------------------------
# Background correlation
# ---------------------------------------------------------------------------
# Events are classified at request time by the middleware, but incidents only
# exist once correlation groups them. Running it on a timer is what makes the
# live demo work: run an attack, wait a few seconds, watch it surface in the
# queue without touching anything.
#
# A daemon thread rather than APScheduler — one less dependency to fail, and
# it dies with the process instead of hanging shutdown.
@app.on_event("startup")
def _start_correlation_loop() -> None:
    import threading
    from backend.app.services.engine import get_engine

    interval = int(os.environ.get("CORRELATE_INTERVAL_SECONDS", "15"))

    def loop() -> None:
        import time
        while True:
            time.sleep(interval)
            try:
                get_engine().correlate()
            except Exception as exc:                     # never kill the thread
                print(f"[correlate] {type(exc).__name__}: {exc}")

    threading.Thread(target=loop, daemon=True, name="adamantine-correlate").start()
    print(f"[startup] correlation loop running every {interval}s")

# ---------------------------------------------------------------------------
# Static mounts
# ---------------------------------------------------------------------------
if os.path.exists("demo-site/static"):
    app.mount("/static", StaticFiles(directory="demo-site/static"), name="demo-static")

# Serve the whole dashboard directory, not just its static subfolder.
#
# Previously only frontend/static was mounted, so every dashboard PAGE 404'd and
# the only way to see one was to open the .html off disk. That appears to work —
# the page renders — but every fetch("/api/v1/...") then resolves against
# file:// and fails silently, so the screens come up empty. html=True makes
# /dashboard/ serve index.html, and the pages' relative asset paths
# ("static/api.js", "style.css") resolve correctly underneath it.
if os.path.exists("frontend"):
    app.mount("/dashboard", StaticFiles(directory="frontend", html=True), name="dashboard")

if os.path.exists("frontend/static"):
    app.mount("/dashboard-static", StaticFiles(directory="frontend/static"), name="dash-static")

if os.path.exists("frontend/mocks"):
    app.mount("/mocks", StaticFiles(directory="frontend/mocks"), name="dash-mocks")


# The browser sensor. Every Sample Store page loads this; if it 404s the store
# still works, it just stops producing browser telemetry and every visitor
# starts looking like a bot.
@app.get("/adamantine-sensor.js", include_in_schema=False)
def adamantine_sensor():
    path = "widget/adamantine-sensor.js"
    if not os.path.exists(path):
        return JSONResponse({"detail": "sensor not installed"}, status_code=404)
    return FileResponse(path, media_type="application/javascript")

# ---------------------------------------------------------------------------
# Probe / honeypot paths — MUST return 404 per contract §7
# ---------------------------------------------------------------------------
@app.get("/.env")
@app.get("/.git/config")
@app.get("/wp-admin/")
@app.get("/wp-admin")
@app.get("/phpmyadmin/")
@app.get("/phpmyadmin")
def probe_404(request: Request):
    return JSONResponse(status_code=404, content={"detail": "Not found"})


# ---------------------------------------------------------------------------
# Sample Store pages
# ---------------------------------------------------------------------------
@app.get("/")
def store_home():
    return FileResponse("demo-site/index.html")


@app.get("/products")
def store_products(page: int = 1):
    return FileResponse("demo-site/products.html")


@app.get("/products/{product_id}")
def store_product_detail(product_id: int):
    return FileResponse("demo-site/product.html")


@app.get("/cart")
def store_cart():
    return FileResponse("demo-site/cart.html")


@app.get("/checkout")
def store_checkout():
    return FileResponse("demo-site/checkout.html")


@app.get("/account")
def store_account():
    return FileResponse("demo-site/account.html")


@app.get("/admin")
def store_admin():
    return FileResponse("demo-site/admin.html")


# ---------------------------------------------------------------------------
# Sensitive / honeypot paths — return as designed
# /actuator/env MUST return 200 (demo honeypot) per contract §7
# ---------------------------------------------------------------------------
@app.get("/actuator/env")
def actuator_env():
    return FileResponse("demo-site/actuator-env.json")


@app.get("/sitemap.xml")
def sitemap():
    return FileResponse("demo-site/sitemap.xml")


@app.get("/robots.txt")
def robots():
    return FileResponse("demo-site/robots.txt")


# ---------------------------------------------------------------------------
# Sensor widget — served from widget/ per contract §2
# Also aliased at /adamantine-sensor.js for backward compat with existing HTML
# ---------------------------------------------------------------------------
@app.get("/widget/adamantine-sensor.js")
@app.get("/adamantine-sensor.js")
def sensor_js():
    # Prefer widget/ location per contract; fall back to demo-site/ if not moved yet
    if os.path.exists("widget/adamantine-sensor.js"):
        return FileResponse("widget/adamantine-sensor.js")
    return FileResponse("demo-site/adamantine-sensor.js")


# ---------------------------------------------------------------------------
# SOC Dashboard
# ---------------------------------------------------------------------------
# The dashboard is served by the StaticFiles mount at /dashboard above.
#
# It used to also be reachable from the root via a /{page}.html catch-all, and
# that was the source of a silent, total failure: the dashboard pages reference
# "static/api.js", which at the root resolves to /static/ — the DEMO STORE's
# static folder, which has no api.js. The page rendered, every dashboard script
# 404'd, and all six screens came up empty with no visible error.
#
# Serving it only from /dashboard/ means those relative paths resolve inside
# frontend/ where they belong.


@app.get("/dashboard-legacy", include_in_schema=False)
def dash_redirect():
    return RedirectResponse(url="/dashboard/")


# Root-level .html catch-all, restricted to the demo store. It must NOT fall
# through to frontend/ — see above.
@app.get("/{page}.html", include_in_schema=False)
def store_page(page: str):
    demo_path = f"demo-site/{page}.html"
    if os.path.exists(demo_path):
        return FileResponse(demo_path)
    if os.path.exists(f"frontend/{page}.html"):
        return RedirectResponse(url=f"/dashboard/{page}.html")
    return JSONResponse(status_code=404, content={"detail": "Not found"})

"""
backend/app/main.py  — Team 1
FastAPI application: mounts static files, serves demo-site HTML,
includes all API routers, adds telemetry middleware.
"""
import os

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
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
# Static mounts
# ---------------------------------------------------------------------------
if os.path.exists("demo-site/static"):
    app.mount("/static", StaticFiles(directory="demo-site/static"), name="demo-static")

if os.path.exists("frontend/static"):
    app.mount("/dashboard-static", StaticFiles(directory="frontend/static"), name="dash-static")

if os.path.exists("frontend/mocks"):
    app.mount("/mocks", StaticFiles(directory="frontend/mocks"), name="dash-mocks")

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
# SOC Dashboard HTML pages
# ---------------------------------------------------------------------------
@app.get("/dashboard")
def dash_root():
    return FileResponse("frontend/index.html")


@app.get("/style.css")
def dash_css():
    return FileResponse("frontend/style.css")


@app.get("/app.js")
def dash_js():
    return FileResponse("frontend/app.js")


# Dynamic catch-all for /incidents.html, /incident.html etc.
@app.get("/{page}.html")
def dash_page(page: str):
    frontend_path = f"frontend/{page}.html"
    if os.path.exists(frontend_path):
        return FileResponse(frontend_path)
    demo_path = f"demo-site/{page}.html"
    if os.path.exists(demo_path):
        return FileResponse(demo_path)
    return JSONResponse(status_code=404, content={"detail": "Not found"})

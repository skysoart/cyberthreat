"""
backend/app/schemas.py  — Team 1
Pydantic v2 request/response models for Team 1 endpoints.
IMPORTANT: Missing browser telemetry fields must be None, NOT 0.
"""
from __future__ import annotations

from typing import Optional
from datetime import datetime

from pydantic import BaseModel, EmailStr, ConfigDict


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class UserLogin(BaseModel):
    email: str
    password: str


class UserCreate(UserLogin):
    full_name: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    email: str
    created_at: datetime


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class CheckoutRequest(BaseModel):
    full_name: str
    email: EmailStr
    address_line1: str
    city: str
    postcode: str
    phone: str
    # Card fields received but never persisted
    card_number: str
    card_expiry: str
    card_cvc: str


# ---------------------------------------------------------------------------
# Telemetry / sensor
# Absent sensor → all 16 browser fields are None, NOT zero.
# HistGradientBoostingClassifier handles NaN natively; zeros would be a lie.
# ---------------------------------------------------------------------------

class BrowserTelemetry(BaseModel):
    """16 browser features from widget/adamantine-sensor.js.
    All Optional with default=None so absent sensor run produces None, not 0.
    """
    mouse_move_count: Optional[int] = None
    mouse_path_entropy: Optional[float] = None
    keystroke_count: Optional[int] = None
    keystroke_interval_mean: Optional[float] = None
    keystroke_interval_std: Optional[float] = None
    form_fill_ms: Optional[int] = None
    paste_events: Optional[int] = None
    click_count: Optional[int] = None
    time_to_first_click_ms: Optional[int] = None
    scroll_events: Optional[int] = None
    page_dwell_ms: Optional[int] = None
    focus_blur_count: Optional[int] = None
    screen_w: Optional[int] = None
    screen_h: Optional[int] = None
    tz_offset: Optional[int] = None
    hardware_concurrency: Optional[int] = None


class TelemetryPayload(BaseModel):
    session_id: str
    page: str
    browser: Optional[BrowserTelemetry] = None


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class WeightsSettings(BaseModel):
    model_confidence: float
    asset_criticality: float
    exploitability: float
    blast_radius: float
    kill_chain_depth: float
    recency: float


class IncidentFeedback(BaseModel):
    label: str                       # confirmed_threat | false_positive | reclassify
    analyst: str
    note: Optional[str] = None
    new_class: Optional[str] = None  # required when label == reclassify


class ModelRollback(BaseModel):
    version: str

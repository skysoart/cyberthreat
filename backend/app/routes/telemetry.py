from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.schemas import TelemetryPayload
from backend.app.models import Event
from backend.app.config import settings

router = APIRouter()

@router.post("/api/v1/telemetry")
def ingest_telemetry(
    payload: TelemetryPayload,
    request: Request,
    x_adamantine_key: str = Header(None),
    db: Session = Depends(get_db)
):
    if x_adamantine_key != settings.ADAMANTINE_DEMO_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
        
    src_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent")
    
    # Store event
    event = Event(
        src_ip=src_ip,
        http_method="POST", # technically the telemetry request was POST
        url_path=payload.page,
        session_id=payload.session_id,
        user_agent=user_agent,
        browser_telemetry=payload.browser.model_dump(),
        # Other fields default appropriately
    )
    db.add(event)
    db.commit()
    
    return {"ok": True}

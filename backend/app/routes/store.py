from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models import Product, Order, OrderItem, User
from backend.app.schemas import CheckoutRequest
from typing import List

router = APIRouter()

@router.get("/api/v1/store/products")
def get_products(db: Session = Depends(get_db)):
    products = db.query(Product).all()
    return products

@router.get("/api/v1/store/products/{product_id}")
def get_product(product_id: int, db: Session = Depends(get_db)):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@router.post("/api/v1/store/checkout")
def checkout(order_req: CheckoutRequest, db: Session = Depends(get_db)):
    # Simple demo checkout
    user = db.query(User).filter(User.email == order_req.email).first()
    
    # Store order without real card details
    order = Order(
        user_id=user.id if user else None,
        total=0.0, # We'd calculate this from a real cart in production
        status="completed",
        payment_method="demo"
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    return {"ok": True, "order_id": order.id, "status": "completed"}

from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from sqlalchemy import func

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Should be hashed and salted
    email = db.Column(db.String(100), unique=True, nullable=False)
    address = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    role = db.Column(db.String(20), nullable=False)  
    business_name = db.Column(db.String(100), nullable=False) 
    town = db.Column(db.String(100), nullable=False)  
    street = db.Column(db.String(100), nullable=False)  
    landmark = db.Column(db.String(100), nullable=False)  
    created_at = db.Column(db.DateTime, default=func.utcnow(), nullable=False)
    
    orders = db.relationship('Order', backref='user', lazy='dynamic')

class Product(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(200))
    category = db.Column(db.String(20), nullable=False)  # e.g., 1 liter, 500 ml, 5 liters
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.String(20), nullable=False) # e.g., in stock, out of stock
    image_path = db.Column(db.String(200))

class Order(db.Model):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    order_date = db.Column(db.Date, nullable=False)
    order_status = db.Column(db.String(20), nullable=False)  # e.g., in progress, delivered
    total_price = db.Column(db.Float, nullable=False)

    user = db.relationship('User', back_populates='orders')
    order_details = db.relationship('OrderDetail', backref='order', lazy='dynamic', cascade="all, delete-orphan")
    payments = db.relationship('Payment', back_populates='order')
    deliveries = db.relationship('Delivery', back_populates='order')

class OrderDetail(db.Model):
    __tablename__ = 'order_details'

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity_ordered = db.Column(db.Integer, nullable=False)
    subtotal = db.Column(db.Float, nullable=False)

    order = db.relationship('Order', back_populates='order_details')

class Payment(db.Model):
    __tablename__ = 'payments'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    payment_date = db.Column(db.Date, nullable=False)
    payment_due = db.Column(db.Float, nullable=False)
    payment_status = db.Column(db.String(20), nullable=False)  # e.g., paid, unpaid

    order = db.relationship('Order', backref='payments', lazy='dynamic')

class Delivery(db.Model):
    __tablename__ = 'deliveries'

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    delivery_date = db.Column(db.Date, nullable=False)
    delivery_status = db.Column(db.String(20), nullable=False)  # e.g., in transit, delivered
    recipient_name = db.Column(db.String(100), nullable=False)  

    user = db.relationship('User', backref='deliveries', lazy='dynamic')
    order = db.relationship('Order', backref='deliveries', lazy='dynamic')


class RevokedToken(db.Model):
    __tablename__ = 'revoked_tokens'

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False)

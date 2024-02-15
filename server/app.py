from flask import Flask, jsonify, request, render_template, session
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, verify_jwt_in_request, jwt_required, create_access_token, create_refresh_token, get_jwt_identity
# from flask_restful import Api, Resource
from models import RevokedToken, db, User, Product, Order, OrderDetail, Payment, Delivery
from config import DEBUG, SECRET_KEY, SQLALCHEMY_DATABASE_URI, UPLOAD_FOLDER, ALLOWED_EXTENSIONS, JWT_SECRET_KEY
from datetime import datetime


app = Flask(__name__)

# Configure the app using the settings from config.py
app.config['DEBUG'] = DEBUG
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS

# Other configurations, such as JWT configuration
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    role = data.get('role')

    # Check if the role is valid (should be 'corporate' or 'personal')
    if role not in ['corporate', 'personal']:
        return jsonify({'message': 'Invalid role'}), 400

    password = data['password']
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    user = User(
        first_name=data['first_name'],
        last_name=data['last_name'],
        username=data['username'],
        password=hashed_password,
        email=data['email'],
        address=data['address'],
        phone_number=data['phone_number'],
        role=role,
        business_name=data.get('business_name') if role == 'corporate' else None,
        town=data['town'],
        street=data['street'],
        landmark=data['landmark']
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username_or_email_or_phone = data.get('username_or_email_or_phone')
    password = data['password']

    # Attempt to find the user by username, email, or phone number
    user = User.query.filter(
        (User.username == username_or_email_or_phone) |
        (User.email == username_or_email_or_phone) |
        (User.phone_number == username_or_email_or_phone)
    ).first()

    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id, fresh=True)
        refresh_token = create_refresh_token(identity=user.id)
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/refresh', methods=['POST'])
@jwt_required(fresh=False)
def refresh():
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id, fresh=False)
    return jsonify({'access_token': new_access_token}), 200


@app.route('/logout', methods=['POST'])
@jwt_required
def logout():
    # Create a new access token with a custom claim to revoke the current token
    current_user_id = get_jwt_identity()
    revoked_token_jti = create_access_token(identity=current_user_id, expires_delta=False, user_claims={'revoke_token': True})
    
    # Add the revoked token to your database or set of revoked tokens
    revoked_token = RevokedToken(jti=revoked_token_jti)
    db.session.add(revoked_token)
    db.session.commit()
    
    return jsonify({'message': 'Successfully logged out'}), 200











# Initialize an empty set to store revoked tokens
revoked_tokens = set()

# Function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Custom decorator to check if the token is blacklisted
def token_not_revoked(fn):
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()  # Verify that a JWT is present in the request
        jti = kwargs.get('jti', None)  # Retrieve 'jti' from kwargs
        if jti is None:
            return jsonify({'error': 'Token identifier not provided'}), 400

        if RevokedToken.query.filter_by(jti=jti).first():
            return jsonify({'error': 'Token has been revoked'}), 401
        return fn(*args, **kwargs)
    return wrapper



# General Routes

@app.errorhandler(404)
def not_found(e):
    return render_template("index.html")

@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad request', 'message': str(e)}), 400

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

@app.route('/', methods=['GET'])
def root():
    return jsonify({'message': 'Welcome to the VEPO API'})


@app.route('/signup', methods=['POST'])
def signup():
    data = request.json

    # Validate the data
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Check if username or email is already taken
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({'error': 'Username is already taken'}), 400

    existing_email = User.query.filter_by(email=data['email']).first()
    if existing_email:
        return jsonify({'error': 'Email is already registered'}), 400

    # Hash the password before storing it
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    # Create a new user based on the role (corporate or personal)
    if data['role'] == 'corporate':
        # Ensure the "business_name" is provided for corporate users
        if 'business_name' not in data:
            return jsonify({'error': 'Business name is required for corporate users'}), 400

        new_user = User(
            first_name=data['first_name'],
            last_name=data['last_name'],
            username=data['username'],
            password=hashed_password,
            email=data['email'],
            address=data['address'],
            phone_number=data['phone_number'],
            role=data['role'],
            business_name=data['business_name'],
            town=data['town'],  
            street=data['street'],  
            landmark=data['landmark']  
        )
    elif data['role'] == 'personal':
        new_user = User(
            first_name=data['first_name'],
            last_name=data['last_name'],
            username=data['username'],
            password=hashed_password,
            email=data['email'],
            address=data['address'],
            phone_number=data['phone_number'],
            role=data['role'],
            town=data['town'],  
            street=data['street'],  
            landmark=data['landmark'] 
        )
    else:
        return jsonify({'error': 'Invalid account type'}), 400

    # Add the new user to the database
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json  

    # Validate the data
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    user = User.query.filter_by(username=data['username']).first()
    
    if user and bcrypt.check_password_hash(user.password, data['password']):
        # Passwords match, user is authenticated
        access_token = create_access_token(identity=user.id, additional_claims={'role': user.role})  # Create a JWT token
        return jsonify({'access_token': access_token})
    else:
        return jsonify({'error': 'Invalid username or password'}), 401


@app.route('/logout/<string:jti>', methods=['POST'])
@jwt_required
@token_not_revoked
def logout(jti):
    # Store the JWT ID in the 'revoked_tokens' table
    revoked_token = RevokedToken(jti=jti)
    db.session.add(revoked_token)
    db.session.commit()

    # Optionally, create a new token to maintain a session
    new_access_token = create_access_token(identity=get_jwt_identity())

    return jsonify({'message': 'Logged out successfully', 'new_access_token': new_access_token})


@app.route('/products/<int:product_id>', methods=['GET'])
def get_product_by_id(product_id):
    product = Product.query.get(product_id)

    if product is None:
        return jsonify({'error': 'Product not found'}), 404

    # Serialize the product object into a dictionary
    product_data = {
        'id': product.id,
        'product_name': product.product_name,
        'description': product.description,
        'category': product.category,
        'price': product.price,
        'stock': product.stock,
        'image_path': product.image_path
    }

    return jsonify(product_data)


@app.route('/products', methods=['GET'])
def get_all_products():
    products = Product.query.all()

    # Serialize the products into a list of dictionaries
    product_list = []
    for product in products:
        product_data = {
            'id': product.id,
            'product_name': product.product_name,
            'description': product.description,
            'category': product.category,
            'price': product.price,
            'stock': product.stock,  
            'image_path': product.image_path
        }
        product_list.append(product_data)

    return jsonify(product_list)


# Common function to process order creation
def process_order_creation(user_id, order_details):
    # processing order creation
    total_price = 0
    new_order = Order(
        user_id=user_id,
        order_date=datetime.now(),
        order_status='in progress',
    )
    db.session.add(new_order)

    for detail in order_details:
        product_id = detail.get('product_id')
        quantity = detail.get('quantity')
        product = Product.query.get(product_id)

        if not product:
            return jsonify({'error': f'Product with ID {product_id} not found'}), 404

        subtotal = product.price * quantity
        total_price += subtotal

        new_order_detail = OrderDetail(
            order_id=new_order.id,
            product_id=product_id,
            quantity_ordered=quantity,
            subtotal=subtotal
        )

        db.session.add(new_order_detail)

    new_order.total_price = total_price
    db.session.commit()

    return jsonify({'message': 'Order created successfully'}), 201


# Process order payments
def process_order_payment(order_id, current_user):
    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    if current_user.role != 'personal' or current_user.id != order.user_id:
        return jsonify({'error': 'Access denied. You can only make payments for your own orders.'}), 403

    # Implement payment logic here, mark the order as 'paid'
    order.order_status = 'paid'
    db.session.commit()

    return jsonify({'message': 'Order payment successful'})




# Corporate User Routes

@app.route('/corporate/create-orders', methods=['POST'])
@jwt_required
def create_corporate_order():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'corporate':
        return jsonify({'error': 'Access denied. Only corporate users can create orders.'}), 403

    data = request.json

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    return process_order_creation(current_user_id, data.get('order_details', []))


@app.route('/corporate/orders/<int:order_id>/add_products', methods=['POST'])
@jwt_required
def add_products_to_corporate_order(order_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if current_user.role != 'corporate':
        return jsonify({'error': 'Access denied. Only corporate users can add products to orders.'}), 403

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    data = request.json
    product_id = data.get('product_id')
    quantity = data.get('quantity')

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    new_order_detail = OrderDetail(
        order_id=order_id,
        product_id=product_id,
        quantity_ordered=quantity,
        subtotal=product.price * quantity
    )

    db.session.add(new_order_detail)
    db.session.commit()

    return jsonify({'message': 'Product added to the order successfully'}), 201


@app.route('/corporate/orders-history', methods=['GET'])
@jwt_required
def get_corporate_order_history():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if current_user.role != 'corporate':
        return jsonify({'error': 'Access denied. Only corporate users can access their order history.'}), 403

    orders = Order.query.filter_by(user_id=current_user_id).all()
    
    if not orders:
        return jsonify({'message': 'No corporate orders found for this user'})

    order_history = []

    for order in orders:
        order_details = OrderDetail.query.filter_by(order_id=order.id).all()

        order_data = {
            'order_id': order.id,
            'order_date': order.order_date.strftime('%Y-%m-%d'),
            'order_status': order.order_status,
            'total_price': order.total_price,
            'order_details': []
        }

        for detail in order_details:
            product = Product.query.get(detail.product_id)
            order_data['order_details'].append({
                'product_id': detail.product_id,
                'product_name': product.product_name,
                'quantity_ordered': detail.quantity_ordered,
                'subtotal': detail.subtotal
            })

        order_history.append(order_data)

    return jsonify(order_history)


@app.route('/corporate/orders/<int:order_id>', methods=['GET'])
@jwt_required
def get_corporate_order_by_id(order_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    if current_user.role != 'corporate' or current_user_id != order.user_id:
        return jsonify({'error': 'Access denied. You can only access your own orders.'}), 403

    order_details = OrderDetail.query.filter_by(order_id=order_id).all()
    order_data = {
        'order_id': order.id,
        'order_date': order.order_date.strftime('%Y-%m-%d'),
        'order_status': order.order_status,
        'total_price': order.total_price,
        'order_details': []
    }

    for detail in order_details:
        product = Product.query.get(detail.product_id)
        order_data['order_details'].append({
            'product_id': detail.product_id,
            'product_name': product.product_name,
            'quantity_ordered': detail.quantity_ordered,
            'subtotal': detail.subtotal
        })

    return jsonify(order_data)


@app.route('/corporate/delete-orders/<int:order_id>', methods=['DELETE'])
@jwt_required
def delete_corporate_order(order_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    if current_user.role != 'corporate' or current_user_id != order.user_id:
        return jsonify({'error': 'Access denied. You can only delete your own orders.'}), 403

    db.session.delete(order)
    db.session.commit()

    return jsonify({'message': 'Corporate order deleted successfully'})


@app.route('/corporate/orders/<int:order_id>/make_payment', methods=['POST'])
@jwt_required
def make_corporate_order_payment(order_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    if current_user.role != 'corporate' or current_user_id != order.user_id:
        return jsonify({'error': 'Access denied. You can only make payments for your own orders.'}), 403

    return process_order_payment(order, current_user_id)

# needs checking later
@app.route('/corporate/payments', methods=['GET'])
@jwt_required
def get_corporate_payments():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'corporate':
        return jsonify({'error': 'Access denied. Only corporate users can access their payments.'}), 403

    orders = Order.query.filter_by(user_id=current_user_id).all()
    payments = []

    for order in orders:
        payment_status = 'unpaid'
        payment_due = order.total_price  
        payment_date = order.payment_date

        # Check if the order is paid
        if order.order_status == 'paid':
            payment_status = 'paid'

        payments.append({
            'order_id': order.id,
            'total_price': order.total_price,
            'payment_date': payment_date,
            'payment_due': payment_due,
            'payment_status': payment_status
        })

    return jsonify(payments)


@app.route('/corporate/payments/<int:order_id>', methods=['GET'])
@jwt_required
def get_corporate_payment_details(order_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    if current_user.role != 'corporate' or current_user_id != order.user_id:
        return jsonify({'error': 'Access denied. You can only access your own payments.'}), 403

    return jsonify({'order_id': order.id, 'order_status': order.order_status})


@app.route('/corporate/deliveries', methods=['GET'])
@jwt_required
def get_corporate_deliveries():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'corporate':
        return jsonify({'error': 'Access denied. Only corporate users can access their deliveries.'}), 403

    corporate_deliveries = Delivery.query.filter_by(user_id=current_user_id).all()

    if not corporate_deliveries:
        return jsonify({'message': 'No deliveries found for this corporate user'})

    deliveries_data = []

    for delivery in corporate_deliveries:
        delivery_data = {
            'delivery_id': delivery.delivery_id,
            'delivery_date': delivery.delivery_date.strftime('%Y-%m-%d'),
            'recipient_name': delivery.recipient_name,
            'delivery_status': delivery.delivery_status
        }
        deliveries_data.append(delivery_data)

    return jsonify(deliveries_data)


@app.route('/corporate/delete-account', methods=['DELETE'])
@jwt_required
def delete_corporate_account():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    # Check if the user exists
    if not current_user:
        return jsonify({'error': 'User not found'}), 404

    # Check if the user has the 'corporate' role
    if current_user.role != 'corporate':
        return jsonify({'error': 'Access denied. Only corporate users can delete their accounts.'}), 403

    # Parse the request data to get the user's provided password for verification
    data = request.json
    provided_password = data.get('password')

    if not provided_password:
        return jsonify({'error': 'Please provide your password to confirm the account deletion.'}), 400

    # Check if the provided password matches the user's stored password
    if not bcrypt.check_password_hash(current_user.password, provided_password):
        return jsonify({'error': 'Password verification failed. Account not deleted.'}), 401

    # If password verification is successful, delete the user's account
    try:
        db.session.delete(current_user)
        db.session.commit()
        return jsonify({'message': 'User account deleted successfully'})
    except Exception as e:
        return jsonify({'error': 'An error occurred while deleting the user account'}), 500



# Personal User Routes

@app.route('/personal/create-orders', methods=['POST'])
@jwt_required
def create_personal_order():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'personal':
        return jsonify({'error': 'Access denied. Only personal users can create orders.'}), 403

    data = request.json
    order_details = data.get('order_details', [])

    if not data or not order_details:
        return jsonify({'error': 'No data provided or empty order details'}), 400

    return process_order_creation(current_user_id, order_details)


@app.route('/personal/orders/<int:order_id>/add_products', methods=['POST'])
@jwt_required
def add_products_to_personal_order(order_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    if current_user.role != 'personal' or current_user_id != order.user_id:
        return jsonify({'error': 'Access denied. You can only add products to your own orders.'}), 403

    data = request.json
    product_id = data.get('product_id')
    quantity = data.get('quantity')

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    new_order_detail = OrderDetail(
        order_id=order_id,
        product_id=product_id,
        quantity_ordered=quantity,
        subtotal=product.price * quantity
    )

    db.session.add(new_order_detail)
    db.session.commit()

    return jsonify({'message': 'Product added to the order successfully'}), 201


@app.route('/personal/orders-history', methods=['GET'])
@jwt_required
def get_personal_order_history():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'personal':
        return jsonify({'error': 'Access denied. Only personal users can access their order history.'}), 403

    orders = Order.query.filter_by(user_id=current_user_id).all()

    if not orders:
        return jsonify({'message': 'No personal orders found for this user'})

    order_history = []

    for order in orders:
        order_details = OrderDetail.query.filter_by(order_id=order.id).all()

        order_data = {
            'order_id': order.id,
            'order_date': order.order_date.strftime('%Y-%m-%d'),
            'order_status': order.order_status,
            'total_price': order.total_price,
            'order_details': []
        }

        for detail in order_details:
            product = Product.query.get(detail.product_id)
            order_data['order_details'].append({
                'product_id': detail.product_id,
                'product_name': product.product_name,
                'quantity_ordered': detail.quantity_ordered,
                'subtotal': detail.subtotal
            })

        order_history.append(order_data)

    return jsonify(order_history)


@app.route('/personal/orders/<int:order_id>', methods=['GET'])
@jwt_required
def get_personal_order_by_id(order_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    if current_user.role != 'personal' or current_user_id != order.user_id:
        return jsonify({'error': 'Access denied. You can only access your own orders.'}), 403

    order_details = OrderDetail.query.filter_by(order_id=order_id).all()
    order_data = {
        'order_id': order.id,
        'order_date': order.order_date.strftime('%Y-%m-d'),
        'order_status': order.order_status,
        'total_price': order.total_price,
        'order_details': []
    }

    for detail in order_details:
        product = Product.query.get(detail.product_id)
        order_data['order_details'].append({
            'product_id': detail.product_id,
            'product_name': product.product_name,
            'quantity_ordered': detail.quantity_ordered,
            'subtotal': detail.subtotal
        })

    return jsonify(order_data)


@app.route('/personal/delete-orders/<int:order_id>', methods=['DELETE'])
@jwt_required
def delete_personal_order(order_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    if current_user.role != 'personal' or current_user_id != order.user_id:
        return jsonify({'error': 'Access denied. You can only delete your own orders.'}), 403

    db.session.delete(order)
    db.session.commit()

    return jsonify({'message': 'Personal order deleted successfully.'})


@app.route('/personal/orders/<int:order_id>/make_payment', methods=['POST'])
@jwt_required
def make_personal_order_payment(order_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    if current_user.role != 'personal' or current_user_id != order.user_id:
        return jsonify({'error': 'Access denied. You can only make payments for your own orders.'}), 403

    # Implement payment logic here, mark the order as 'paid'

    return process_order_payment(order_id, current_user)


@app.route('/personal/payments', methods=['GET'])
@jwt_required
def get_personal_payments():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'personal':
        return jsonify({'error': 'Access denied. Only personal users can access their payments.'}), 403

    orders = Order.query.filter_by(user_id=current_user_id).all()
    payments = []

    for order in orders:
        payment_status = 'unpaid'
        payment_due = order.total_price
        payment_date = order.payment_date

        # Check if the order is paid
        if order.order_status == 'paid':
            payment_status = 'paid'

        payments.append({
            'order_id': order.id,
            'total_price': order.total_price,
            'payment_date': payment_date,
            'payment_due': payment_due,
            'payment_status': payment_status
        })

    return jsonify(payments)


@app.route('/personal/payments/<int:order_id>', methods=['GET'])
@jwt_required
def get_personal_payment_details(order_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    if current_user.role != 'personal' or current_user_id != order.user_id:
        return jsonify({'error': 'Access denied. You can only access your own payments.'}), 403

    return jsonify({'order_id': order.id, 'order_status': order.order_status})


@app.route('/personal/deliveries', methods=['GET'])
@jwt_required
def get_personal_deliveries():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    if current_user.role != 'personal':
        return jsonify({'error': 'Access denied. Only personal users can access their deliveries.'}), 403

    personal_deliveries = Delivery.query.filter_by(user_id=current_user_id).all()

    if not personal_deliveries:
        return jsonify({'message': 'No deliveries found for this personal user'})

    deliveries_data = []

    for delivery in personal_deliveries:
        delivery_data = {
            'delivery_id': delivery.delivery_id,
            'delivery_date': delivery.delivery_date.strftime('%Y-%m-%d'),
            'recipient_name': delivery.recipient_name,
            'delivery_status': delivery.delivery_status
        }
        deliveries_data.append(delivery_data)

    return jsonify(deliveries_data)


@app.route('/personal/delete-account', methods=['DELETE'])
@jwt_required
def delete_personal_account():
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)

    # Check if the user exists
    if not current_user:
        return jsonify({'error': 'User not found'}), 404

    # Check if the user has the 'personal' role
    if current_user.role != 'personal':
        return jsonify({'error': 'Access denied. Only personal users can delete their accounts.'}), 403

    # Parse the request data to get the user's provided password for verification
    data = request.json
    provided_password = data.get('password')

    if not provided_password:
        return jsonify({'error': 'Please provide your password to confirm the account deletion.'}), 400

    # Check if the provided password matches the user's stored password
    if not bcrypt.check_password_hash(current_user.password, provided_password):
        return jsonify({'error': 'Password verification failed. Account not deleted.'}), 401

    # If password verification is successful, delete the user's account
    try:
        db.session.delete(current_user)
        db.session.commit()
        return jsonify({'message': 'Personal user account deleted successfully'})
    except Exception as e:
        return jsonify({'error': 'An error occurred while deleting the user account'}), 500



# Admin User Routes

@app.route('/admin/create-user', methods=['POST'])
@jwt_required
def create_user():
    current_user_id = get_jwt_identity()  
    current_user = User.query.get(current_user_id)  

    # Check if the current user is an admin
    if current_user.role != 'admin':
        return jsonify({'error': 'Permission denied. Only admin users can create new users'}), 403

    data = request.json

    # Validate the data (rest of the code remains the same)
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Check if the username or email is already taken
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({'error': 'Username is already taken'}), 400

    existing_email = User.query.filter_by(email=data['email']).first()
    if existing_email:
        return jsonify({'error': 'Email is already registered'}), 400

    # Hash and salt the password
    password = data['password']
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create a new user with the hashed password
    new_user = User(
        first_name=data['first_name'],
        last_name=data['last_name'],
        username=data['username'],
        password=hashed_password,
        email=data['email'],
        address=data['address'],
        phone_number=data['phone_number'],
        role=data['role'],
        business_name=data.get('business_name', ''),
        town=data.get('town', ''),
        street=data.get('street', ''),
        landmark=data.get('landmark', '')
    )

    # Add the user to the database
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201


@app.route('/admin/users', methods=['GET'])
@jwt_required
def get_all_users_with_details():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    users = User.query.all()
    user_details = []

    for user in users:
        user_data = {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'business_name': user.business_name,
            'town': user.town,
            'street': user.street,
            'landmark': user.landmark,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        }

        # Get associated orders with their details
        orders = []
        for order in user.orders:
            order_data = {
                'id': order.id,
                'order_date': order.order_date.strftime('%Y-%m-%d'),
                'order_status': order.order_status,
                'total_price': order.total_price,
            }
            
            # Get associated order details
            order_data['order_details'] = []
            for detail in order.order_details:
                product = Product.query.get(detail.product_id)
                detail_data = {
                    'product_id': detail.product_id,
                    'product_name': product.product_name if product else 'Product Not Found',
                    'quantity_ordered': detail.quantity_ordered,
                    'subtotal': detail.subtotal,
                }
                order_data['order_details'].append(detail_data)
            
            # Get associated delivery details
            order_data['deliveries'] = [
                {
                    'delivery_date': delivery.delivery_date.strftime('%Y-%m-%d'),
                    'delivery_status': delivery.delivery_status,
                    'recipient_name': delivery.recipient_name,
                }
                for delivery in order.deliveries
            ]
            # Get associated payment details
            order_data['payments'] = [
                {
                    'payment_date': payment.payment_date.strftime('%Y-%m-%d'),
                    'payment_due': payment.payment_due,
                    'payment_status': payment.payment_status,
                }
                for payment in order.payments
            ]
            orders.append(order_data)

        user_data['orders'] = orders
        user_details.append(user_data)

    return jsonify(user_details)


@app.route('/admin/users/<int:user_id>', methods=['GET'])
@jwt_required
def get_user_with_details(user_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get(user_id)

    if user is None:
        return jsonify({'error': 'User not found'}), 404

    user_data = {
        'id': user.id,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'business_name': user.business_name,
        'town': user.town,
        'street': user.street,
        'landmark': user.landmark,
        'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
    }

    # Get associated orders with order details
    orders = []
    for order in user.orders:
        order_details = {
            'id': order.id,
            'order_date': order.order_date.strftime('%Y-%m-%d'),
            'order_status': order.order_status,
            'total_price': order.total_price,
        }

        # Get order details with product names
        order_details['order_details'] = [
            {
                'product_id': detail.product_id,
                'product_name': Product.query.get(detail.product_id).product_name,  # Retrieve product name
                'quantity_ordered': detail.quantity_ordered,
                'subtotal': detail.subtotal,
            }
            for detail in order.order_details
        ]

        # Get associated deliveries
        order_details['deliveries'] = [
            {
                'delivery_date': delivery.delivery_date.strftime('%Y-%m-%d'),
                'delivery_status': delivery.delivery_status,
                'recipient_name': delivery.recipient_name,
            }
            for delivery in order.deliveries
        ]

        # Get associated payments
        order_details['payments'] = [
            {
                'payment_date': payment.payment_date.strftime('%Y-%m-%d'),
                'payment_due': payment.payment_due,
                'payment_status': payment.payment_status,
            }
            for payment in order.payments
        ]

        orders.append(order_details)

    user_data['orders'] = orders

    return jsonify(user_data)


@app.route('/admin/update-users/<int:user_id>', methods=['PATCH'])
@jwt_required
def update_user_by_id(user_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.json

    # Update user fields if they are provided in the request
    if 'first_name' in data:
        user.first_name = data['first_name']

    if 'last_name' in data:
        user.last_name = data['last_name']

    if 'username' in data:
        user.username = data['username']

    if 'email' in data:
        user.email = data['email']

    if 'address' in data:
        user.address = data['address']

    if 'phone_number' in data:
        user.phone_number = data['phone_number']

    if 'role' in data:
        user.role = data['role']

    if 'business_name' in data:
        user.business_name = data['business_name']

    if 'town' in data:
        user.town = data['town']

    if 'street' in data:
        user.street = data['street']

    if 'landmark' in data:
        user.landmark = data['landmark']

    db.session.commit()
    return jsonify({'message': 'User updated successfully'})


@app.route('/admin/delete-users/<int:user_id>', methods=['DELETE'])
@jwt_required
def delete_user_by_id(user_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'User deleted successfully'})


@app.route('/admin/create-products', methods=['POST'])
@jwt_required
def create_product():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    data = request.json

    new_product = Product(
        product_name=data['product_name'],
        description=data.get('description', ''),
        category=data['category'],
        price=data['price'],
        stock=data['stock'],
        image_path=data.get('image_path', '')
    )

    db.session.add(new_product)
    db.session.commit()

    return jsonify({'message': 'Product created successfully'}), 201


@app.route('/admin/update-products/<int:product_id>', methods=['PATCH'])
@jwt_required
def update_product(product_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    product = Product.query.get(product_id)

    if not product:
        return jsonify({'error': 'Product not found'}), 404

    data = request.json

    # Update product fields
    product.product_name = data.get('product_name', product.product_name)
    product.description = data.get('description', product.description)
    product.category = data.get('category', product.category)
    product.price = data.get('price', product.price)
    product.stock = data.get('stock', product.stock)
    product.image_path = data.get('image_path', product.image_path)

    db.session.commit()
    return jsonify({'message': 'Product updated successfully'})


@app.route('/admin/delete-products/<int:product_id>', methods=['DELETE'])
@jwt_required
def delete_product(product_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    product = Product.query.get(product_id)

    if not product:
        return jsonify({'error': 'Product not found'}), 404

    db.session.delete(product)
    db.session.commit()

    return jsonify({'message': 'Product deleted successfully'})


@app.route('/admin/customer_orders', methods=['GET'])
@jwt_required
def get_customer_orders():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    # Query all customer orders
    orders = Order.query.filter_by(order_status='completed').all()

    customer_orders = []

    for order in orders:
        customer = User.query.get(order.user_id)

        order_data = {
            'order_id': order.id,
            'order_date': order.order_date.strftime('%Y-%m-%d'),
            'total_price': order.total_price,
            'customer_name': f'{customer.first_name} {customer.last_name}',
            'customer_phone_no': customer.phone_number,
            'order_status': order.order_status,
            'order_details': []
        }

        # Get order details for the order
        order_details = OrderDetail.query.filter_by(order_id=order.id).all()
        for detail in order_details:
            product = Product.query.get(detail.product_id)
            detail_data = {
                'product_id': product.id,
                'product_name': product.product_name,
                'quantity_ordered': detail.quantity_ordered,
                'subtotal': detail.subtotal,
            }
            order_data['order_details'].append(detail_data)

        customer_orders.append(order_data)

    return jsonify(customer_orders)



if __name__ == '__main__':
    app.run(debug=True)

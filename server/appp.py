from flask import request, jsonify, Blueprint
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from server.models import db, User, RevokedToken

user_bp = Blueprint('user', __name__)

@user_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    role = data.get('role')
    
    # Check if the role is valid (should be 'corporate' or 'personal')
    if role not in ['corporate', 'personal']:
        return jsonify({'message': 'Invalid role'}), 400
    
    user = User(
        first_name=data['first_name'],
        last_name=data['last_name'],
        username=data['username'],
        password=generate_password_hash(data['password'], method='sha256'),
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

@user_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id, fresh=True)
        refresh_token = create_refresh_token(identity=user.id)
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@user_bp.route('/logout', methods=['POST'])
@jwt_required
def logout():
    jti = get_jwt_identity()
    revoked_token = RevokedToken(jti=jti)
    db.session.add(revoked_token)
    db.session.commit()
    return jsonify({'message': 'Successfully logged out'}), 200

@user_bp.route('/user/<int:id>', methods=['PATCH', 'GET', 'DELETE'])
@jwt_required
def user(id):
    current_user = User.query.get(id)
    
    if not current_user:
        return jsonify({'message': 'User not found'}), 404
    
    if current_user.id != get_jwt_identity():
        return jsonify({'message': 'Unauthorized'}), 401
    
    if request.method == 'PATCH':
        data = request.get_json()
        # Implement logic to update user details
        
    if request.method == 'GET':
        # Implement logic to retrieve user details
        pass

    if request.method == 'DELETE':
        db.session.delete(current_user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'}), 200

    return jsonify({'message': 'Method not allowed'}), 405

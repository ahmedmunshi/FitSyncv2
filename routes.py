from flask import Blueprint, request, jsonify
from models import User, Activity
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

auth_routes = Blueprint('auth', __name__)
activity_routes = Blueprint('activity', __name__)

# Registration route
@auth_routes.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    new_user = User(username=data['username'], password=generate_password_hash(data['password']))
    new_user.save()
    return jsonify(message='User registered successfully'), 201

# Login route
@auth_routes.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.objects(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        token = create_access_token(identity=str(user.id))
        return jsonify(token=token)
    return jsonify(message='Invalid credentials'), 401

# Fetch activities route
@activity_routes.route('/api/activities', methods=['GET'])
@jwt_required()
def get_activities():
    user_id = get_jwt_identity()
    activities = Activity.objects(user_id=user_id)
    return jsonify(activities), 200

# Add activity route
@activity_routes.route('/api/activities', methods=['POST'])
@jwt_required()
def add_activity():
    data = request.get_json()
    user_id = get_jwt_identity()
    new_activity = Activity(
        user_id=user_id,
        type=data['type'],
        distance=data['distance']
    )
    new_activity.save()
    return jsonify(message='Activity added successfully'), 201

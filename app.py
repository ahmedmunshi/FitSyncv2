import os
from flask import Flask, jsonify  # Import jsonify for JSON responses
from flask_mongoengine import MongoEngine
from flask_jwt_extended import JWTManager

# Initialize Flask application
app = Flask(__name__)

# MongoDB connection settings
app.config['MONGODB_SETTINGS'] = {
    'host': 'mongodb+srv://ahmedmunshi29:izoz2T3xV8E13qJg@fitsync1.jrl8r.mongodb.net/?retryWrites=true&w=majority&appName=FitSync1'
}

# JWT secret key
app.config['JWT_SECRET_KEY'] = 'mysecret141412'

# Initialize database and JWT manager
db = MongoEngine(app)
jwt = JWTManager(app)

# Import routes
from routes import auth_routes, activity_routes
app.register_blueprint(auth_routes)
app.register_blueprint(activity_routes)

# Define a root route
@app.route('/', methods=['GET'])
def home():
    return jsonify(message="Welcome to the FitSync API!"), 200

if __name__ == '__main__':
    app.run(port=5005)

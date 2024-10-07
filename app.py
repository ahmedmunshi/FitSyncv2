import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from flask_mongoengine import MongoEngine
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import jwt as pyjwt  # Import PyJWT library for manually decoding JWT tokens
from werkzeug.security import generate_password_hash, check_password_hash
from validate_email_address import validate_email
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()  # Load environment variables from .env file

# MongoDB configuration
app.config['MONGODB_SETTINGS'] = {
    'host': os.getenv('MONGODB_URI', 'your_default_mongodb_uri_here')
}

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'mysecret141412')

db = MongoEngine(app)
jwt = JWTManager(app)

# User model
class User(db.Document):
    username = db.StringField(required=True, unique=True)
    password = db.StringField(required=True)

# Activity model
class Activity(db.Document):
    user_id = db.ReferenceField(User, required=True)
    type = db.StringField(required=True)
    distance = db.FloatField(required=True)

# Home route
@app.route('/')
def home_page():
    return render_template('home.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    print("Request cookies:", request.cookies)  # Debug statement
    jwt_token = request.cookies.get('jwt')

    if not jwt_token:
        print("No JWT token found in cookies")  # Debug statement
        return "Token is missing", 401

    try:
        # Decode the JWT using PyJWT library
        claims = pyjwt.decode(jwt_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        print(f"Decoded JWT Claims: {claims}")  # Debug statement
        user_id = claims.get("sub")  # Get the user ID (subject) from claims
    except pyjwt.ExpiredSignatureError:
        print("JWT has expired")  # Debug statement
        return "Token has expired", 401
    except pyjwt.InvalidTokenError as e:
        print(f"JWT verification failed: {str(e)}")  # Debug statement
        return "Token is invalid", 401

    # Check if the user exists in the database
    user = User.objects(id=user_id).first()
    if not user:
        return "User not found", 401  # Debug statement

    activities = Activity.objects(user_id=user_id)
    print(f"Activities fetched: {activities}")  # Debug statement

    return render_template('dashboard.html', activities=activities)

# Add Activity route
@app.route('/add-activity', methods=['GET', 'POST'])
def add_activity():
    jwt_token = request.cookies.get('jwt')

    if not jwt_token:
        print("No JWT token found in cookies")  # Debug statement
        return "Token is missing", 401

    try:
        # Decode the JWT using PyJWT library
        claims = pyjwt.decode(jwt_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        print(f"Decoded JWT Claims: {claims}")  # Debug statement
        user_id = claims.get("sub")  # Get the user ID (subject) from claims
    except pyjwt.ExpiredSignatureError:
        print("JWT has expired")  # Debug statement
        return "Token has expired", 401
    except pyjwt.InvalidTokenError as e:
        print(f"JWT verification failed: {str(e)}")  # Debug statement
        return "Token is invalid", 401

    if request.method == 'POST':
        data = request.form
        new_activity = Activity(
            user_id=user_id,
            type=data['type'],
            distance=float(data['distance'])
        )
        new_activity.save()
        return redirect(url_for('dashboard'))

    return render_template('add_activity.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        email = data['username']  # Using username field for email
        print(f"Attempting login for email: {email}")  # Debug statement
        if not validate_email(email):
            return "Invalid email address", 400

        user = User.objects(username=email).first()
        if user:
            print(f"User found: {user.username}")  # Debug statement
            if check_password_hash(user.password, data['password']):
                print("Password match!")  # Debug statement
                token = create_access_token(identity=str(user.id))
                print(f"Generated JWT: {token}")  # Debug statement to see the generated token
                response = make_response(redirect(url_for('dashboard')))
                response.set_cookie('jwt', token, httponly=True, secure=False)  # Store token as HTTP-only cookie
                print(f"Set cookie: {response.headers.get('Set-Cookie')}")  # Debug statement to check cookie
                return response
            else:
                print("Password mismatch!")  # Debug statement
        else:
            print("User not found.")  # Debug statement

        return "Invalid credentials", 401
    return render_template('login.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        email = data['username']  # Using username field for email
        if not validate_email(email):
            return "Invalid email address", 400

        # Check if the username (email) already exists
        if User.objects(username=email).first():
            return "Username already exists. Please choose a different one.", 400

        new_user = User(
            username=email,
            password=generate_password_hash(data['password'])
        )
        new_user.save()
        return redirect(url_for('login'))
    return render_template('register.html')

# Profile route
@app.route('/profile')
def profile():
    jwt_token = request.cookies.get('jwt')

    if not jwt_token:
        return redirect(url_for('login'))

    try:
        claims = pyjwt.decode(jwt_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user_id = claims.get("sub")
    except pyjwt.ExpiredSignatureError:
        return redirect(url_for('login'))
    except pyjwt.InvalidTokenError:
        return redirect(url_for('login'))

    user = User.objects(id=user_id).first()
    if not user:
        return redirect(url_for('login'))

    return render_template('profile.html', user=user)

# Logout route
@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('home_page')))
    response.set_cookie('jwt', '', expires=0)
    return response



# Forgot Password route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.objects(username=email).first()  # Assuming username is the email
        if user:
            # Here you would typically send an email with a reset link.
            return "A reset link has been sent to your email address."  # Placeholder response
        return "Email not found.", 404
    return render_template('forgot_password.html')

if __name__ == '__main__':
    app.run(port=5005)

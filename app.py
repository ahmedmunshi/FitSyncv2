import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from flask_mongoengine import MongoEngine
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
import jwt as pyjwt  # Import PyJWT library for manually decoding JWT tokens
from werkzeug.security import generate_password_hash, check_password_hash
from validate_email_address import validate_email
from dotenv import load_dotenv
from datetime import datetime, timedelta
import pytz

app = Flask(__name__)
load_dotenv()  # Load environment variables from .env file

# MongoDB configuration
app.config['MONGODB_SETTINGS'] = {
    'host': os.getenv('MONGODB_URI', 'your_default_mongodb_uri_here')
}

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'mysecret141412')
app.config['JWT_COOKIE_SECURE'] = False  # Should be True in production
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'  # Make cookie sitewide
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)  # Extend the expiration

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
    date = db.DateTimeField(default=datetime.now(pytz.timezone('America/Toronto')))  # Default to Toronto's Eastern Time
    
# Home route
@app.route('/')
def home_page():
    return render_template('home.html')

# Dashboard route
@app.route('/dashboard')
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()
    user = User.objects(id=user_id).first()
    activities = Activity.objects(user_id=user_id)

    # Toronto timezone definition
    toronto_tz = pytz.timezone('America/Toronto')
    today = datetime.now(tz=toronto_tz).date()

    # Initialize lists to separate today's and past activities
    today_activities = []
    past_activities = []

    # Split activities into today's and past activities
    for activity in activities:
        if activity.date.date() == today:
            today_activities.append(activity)
        else:
            past_activities.append(activity)
    
    past_activities = sorted(past_activities, key=lambda activity: activity.date, reverse=True)

    # Return the dashboard page with the filtered activities
    return render_template('dashboard.html', today_activities=today_activities, past_activities=past_activities)


# Add Activity route
@app.route('/add-activity', methods=['GET', 'POST'])
@jwt_required()
def add_activity():
    user_id = get_jwt_identity()
    toronto_tz = pytz.timezone('America/Toronto') 
    today_date = datetime.today().strftime('%Y-%m-%d')

    if request.method == 'POST':
        data = request.form
        activity_date = data.get('date')

        if not activity_date:
            activity_date = today_date
        
        if activity_date:
            # Convert the date string to a datetime object with Toronto timezone
            
            activity_date = datetime.strptime(activity_date, '%Y-%m-%d')  # Convert string to datetime
            activity_date = toronto_tz.localize(activity_date)  # Localize the date to Toronto time
        else:
            # If no date is provided, set it to the current date in Toronto time
            activity_date = datetime.now(tz=toronto_tz)

        new_activity = Activity(
            user_id=user_id,
            type=data['type'],
            distance=float(data['distance']),
            date=activity_date
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
                response = make_response(redirect(url_for('profile')))
                set_access_cookies(response, token)
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
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.objects(id=user_id).first()
    return render_template('profile.html', user=user)

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

# Logout route
@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('home_page')))
    unset_jwt_cookies(response)
    return response

if __name__ == '__main__':
    app.run(debug=False, port=5005)
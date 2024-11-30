import os
from flask import Flask, render_template, request, redirect, url_for, make_response
from flask_mongoengine import MongoEngine
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
from werkzeug.security import generate_password_hash, check_password_hash
from validate_email_address import validate_email
from dotenv import load_dotenv
from datetime import datetime, timedelta
import pytz
from models import User, Activity, Weight  # Ensure models are imported

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


# Home route
@app.route('/')
def home_page():
    return render_template('home.html')


# Onboarding route
@app.route('/onboarding', methods=['GET', 'POST'])
@jwt_required()
def onboarding():
    user_id = get_jwt_identity()
    user = User.objects(id=user_id).first()

    # Redirect if the user is not new
    if not user.is_new_user:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        sample_workout = request.form.get('sample_workout')
        if sample_workout:
            # Save the sample activity
            new_activity = Activity(
                user_id=user,
                type="Sample Workout",
                distance=float(sample_workout),
                note="This is a sample activity"  # Default note for onboarding
            )
            new_activity.save()

            # Mark the user as no longer new
            user.is_new_user = False
            user.save()

            return redirect(url_for('dashboard'))

    return render_template('onboarding.html')


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
        note = data.get('note', "No notes added")  # Default value for note

        if not activity_date:
            activity_date = today_date

        if activity_date:
            # Convert the date string to a datetime object with Toronto timezone
            activity_date = datetime.strptime(activity_date, '%Y-%m-%d')
            activity_date = toronto_tz.localize(activity_date)
        else:
            activity_date = datetime.now(tz=toronto_tz)

        new_activity = Activity(
            user_id=user_id,
            type=data['type'],
            distance=float(data['distance']),
            date=activity_date,
            note=note  # Save the note
        )
        new_activity.save()
        return redirect(url_for('dashboard'))
    return render_template('add_activity.html', today_date=today_date)


# Dashboard route
@app.route('/dashboard')
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()
    try:
        activities = Activity.objects(user_id=user_id)

        # Ensure missing `note` fields are dynamically handled
        for activity in activities:
            if not hasattr(activity, 'note'):
                activity.note = "No notes added"

        # Toronto timezone definition
        toronto_tz = pytz.timezone('America/Toronto')
        today = datetime.now(toronto_tz).date()

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

        return render_template('dashboard.html', today_activities=today_activities, past_activities=past_activities)

    except Exception as e:
        print(f"Error occurred in dashboard: {e}")
        return render_template('error.html', message="An error occurred while loading the dashboard.")


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        email = data['username']
        password = data['password']

        user = User.objects(username=email).first()

        if user and check_password_hash(user.password, password):
            token = create_access_token(identity=str(user.id))
            response = make_response(redirect(url_for('onboarding' if user.is_new_user else 'dashboard')))
            set_access_cookies(response, token)
            return response

    return render_template('login.html')


# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        email = data['username']
        if not validate_email(email):
            return "Invalid email address", 400

        if User.objects(username=email).first():
            return "Username already exists. Please choose a different one.", 400

        new_user = User(
            username=email,
            password=generate_password_hash(data['password'])
        )
        new_user.save()
        return redirect(url_for('login'))
    return render_template('register.html')


# Add Weight Entry route
@app.route('/add-weight', methods=['GET', 'POST'])
@jwt_required()
def add_weight():
    user_id = get_jwt_identity()
    toronto_tz = pytz.timezone('America/Toronto')
    today_date = datetime.today().strftime('%Y-%m-%d')

    if request.method == 'POST':
        data = request.form
        weight_value = data.get('weight')
        weight_date = data.get('date', today_date)

        if weight_date:
            # Convert the date string to a datetime object with Toronto timezone
            weight_date = datetime.strptime(weight_date, '%Y-%m-%d')
            weight_date = toronto_tz.localize(weight_date)
        else:
            weight_date = datetime.now(tz=toronto_tz)

        new_weight_entry = Weight(
            user_id=user_id,
            weight=float(weight_value),
            date=weight_date
        )
        new_weight_entry.save()
        return redirect(url_for('weight_history'))

    return render_template('add_weight.html', today_date=today_date)


# Weight History route
@app.route('/weight-history')
@jwt_required()
def weight_history():
    user_id = get_jwt_identity()
    try:
        weights = Weight.objects(user_id=user_id)

        # Calculate weight trend
        weight_entries = list(weights)
        if weight_entries:
            current_weight = weight_entries[0].weight
            initial_weight = weight_entries[-1].weight
            weight_change = current_weight - initial_weight
        else:
            current_weight = initial_weight = weight_change = None

        return render_template('weight_history.html',
                               weights=weights,
                               current_weight=current_weight,
                               initial_weight=initial_weight,
                               weight_change=weight_change)

    except Exception as e:
        print(f"Error occurred in weight history: {e}")
        return render_template('error.html', message="An error occurred while loading weight history.")

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
        user = User.objects(username=email).first()
        if user:
            return "A reset link has been sent to your email address."
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

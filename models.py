from mongoengine import Document, StringField, ReferenceField, DateTimeField, FloatField, BooleanField
from datetime import datetime
import pytz

class User(Document):
    username = StringField(required=True, unique=True)
    password = StringField(required=True)
    is_new_user = BooleanField(default=True)  # Track if the user is new

class Activity(Document):
    user_id = ReferenceField(User, required=True)
    type = StringField(required=True)
    distance = FloatField(required=True)
    date = DateTimeField(default=datetime.utcnow)
    note = StringField(default="No notes added")  # Add default value for note


class Weight(Document):
    user_id = ReferenceField(User, required=True)
    weight = FloatField(required=True)  # Store weight in kg or lbs
    date = DateTimeField(default=datetime.now(tz=pytz.timezone('America/Toronto')))

    meta = {
        'collection': 'weights',
        'ordering': ['-date']  # Sort by most recent first
    }
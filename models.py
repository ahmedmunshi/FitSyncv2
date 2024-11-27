from mongoengine import Document, StringField, ReferenceField, DateTimeField, FloatField, BooleanField
from datetime import datetime

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

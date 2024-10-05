from mongoengine import Document, StringField, ReferenceField, DateTimeField, FloatField
from datetime import datetime

class User(Document):
    username = StringField(required=True, unique=True)
    password = StringField(required=True)

class Activity(Document):
    user_id = ReferenceField(User)
    type = StringField(required=True)
    distance = FloatField(required=True)
    date = DateTimeField(default=datetime.utcnow)

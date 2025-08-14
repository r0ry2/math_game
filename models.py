from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()#حلقة الوصل بين Flask وقاعدة البيانات

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)#Pk
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    display_name = db.Column(db.String(100), nullable=True)


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.Text, nullable=False)
    choice1 = db.Column(db.String(200), nullable=False)
    choice2 = db.Column(db.String(200), nullable=False)
    choice3 = db.Column(db.String(200), nullable=False)
    choice4 = db.Column(db.String(200), nullable=False)
    correct_answer = db.Column(db.String(200), nullable=False)  

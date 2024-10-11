from flask import Flask, render_template, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit, join_room, leave_room
from datetime import datetime
from flask import redirect, url_for, request
from flask_login import current_user

app = Flask(__name__)
app.secret_key = 'some_secret_key'  # This should be a random secret string
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///c:/Users/wills/production/apps/messaging_app_2/database/site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*")

friends = db.Table('friends',
                   db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                   db.Column('friend_id', db.Integer, db.ForeignKey('user.id')))

# Define User and Friend models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    friends = db.relationship('User', secondary='friends',
                              primaryjoin=(id == friends.c.user_id),
                              secondaryjoin=(id == friends.c.friend_id))

# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

from wtforms.validators import Email

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email')
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')
    submit = SubmitField('Register')

# Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient = db.relationship('User', foreign_keys=[recipient_id])
    content = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"Message('{self.sender.username}', '{self.recipient.username}', '{self.content}', '{self.timestamp}')"

# Handle user loading
@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))

@app.errorhandler(401)
def unauthorized(e):
    # If the user is not authenticated and tries to access a protected page,
    # redirect them to the login page with a next parameter to redirect them back
    # to the page they tried to access after logging in.
    return redirect(url_for('login', next=request.endpoint))


@app.route('/')
def index():
    return render_template('index.html', current_user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')  # Get the next page to redirect to
            return redirect(next_page or url_for('chat'))  # Redirect to the next page or chat if next is None
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_friend', methods=['POST'])
@login_required
def add_friend():
    friend_name = request.form.get('friend_name')
    friend = User.query.filter_by(username=friend_name).first()
    if friend and friend not in current_user.friends:
        current_user.friends.append(friend)
        friend.friends.append(current_user)  # Add this line
        db.session.commit()
    return redirect(url_for('chat'))

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', current_user=current_user)

@app.route('/passwordreset', methods=['GET', 'POST'])
def passwordreset():
    return render_template('passwordreset.html', current_user=current_user)

from flask import jsonify
from sqlalchemy import and_


from sqlalchemy import or_, and_

def fetch_chat_history(user1_username, user2_username, limit, offset):
    user1 = User.query.filter_by(username=user1_username).first()
    user2 = User.query.filter_by(username=user2_username).first()

    if user1 and user2:
        # Retrieve a limited chat history between user1 and user2 with offset
        chat_history = Message.query.filter(
            or_(
                and_(Message.sender_id == user1.id, Message.recipient_id == user2.id),
                and_(Message.sender_id == user2.id, Message.recipient_id == user1.id)
            )
        ).order_by(Message.timestamp.desc()).limit(limit).offset(offset).all()

        # Format chat history as a list of dictionaries
        chat_history_formatted = [
            {
                'sender': message.sender.username,
                'recipient': message.recipient.username,
                'content': message.content,
                'timestamp': message.timestamp.isoformat()
            }
            for message in chat_history
        ]

        return chat_history_formatted
    else:
        return []


# Import 'or_' to use in the query
from sqlalchemy import or_

@app.route('/get_chat_history/<string:friend_username>/<int:limit>/<int:offset>')
@login_required
def get_chat_history(friend_username, limit, offset):
    friend = User.query.filter_by(username=friend_username).first()
    if friend and friend in current_user.friends:
        chat_history = fetch_chat_history(current_user.username, friend_username, limit, offset)
        return jsonify({'chatHistory': chat_history})
    return jsonify({'error': 'Friend not found or not in friends list'})

@socketio.on('join', namespace='/chat')
@login_required
def on_join():
    for friend in current_user.friends:
        room = '-'.join(sorted([current_user.username, friend.username]))
        join_room(room)
        print(f"User {current_user.username} joined room: {room}")

@app.route('/rooms')
@login_required
def rooms():
    from flask_socketio import rooms
    print(rooms())
    return ', '.join(rooms())


@socketio.on('private_message', namespace='/chat')
@login_required
def private_message(payload):
    print(f"Received message for: {payload['to']} with content: {payload['message']}")
    recipient = User.query.filter_by(username=payload['to']).first()
    if recipient and recipient in current_user.friends:
        room = '-'.join(sorted([current_user.username, recipient.username]))
        message = Message(sender_id=current_user.id, recipient_id=recipient.id, content=payload['message'])
        db.session.add(message)
        db.session.commit()
        # Emit the message to the room. This will send it to both the sender and recipient.
        # The sender's frontend will display it as a sent message, and the recipient's frontend will display it as a received message.
        emit('new_private_message', {'from': current_user.username, 'message': payload['message']}, room=room)
        print(f"Emitted message to room: {room}")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables
    socketio.run(app, port=5015, debug=True)
from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_simple_captcha import CAPTCHA
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
db = SQLAlchemy(app)
with app.app_context():
    db.create_all()
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

YOUR_CONFIG = {
    'SECRET_CAPTCHA_KEY': 'LONGLONGKEY',
    'CAPTCHA_LENGTH': 6,
    'CAPTCHA_DIGITS': False,
    'EXPIRE_SECONDS': 600,
}
SIMPLE_CAPTCHA = CAPTCHA(config=YOUR_CONFIG)
app = SIMPLE_CAPTCHA.init_app(app)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    rules = db.Column(db.Text, default='')
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    owner = db.relationship('User')

class ChannelModerator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class ChannelBan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class PrivateRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])

# Login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.template_filter()
def year(s):
    return str(datetime.date.today().year)

# Routes
@app.route('/')
@login_required
def index():
    channels = Channel.query.all()
    private_rooms = PrivateRoom.query.filter(
        (PrivateRoom.user1_id == current_user.id) |
        (PrivateRoom.user2_id == current_user.id)
    ).all()
    return render_template('index.html', channels=channels, private_rooms=private_rooms)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        new_captcha_dict = SIMPLE_CAPTCHA.create()
    if request.method == 'POST':
        c_hash = request.form.get('captcha-hash')
        c_text = request.form.get('captcha-text')
        if not SIMPLE_CAPTCHA.verify(c_text, c_hash):
            flash("Are you robot?")
            return redirect(url_for("register"))
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(username=username).first():
            flash('User already exists')
            return redirect(url_for('register'))
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html', captcha=new_captcha_dict)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/channel/")
def redir_channel():
    return redirect("/channel/" + request.args["name"])

@app.route('/private/')
@login_required
def redir_private():
    return redirect('/private/' + request.args['username'])

@app.route('/channel/<name>')
@login_required
def channel(name):
    chan = Channel.query.filter_by(name=name).first()
    if not chan:
        chan = Channel(name=name, owner=current_user)
        db.session.add(chan)
        db.session.commit()
    if ChannelBan.query.filter_by(channel_id=chan.id, user_id=current_user.id).first():
        return "You are banned from this channel."
    rules = chan.rules
    return render_template('channel.html', channel=chan, rules=rules)

@app.route('/channel/<name>/rules', methods=['POST'])
@login_required
def update_rules(name):
    chan = Channel.query.filter_by(name=name).first()
    if chan and (chan.owner == current_user or current_user.is_admin):
        chan.rules = request.form['rules']
        db.session.commit()
    return redirect(url_for('channel', name=name))

@app.route('/channel/<name>/moderate', methods=['POST'])
@login_required
def moderate(name):
    chan = Channel.query.filter_by(name=name).first()
    action = request.form['action']
    username = request.form['username']
    user = User.query.filter_by(username=username).first()
    if not chan or not user:
        return 'Error'
    if chan.owner != current_user and not current_user.is_admin:
        return 'Permission denied'

    if action == 'ban':
        db.session.add(ChannelBan(channel_id=chan.id, user_id=user.id))
    elif action == 'unban':
        ChannelBan.query.filter_by(channel_id=chan.id, user_id=user.id).delete()

    db.session.commit()
    return redirect(url_for('channel', name=name))

@app.route('/private/<username>')
@login_required
def private_chat(username):
    other = User.query.filter_by(username=username).first()
    if not other:
        flash('User not found')
        return redirect(url_for('index'))
    if other.id == current_user.id:
        flash('Cannot chat with yourself')
        return redirect(url_for('index'))
    room = PrivateRoom.query.filter(
        ((PrivateRoom.user1_id == current_user.id) & (PrivateRoom.user2_id == other.id)) |
        ((PrivateRoom.user1_id == other.id) & (PrivateRoom.user2_id == current_user.id))
    ).first()
    if not room:
        room = PrivateRoom(user1=current_user, user2=other)
        db.session.add(room)
        db.session.commit()
    return redirect(url_for('private_by_id', room_id=room.id))

@app.route('/p/<int:room_id>')
@login_required
def private_by_id(room_id):
    room = PrivateRoom.query.get(room_id)
    if not room or current_user.id not in [room.user1_id, room.user2_id]:
        flash('Chat not found')
        return redirect(url_for('index'))
    other = room.user2 if room.user1_id == current_user.id else room.user1
    return render_template('private.html', room=room, other=other)

# SocketIO
@socketio.on('join')
@login_required
def on_join(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': f'{current_user.username} has joined the channel.'}, room=room)

@socketio.on('leave')
@login_required
def on_leave(data):
    room = data['room']
    leave_room(room)
    emit('status', {'msg': f'{current_user.username} has left the channel.'}, room=room)

@socketio.on('message')
@login_required
def handle_message(data):
    room = data['room']
    if room.startswith('private_'):
        emit('message', {'msg': f'{current_user.username}: {data["msg"]}'}, room=room)
        return
    chan = Channel.query.filter_by(name=room).first()
    if ChannelBan.query.filter_by(channel_id=chan.id, user_id=current_user.id).first():
        return
    emit('message', {'msg': f'{current_user.username}: {data["msg"]}'}, room=room)

if __name__ == '__main__':
    socketio.run(app, debug=True)

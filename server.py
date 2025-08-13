from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from models import db, User, ConnectedUser
import os

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
socketio = SocketIO(app)

connected_users = set()

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'])

@app.route('/logout')
def logout():
    username = session.get('username')
    if username:
        user = ConnectedUser.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
        connected_users.discard(username)
    session.clear()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session['username'] = username
            return redirect(url_for('index'))
        return render_template('auth.html', register=False, message="Credenciales inválidas")
    return render_template('auth.html', register=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return render_template('auth.html', register=True, message="Usuario ya existe")
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        return redirect(url_for('index'))
    return render_template('auth.html', register=True)

@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    if username:
        connected_users.add(username)
        if not ConnectedUser.query.filter_by(username=username).first():
            db.session.add(ConnectedUser(username=username))
            db.session.commit()
        emit('update_users', list(connected_users), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username:
        connected_users.discard(username)
        user = ConnectedUser.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
        emit('update_users', list(connected_users), broadcast=True)

@socketio.on('start_call')
def handle_start_call(data):
    emit('incoming_call', {
        'caller': session.get('username'),
        'call_type': data['call_type'],
        'room': data['room']
    }, to=data['target_user'])

@socketio.on('accept_call')
def handle_accept_call(data):
    emit('call_accepted', {
        'room': data['room'],
        'call_type': data['call_type']
    }, to=data['caller'])

@socketio.on('reject_call')
def handle_reject_call(data):
    emit('call_rejected', {}, to=data['caller'])

@socketio.on('end_call')
def handle_end_call(data):
    emit('call_ended', {}, room=data['room'])

@socketio.on('webrtc_signal')
def handle_webrtc_signal(data):
    emit('webrtc_signal', data, to=data['target'])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000)
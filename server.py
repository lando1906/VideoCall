from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
import time
from gevent import monkey
import uuid

monkey.patch_all()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret-key')
app.config['UPLOAD_FOLDER'] = 'static/uploads'

socketio = SocketIO(app, async_mode='gevent', cors_allowed_origins="*")

# Database setup
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE NOT NULL,
                     password TEXT NOT NULL,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                     )''')
        conn.commit()

init_db()

# Global variables
online_users = set()
active_calls = {}

# Routes
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('auth', mode='login'))
    return render_template('index.html', username=session['username'])

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    mode = request.args.get('mode', 'login')
    
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        with get_db_connection() as conn:
            if request.form['action'] == 'login':
                user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                if user and check_password_hash(user['password'], password):
                    session['username'] = username
                    return redirect(url_for('index'))
                return render_template('auth.html', error='Credenciales inválidas', mode='login')
            
            elif request.form['action'] == 'register':
                existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                if existing_user:
                    return render_template('auth.html', error='Usuario ya existe', mode='register')
                
                conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                            (username, generate_password_hash(password)))
                conn.commit()
                session['username'] = username
                return redirect(url_for('index'))
    
    return render_template('auth.html', mode=mode)

@app.route('/logout')
def logout():
    username = session.pop('username', None)
    if username in online_users:
        online_users.remove(username)
        emit('update_users', list(online_users), broadcast=True)
    
    # End all active calls for this user
    for room_id, call_data in list(active_calls.items()):
        if username in [call_data['caller'], call_data['callee']]:
            emit('call_ended', {'room_id': room_id}, room=room_id)
            del active_calls[room_id]
    
    return redirect(url_for('auth', mode='login'))

# Socket.IO Events
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        username = session['username']
        if username not in online_users:
            online_users.add(username)
            emit('update_users', list(online_users), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session and session['username'] in online_users:
        username = session['username']
        online_users.remove(username)
        emit('update_users', list(online_users), broadcast=True)
        
        # End all active calls for this user
        for room_id, call_data in list(active_calls.items()):
            if username in [call_data['caller'], call_data['callee']]:
                emit('call_ended', {'room_id': room_id}, room=room_id)
                del active_calls[room_id]

@socketio.on('start_call')
def handle_start_call(data):
    caller = session['username']
    target_user = data['target_user']
    call_type = data['call_type']
    room_id = f"call_{caller}_{target_user}_{int(time.time())}"
    
    if target_user in online_users:
        active_calls[room_id] = {
            'caller': caller,
            'callee': target_user,
            'type': call_type,
            'status': 'ringing'
        }
        
        emit('incoming_call', {
            'caller': caller,
            'call_type': call_type,
            'room_id': room_id
        }, room=target_user)
        
        emit('call_initiated', {
            'room_id': room_id,
            'target_user': target_user
        }, room=caller)
    else:
        emit('call_failed', {
            'reason': 'El usuario no está disponible',
            'target_user': target_user
        }, room=caller)

@socketio.on('accept_call')
def handle_accept_call(data):
    room_id = data['room_id']
    callee = session['username']
    
    if room_id in active_calls and active_calls[room_id]['callee'] == callee:
        active_calls[room_id]['status'] = 'accepted'
        join_room(room_id)
        emit('join_room', {'room_id': room_id}, room=active_calls[room_id]['caller'])
        
        emit('call_accepted', {
            'room_id': room_id,
            'callee': callee,
            'call_type': active_calls[room_id]['type']
        }, room=active_calls[room_id]['caller'])
    else:
        emit('call_ended', {
            'reason': 'La llamada ya no está disponible',
            'room_id': room_id
        }, room=callee)

@socketio.on('reject_call')
def handle_reject_call(data):
    room_id = data.get('room_id')
    if room_id in active_calls:
        emit('call_rejected', {
            'room_id': room_id,
            'caller': active_calls[room_id]['caller'],
            'reason': 'Llamada rechazada'
        }, room=active_calls[room_id]['caller'])
        
        emit('call_ended', {
            'reason': 'Llamada rechazada',
            'room_id': room_id
        }, room=active_calls[room_id]['callee'])
        
        del active_calls[room_id]

@socketio.on('end_call')
def handle_end_call(data):
    room_id = data['room_id']
    if room_id in active_calls:
        emit('call_ended', {
            'room_id': room_id,
            'reason': 'Llamada finalizada'
        }, room=room_id)
        
        if room_id in active_calls:
            del active_calls[room_id]

@socketio.on('join_room')
def handle_join_room(data):
    join_room(data['room_id'])

@socketio.on('webrtc_signal')
def handle_webrtc_signal(data):
    room_id = data['room_id']
    target = data.get('target')
    
    # Reenviar señal al destinatario específico o a toda la sala
    if target:
        emit('webrtc_signal', data, room=target)
    else:
        emit('webrtc_signal', data, room=room_id)

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
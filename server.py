from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from gevent import monkey
import uuid

# Configuración inicial
monkey.patch_all()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'tu-clave-secreta-aqui')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

socketio = SocketIO(app, async_mode='gevent', cors_allowed_origins="*")

# Helpers
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Inicialización de la base de datos
def init_db():
    with get_db_connection() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT UNIQUE NOT NULL,
                     password TEXT NOT NULL,
                     avatar TEXT,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                     )''')
        conn.commit()

init_db()

# Usuarios conectados y llamadas activas
online_users = set()
active_calls = {}

# Rutas principales
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('auth', mode='login'))
    
    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE username = ?', (session['username'],)).fetchone()
    
    return render_template('index.html', username=session['username'])

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    mode = request.args.get('mode', 'login')
    if mode not in ['login', 'register']:
        mode = 'login'

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        action = request.form['action']
        
        with get_db_connection() as conn:
            if action == 'login':
                user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                if user and check_password_hash(user['password'], password):
                    session['username'] = username
                    return redirect(url_for('index'))
                return render_template('auth.html', error='Usuario o contraseña incorrectos', mode='login')
            
            elif action == 'register':
                # Verificar si el usuario ya existe
                existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                if existing_user:
                    return render_template('auth.html', error='El nombre de usuario ya está en uso', mode='register')
                
                # Manejar el avatar
                avatar_filename = 'default-avatar.png'
                if 'avatar' in request.files and request.files['avatar'].filename:
                    file = request.files['avatar']
                    if file and allowed_file(file.filename):
                        ext = file.filename.rsplit('.', 1)[1].lower()
                        avatar_filename = f"{uuid.uuid4().hex}.{ext}"
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], avatar_filename))
                
                # Crear nuevo usuario
                conn.execute('INSERT INTO users (username, password, avatar) VALUES (?, ?, ?)',
                           (username, generate_password_hash(password), avatar_filename))
                conn.commit()
                
                session['username'] = username
                return redirect(url_for('index'))
    
    return render_template('auth.html', mode=mode)

@app.route('/logout')
def logout():
    username = session.pop('username', None)
    if username in online_users:
        online_users.remove(username)
        emit('update_users', list(online_users), broadcast=True, namespace='/')
    
    # Terminar cualquier llamada activa
    for room, users in active_calls.items():
        if username in users:
            emit('call_ended', room=room)
            del active_calls[room]
            break
    
    return redirect(url_for('auth', mode='login'))

# WebSocket events
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        username = session['username']
        if username not in online_users:
            online_users.add(username)
            emit('update_users', list(online_users), broadcast=True, namespace='/')

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session and session['username'] in online_users:
        username = session['username']
        online_users.remove(username)
        emit('update_users', list(online_users), broadcast=True, namespace='/')
        
        # Terminar llamadas si el usuario se desconecta
        for room, users in active_calls.items():
            if username in users:
                emit('call_ended', room=room)
                del active_calls[room]
                break

@socketio.on('start_call')
def handle_start_call(data):
    caller = session['username']
    target_user = data['target_user']
    call_type = data['call_type']
    
    if target_user in online_users:
        room = f"{caller}_{target_user}"
        active_calls[room] = [caller, target_user]
        emit('incoming_call', {'caller': caller, 'call_type': call_type}, room=target_user)
    else:
        emit('call_rejected', room=caller)

@socketio.on('accept_call')
def handle_accept_call(data):
    caller = data['caller']
    call_type = data['call_type']
    target_user = session['username']
    room = f"{caller}_{target_user}"
    
    join_room(room)
    emit('join_room', {'room': room}, room=caller)
    
    emit('call_accepted', {'room': room, 'call_type': call_type}, room=caller)

@socketio.on('reject_call')
def handle_reject_call(data):
    caller = data['caller']
    emit('call_rejected', room=caller)

@socketio.on('end_call')
def handle_end_call(data):
    room = data['room']
    emit('call_ended', room=room)
    if room in active_calls:
        del active_calls[room]

@socketio.on('join_room')
def handle_join_room(data):
    join_room(data['room'])

@socketio.on('webrtc_signal')
def handle_webrtc_signal(data):
    room = data['room']
    emit('webrtc_signal', data, room=room)

if __name__ == '__main__':
    # Crear directorio de uploads si no existe
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True)
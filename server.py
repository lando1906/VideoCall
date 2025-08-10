from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from gevent import monkey
from socketio import WSGIApp

# Parchear para soportar WebSocket en producción
monkey.patch_all()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'tu-clave-secreta')
socketio = SocketIO(app, async_mode='gevent', cors_allowed_origins="*")

# Configuración de SQLite
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password TEXT NOT NULL,
                 avatar TEXT  -- Campo para almacenar la ruta del avatar (opcional)
                 )''')
    conn.commit()
    conn.close()

init_db()

# Usuarios conectados
online_users = set()

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('auth', mode='login'))
    return render_template('index.html', username=session['username'])

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    mode = request.args.get('mode', 'login')
    if mode not in ['login', 'register']:
        mode = 'login'

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        action = request.form['action']
        avatar = request.form.get('avatar', 'default-avatar.png')  # Simulación de avatar
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        if action == 'login':
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            if user and check_password_hash(user[2], password):
                session['username'] = username
                conn.close()
                return redirect(url_for('index'))
            conn.close()
            return render_template('auth.html', error='Credenciales inválidas', mode='login')
        elif action == 'register':
            try:
                c.execute("INSERT INTO users (username, password, avatar) VALUES (?, ?, ?)",
                         (username, generate_password_hash(password), avatar))
                conn.commit()
                session['username'] = username
                conn.close()
                return redirect(url_for('index'))
            except sqlite3.IntegrityError:
                conn.close()
                return render_template('auth.html', error='Usuario ya existe', mode='register')
    return render_template('auth.html', mode=mode)

@app.route('/logout')
def logout():
    username = session.pop('username', None)
    if username:
        online_users.discard(username)
        socketio.emit('update_users', list(online_users))
    return redirect(url_for('auth', mode='login'))

@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        online_users.add(session['username'])
        emit('update_users', list(online_users), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        online_users.discard(session['username'])
        emit('update_users', list(online_users), broadcast=True)

@socketio.on('start_call')
def handle_start_call(data):
    target_user = data['target_user']
    call_type = data['call_type']  # 'video' o 'audio'
    caller = session['username']
    emit('incoming_call', {'caller': caller, 'call_type': call_type}, to=target_user)

@socketio.on('accept_call')
def handle_accept_call(data):
    caller = data['caller']
    call_type = data['call_type']
    target_user = session['username']
    room = f"{caller}_{target_user}"
    emit('call_accepted', {'room': room, 'call_type': call_type}, to=caller)

@socketio.on('reject_call')
def handle_reject_call(data):
    caller = data['caller']
    emit('call_rejected', to=caller)

@socketio.on('end_call')
def handle_end_call(data):
    room = data['room']
    emit('call_ended', room=room)

@socketio.on('webrtc_signal')
def handle_webrtc_signal(data):
    room = data['room']
    emit('webrtc_signal', data, room=room)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
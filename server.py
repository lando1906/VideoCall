from flask import Flask, request, jsonify, send_from_directory, session
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import sqlite3
import os
import bcrypt
import uuid
from datetime import datetime
import ffmpeg
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuración de directorios
UPLOAD_FOLDER = 'uploads'
THUMBNAIL_FOLDER = 'thumbnails'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(THUMBNAIL_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['THUMBNAIL_FOLDER'] = THUMBNAIL_FOLDER

# Configuración de SQLite
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        avatar TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        video_path TEXT NOT NULL,
        thumbnail_path TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    conn.commit()
    conn.close()

init_db()

# Middleware para obtener el ID de Socket.IO
def get_socket_id():
    return request.headers.get('X-Socket-Id')

# Rutas de autenticación
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')

    if not email or not password or not name:
        return jsonify({'success': False, 'message': 'Faltan datos'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
                  (email, hashed_password, name))
        conn.commit()
        user_id = c.lastrowid
        session['user_id'] = user_id
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'El correo ya está registrado'}), 400
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT id, password, name, avatar FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[1]):
        session['user_id'] = user[0]
        return jsonify({
            'success': True,
            'user': {'name': user[2], 'avatar': user[3], 'email': email}
        })
    return jsonify({'success': False, 'message': 'Correo o contraseña incorrectos'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'success': True})

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'user_id' in session:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT name, avatar, email FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        if user:
            return jsonify({
                'authenticated': True,
                'user': {'name': user[0], 'avatar': user[1], 'email': user[2]}
            })
    return jsonify({'authenticated': False})

# Rutas de videos
@app.route('/api/upload', methods=['POST'])
def upload_video():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'No autenticado'}), 401

    title = request.form.get('title')
    video = request.files.get('video')
    if not title or not video:
        return jsonify({'success': False, 'message': 'Faltan datos'}), 400

    video_filename = f"{uuid.uuid4()}_{video.filename}"
    video_path = os.path.join(app.config['UPLOAD_FOLDER'], video_filename)
    video.save(video_path)

    # Generar miniatura
    thumbnail_filename = f"{uuid.uuid4()}.jpg"
    thumbnail_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumbnail_filename)
    try:
        stream = ffmpeg.input(video_path, ss=1)
        stream = ffmpeg.output(stream, thumbnail_path, vframes=1, format='image2', vcodec='mjpeg')
        ffmpeg.run(stream)
    except ffmpeg.Error as e:
        return jsonify({'success': False, 'message': 'Error al generar miniatura'}), 500

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO videos (user_id, title, video_path, thumbnail_path, created_at) VALUES (?, ?, ?, ?, ?)',
              (session['user_id'], title, video_path, thumbnail_path, datetime.utcnow().isoformat()))
    video_id = c.lastrowid
    conn.commit()

    c.execute('SELECT name FROM users WHERE id = ?', (session['user_id'],))
    author = c.fetchone()[0]
    conn.close()

    video_data = {
        'id': video_id,
        'title': title,
        'author': author,
        'video_url': f"/uploads/{video_filename}",
        'thumbnail': f"/thumbnails/{thumbnail_filename}"
    }
    socketio.emit('video_uploaded', video_data, to=get_socket_id())
    return jsonify({'success': True, 'video': video_data})

@app.route('/api/videos', methods=['GET'])
def get_videos():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT v.id, v.title, v.video_path, v.thumbnail_path, u.name FROM videos v JOIN users u ON v.user_id = u.id')
    videos = [{
        'id': row[0],
        'title': row[1],
        'video_url': f"/{row[2]}",
        'thumbnail': f"/{row[3]}",
        'author': row[4]
    } for row in c.fetchall()]
    conn.close()
    return jsonify(videos)

@app.route('/api/user-videos', methods=['GET'])
def get_user_videos():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'No autenticado'}), 401
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT id, title, video_path, thumbnail_path FROM videos WHERE user_id = ?', (session['user_id'],))
    videos = [{
        'id': row[0],
        'title': row[1],
        'video_url': f"/{row[2]}",
        'thumbnail': f"/{row[3]}",
        'author': 'Tú'
    } for row in c.fetchall()]
    conn.close()
    return jsonify(videos)

@app.route('/api/delete-video/<int:video_id>', methods=['DELETE'])
def delete_video(video_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'No autenticado'}), 401

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT video_path, thumbnail_path FROM videos WHERE id = ? AND user_id = ?', (video_id, session['user_id']))
    video = c.fetchone()
    if not video:
        conn.close()
        return jsonify({'success': False, 'message': 'Video no encontrado o no autorizado'}), 404

    try:
        os.remove(video[0])
        os.remove(video[1])
    except OSError:
        pass

    c.execute('DELETE FROM videos WHERE id = ?', (video_id,))
    conn.commit()
    conn.close()

    socketio.emit('video_deleted', video_id, broadcast=True)
    return jsonify({'success': True})

# Actualizar perfil
@app.route('/api/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'No autenticado'}), 401

    name = request.form.get('name')
    avatar = request.files.get('avatar')
    avatar_path = None

    if avatar:
        avatar_filename = f"{uuid.uuid4()}_{avatar.filename}"
        avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], avatar_filename)
        avatar.save(avatar_path)

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if avatar_path:
        c.execute('UPDATE users SET name = ?, avatar = ? WHERE id = ?', (name, f"/uploads/{avatar_filename}", session['user_id']))
    else:
        c.execute('UPDATE users SET name = ? WHERE id = ?', (name, session['user_id']))
    conn.commit()
    c.execute('SELECT name, avatar FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()

    user_data = {'name': user[0], 'avatar': user[1]}
    socketio.emit('profile_updated', user_data, broadcast=True)
    return jsonify({'success': True, 'avatar': user_data['avatar']})

# Servir archivos estáticos
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/auth.html')
def serve_auth():
    return send_from_directory('.', 'auth.html')

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/thumbnails/<path:filename>')
def serve_thumbnail(filename):
    return send_from_directory(app.config['THUMBNAIL_FOLDER'], filename)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
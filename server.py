import os
from flask import Flask, request, jsonify, send_from_directory, render_template, redirect
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Configuración de Flask
app = Flask(__name__,
            static_folder='static',
            template_folder='templates')

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret-key-dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max para avatares

# Asegurar que la carpeta de uploads existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Inicializar extensiones
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Modelos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    display_name = db.Column(db.String(80), nullable=False)
    avatar = db.Column(db.String(120))
    online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

# Helpers
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_avatar(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        return unique_filename
    return None

# Rutas de páginas
@app.route('/')
def home():
    return redirect('/auth')

@app.route('/auth')
def auth_page():
    return render_template('auth.html')

@app.route('/chat')
def chat_page():
    return render_template('chat.html')

# API Routes
@app.route('/api/users')
def get_users():
    exclude_id = request.args.get('exclude')
    users = User.query.filter(User.id != exclude_id).all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'display_name': user.display_name,
        'avatar': user.avatar,
        'online': user.online
    } for user in users])

@app.route('/api/chats')
def get_chats():
    user_id = request.args.get('user_id')
    messages = Message.query.filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).order_by(Message.timestamp.desc()).all()

    chats = {}
    for msg in messages:
        other_user_id = msg.receiver_id if msg.sender_id == int(user_id) else msg.sender_id
        if other_user_id not in chats:
            user = User.query.get(other_user_id)
            chats[other_user_id] = {
                'id': f"{min(int(user_id), other_user_id)}-{max(int(user_id), other_user_id)}",
                'unread_count': 0,
                'last_message': None,
                'participant': {
                    'id': user.id,
                    'display_name': user.display_name,
                    'avatar': user.avatar,
                    'online': user.online
                }
            }

        if not chats[other_user_id]['last_message']:
            chats[other_user_id]['last_message'] = {
                'content': msg.content,
                'timestamp': msg.timestamp.isoformat(),
                'read': msg.read
            }

        if not msg.read and msg.receiver_id == int(user_id):
            chats[other_user_id]['unread_count'] += 1

    return jsonify(list(chats.values()))

@app.route('/api/messages')
def get_messages():
    chat_id = request.args.get('chat_id')
    user1_id, user2_id = map(int, chat_id.split('-'))

    messages = Message.query.filter(
        ((Message.sender_id == user1_id) & (Message.receiver_id == user2_id)) |
        ((Message.sender_id == user2_id) & (Message.receiver_id == user1_id))
    ).order_by(Message.timestamp.asc()).all()

    return jsonify([{
        'id': msg.id,
        'sender_id': msg.sender_id,
        'content': msg.content,
        'timestamp': msg.timestamp.isoformat(),
        'read': msg.read
    } for msg in messages])

@app.route('/api/messages', methods=['POST'])
def create_message():
    data = request.json
    new_message = Message(
        sender_id=data['sender_id'],
        receiver_id=data['receiver_id'],
        content=data['content']
    )
    db.session.add(new_message)
    db.session.commit()

    socketio.emit('receive_message', {
        'id': new_message.id,
        'sender_id': new_message.sender_id,
        'receiver_id': new_message.receiver_id,
        'content': new_message.content,
        'timestamp': new_message.timestamp.isoformat(),
        'read': new_message.read
    }, room=str(new_message.receiver_id))

    return jsonify({'success': True, 'message_id': new_message.id})

@app.route('/api/update_avatar', methods=['POST'])
def update_avatar():
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'})

    user_id = request.form.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'User ID required'})

    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})

    avatar_filename = save_avatar(file)
    if not avatar_filename:
        return jsonify({'success': False, 'error': 'Invalid file type'})

    user = User.query.get(user_id)
    if user:
        if user.avatar:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user.avatar))
            except OSError:
                pass

        user.avatar = avatar_filename
        db.session.commit()

        return jsonify({'success': True, 'avatar': avatar_filename})

    return jsonify({'success': False, 'error': 'User not found'})

# Auth Routes
@app.route('/login', methods=['POST'])
def login():
    data = request.form
    user = User.query.filter_by(username=data['username']).first()

    if user and user.check_password(data['password']):
        user.online = True
        user.last_seen = datetime.utcnow()
        db.session.commit()
        return jsonify({
            'success': True,
            'user_id': user.id,
            'username': user.username,
            'display_name': user.display_name,
            'avatar': user.avatar
        })

    return jsonify({'success': False, 'error': 'Invalid credentials'})

@app.route('/register', methods=['POST'])
def register():
    if 'username' not in request.form or 'password' not in request.form:
        return jsonify({'success': False, 'error': 'Missing required fields'})

    if User.query.filter_by(username=request.form['username']).first():
        return jsonify({'success': False, 'error': 'Username already exists'})

    new_user = User(
        username=request.form['username'],
        display_name=request.form.get('display_name', request.form['username'])
    )
    new_user.set_password(request.form['password'])

    if 'avatar' in request.files:
        avatar_filename = save_avatar(request.files['avatar'])
        if avatar_filename:
            new_user.avatar = avatar_filename

    db.session.add(new_user)
    db.session.commit()

    return jsonify({
        'success': True,
        'user_id': new_user.id,
        'username': new_user.username,
        'display_name': new_user.display_name,
        'avatar': new_user.avatar
    })

# Static Files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# Socket.IO Events
@socketio.on('connect')
def handle_connect():
    user_id = request.args.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.online = True
            user.last_seen = datetime.utcnow()
            db.session.commit()
            socketio.emit('user_status', {
                'user_id': user.id,
                'online': True
            }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    user_id = request.args.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.online = False
            user.last_seen = datetime.utcnow()
            db.session.commit()
            socketio.emit('user_status', {
                'user_id': user.id,
                'online': False
            }, broadcast=True)

@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    if 'message_ids' in data:
        messages = Message.query.filter(Message.id.in_(data['message_ids'])).all()
        for msg in messages:
            msg.read = True
        db.session.commit()

@socketio.on('typing')
def handle_typing(data):
    socketio.emit('typing', {
        'sender_id': data['sender_id'],
        'receiver_id': data['receiver_id'],
        'is_typing': data['is_typing']
    }, room=data['receiver_id'])

# Base de datos
db_initialized = False

@app.before_request
def create_tables():
    global db_initialized
    if not db_initialized:
        db.create_all()
        db_initialized = True

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)
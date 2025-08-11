import os
from flask import Flask, request, jsonify, send_from_directory, render_template, redirect
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime
from dotenv import load_dotenv
import logging

# Configuración inicial
load_dotenv()
app = Flask(__name__,
            static_folder='static',
            template_folder='templates')

# Configuración mejorada para Socket.IO
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret-key-dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB ahora

# Configuración de logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('socketio')

# Inicialización con Socket.IO como componente principal
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   logger=logger,
                   engineio_logger=True,
                   async_mode='gevent_uwsgi',  # Puedes cambiar a 'eventlet' si prefieres
                   max_http_buffer_size=10 * 1024 * 1024)  # 10MB para transferencias grandes

db = SQLAlchemy(app)

# Modelos (optimizados para operaciones en tiempo real)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    display_name = db.Column(db.String(80), nullable=False)
    avatar = db.Column(db.String(120))
    online = db.Column(db.Boolean, default=False, index=True)  # Índice para búsquedas frecuentes
    last_seen = db.Column(db.DateTime, index=True)
    socket_id = db.Column(db.String(120))  # Almacenar ID de socket para mensajes directos

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'display_name': self.display_name,
            'avatar': self.avatar,
            'online': self.online,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'read': self.read
        }

# Helpers mejorados para Socket.IO
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_avatar(file):
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        # Aquí podrías añadir procesamiento con la GPU para optimizar imágenes
        # Ejemplo: redimensionar, comprimir, convertir a WebP, etc.
        
        return unique_filename
    return None

# Eventos de Socket.IO (nueva implementación)
@socketio.on('connect')
def handle_connect():
    logger.info(f"Cliente conectado: {request.sid}")
    emit('connection_response', {'status': 'connected'})

@socketio.on('authenticate')
def handle_auth(data):
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        user.online = True
        user.last_seen = datetime.utcnow()
        user.socket_id = request.sid  # Almacenar el ID de socket
        db.session.commit()
        
        join_room(f'user_{user.id}')  # Sala privada para el usuario
        emit('auth_response', {
            'success': True,
            'user': user.to_dict()
        })
        
        # Notificar a todos que el usuario está online
        socketio.emit('user_online', user.to_dict(), broadcast=True)
    else:
        emit('auth_response', {'success': False, 'error': 'Invalid credentials'})

@socketio.on('disconnect')
def handle_disconnect():
    user = User.query.filter_by(socket_id=request.sid).first()
    if user:
        user.online = False
        user.last_seen = datetime.utcnow()
        user.socket_id = None
        db.session.commit()
        
        leave_room(f'user_{user.id}')
        socketio.emit('user_offline', {'user_id': user.id}, broadcast=True)
    logger.info(f"Cliente desconectado: {request.sid}")

@socketio.on('get_users')
def handle_get_users(data):
    exclude_id = data.get('exclude')
    users = User.query.filter(User.id != exclude_id).all()
    emit('users_list', [user.to_dict() for user in users])

@socketio.on('get_chats')
def handle_get_chats(data):
    user_id = data['user_id']
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
                'participant': user.to_dict()
            }

        if not chats[other_user_id]['last_message']:
            chats[other_user_id]['last_message'] = msg.to_dict()

        if not msg.read and msg.receiver_id == int(user_id):
            chats[other_user_id]['unread_count'] += 1

    emit('chats_list', list(chats.values()))

@socketio.on('get_messages')
def handle_get_messages(data):
    chat_id = data['chat_id']
    user1_id, user2_id = map(int, chat_id.split('-'))

    messages = Message.query.filter(
        ((Message.sender_id == user1_id) & (Message.receiver_id == user2_id)) |
        ((Message.sender_id == user2_id) & (Message.receiver_id == user1_id))
    ).order_by(Message.timestamp.asc()).all()

    emit('messages_list', [msg.to_dict() for msg in messages])

@socketio.on('send_message')
def handle_send_message(data):
    new_message = Message(
        sender_id=data['sender_id'],
        receiver_id=data['receiver_id'],
        content=data['content']
    )
    db.session.add(new_message)
    db.session.commit()

    # Enviar al remitente (confirmación)
    emit('message_sent', new_message.to_dict(), room=request.sid)
    
    # Enviar al receptor (si está conectado)
    receiver = User.query.get(data['receiver_id'])
    if receiver and receiver.socket_id:
        emit('new_message', new_message.to_dict(), room=receiver.socket_id)
    
    # También a la sala de chat compartida
    chat_id = f"{min(data['sender_id'], data['receiver_id'])}-{max(data['sender_id'], data['receiver_id'])}"
    emit('chat_update', {
        'chat_id': chat_id,
        'message': new_message.to_dict()
    }, room=f'chat_{chat_id}')

@socketio.on('join_chat')
def handle_join_chat(data):
    chat_id = data['chat_id']
    join_room(f'chat_{chat_id}')
    emit('chat_joined', {'chat_id': chat_id})

@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    messages = Message.query.filter(Message.id.in_(data['message_ids'])).all()
    for msg in messages:
        msg.read = True
    db.session.commit()
    
    # Notificar al remitente que sus mensajes fueron leídos
    if messages:
        sender_id = messages[0].sender_id
        receiver_id = messages[0].receiver_id
        chat_id = f"{min(sender_id, receiver_id)}-{max(sender_id, receiver_id)}"
        emit('messages_read', {
            'message_ids': data['message_ids'],
            'chat_id': chat_id
        }, room=f'chat_{chat_id}')

@socketio.on('upload_avatar')
def handle_upload_avatar(data):
    # Implementación alternativa para manejar uploads via Socket.IO
    user = User.query.get(data['user_id'])
    if not user:
        emit('avatar_uploaded', {'success': False, 'error': 'User not found'})
        return
    
    # Aquí procesarías el archivo (data['file']) en un entorno real
    # Por simplicidad, asumimos que el cliente ya procesó la imagen
    
    user.avatar = data['avatar_url']
    db.session.commit()
    
    emit('avatar_uploaded', {
        'success': True,
        'avatar': user.avatar
    }, broadcast=True)

@socketio.on('register')
def handle_register(data):
    if User.query.filter_by(username=data['username']).first():
        emit('registration_response', {'success': False, 'error': 'Username exists'})
        return

    new_user = User(
        username=data['username'],
        display_name=data.get('display_name', data['username'])
    )
    new_user.set_password(data['password'])

    if 'avatar' in data:
        new_user.avatar = data['avatar']

    db.session.add(new_user)
    db.session.commit()

    emit('registration_response', {
        'success': True,
        'user': new_user.to_dict()
    })

# Rutas HTTP mínimas (solo para entrega inicial)
@app.route('/')
def home():
    return redirect('/auth')

@app.route('/auth')
def auth_page():
    return render_template('auth.html')

@app.route('/chat')
def chat_page():
    return render_template('chat.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Inicialización de la base de datos
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, 
                host='0.0.0.0', 
                port=port, 
                debug=True,
                use_reloader=True,
                log_output=True)
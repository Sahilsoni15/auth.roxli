from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from functools import wraps
import secrets as sec
import firebase_admin
from firebase_admin import credentials, db
import hashlib
import os
from PIL import Image, ImageDraw, ImageFont
import io
import base64
import secrets
try:
    import jwt
except ImportError:
    import PyJWT as jwt
from datetime import datetime, timedelta
import pytz
import uuid

app = Flask(__name__)
app.secret_key = sec.token_hex(32)
CORS(app, supports_credentials=True, origins=['https://auth.roxli.in', 'https://account.roxli.in', 'https://mail.roxli.in', 'https://search.roxli.in'])

# Security headers
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://auth.roxli.in https://account.roxli.in https://mail.roxli.in https://search.roxli.in"
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# OAuth Configuration - Fixed secret for consistency
JWT_SECRET = 'roxli_jwt_secret_key_2024'
TOKEN_EXPIRY = timedelta(days=60)

# Rate limiting storage
rate_limits = {}

def rate_limit(max_requests=5, window=300):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr
            now = datetime.now().timestamp()
            
            if client_ip not in rate_limits:
                rate_limits[client_ip] = []
            
            # Clean old requests
            rate_limits[client_ip] = [req_time for req_time in rate_limits[client_ip] if now - req_time < window]
            
            if len(rate_limits[client_ip]) >= max_requests:
                return jsonify({'error': 'Too many requests'}), 429
            
            rate_limits[client_ip].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def validate_input(data, required_fields):
    for field in required_fields:
        if not data.get(field) or len(str(data.get(field)).strip()) == 0:
            return False
    return True

# Firebase initialization
try:
    # Try environment variable first (for Railway)
    firebase_config = os.environ.get('FIREBASE_CONFIG')
    if firebase_config:
        import json
        cred = credentials.Certificate(json.loads(firebase_config))
    else:
        # Fallback to local file
        cred = credentials.Certificate('firebase-key.json')
    
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://roxli-5aebd-default-rtdb.firebaseio.com/'
    })
except Exception as e:
    print(f"Firebase initialization failed: {e}")
    # Create a mock Firebase for testing
    class MockDB:
        def reference(self, path):
            return self
        def get(self):
            return {}
        def set(self, data):
            return True
        def update(self, data):
            return True
    
    class MockFirebase:
        def reference(self, path, app=None):
            return MockDB()
    
    db = MockFirebase()

def generate_avatar(first_name, last_name):
    """Generate avatar like ui-avatars.com with solid background and black text"""
    initials = f"{first_name[0].upper()}{last_name[0].upper()}"
    
    # Solid background colors (similar to ui-avatars.com)
    colors = [
        '#2ecc71',  # Green
        '#3498db',  # Blue
        '#9b59b6',  # Purple
        '#e74c3c',  # Red
        '#f39c12',  # Orange
        '#1abc9c',  # Turquoise
        '#34495e',  # Dark Blue
        '#e67e22',  # Carrot
        '#95a5a6',  # Silver
        '#f1c40f',  # Yellow
    ]
    
    # Select color based on initials
    color_index = (ord(first_name[0]) + ord(last_name[0])) % len(colors)
    bg_color = colors[color_index]
    
    # Create square image (like ui-avatars.com)
    size = (200, 200)
    img = Image.new('RGB', size, color=bg_color)
    draw = ImageDraw.Draw(img)
    
    # Try to load a clean font
    font_size = 80
    font = None
    
    font_paths = [
        "/System/Library/Fonts/Helvetica.ttc",  # macOS
        "C:/Windows/Fonts/arial.ttf",  # Windows
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",  # Linux
    ]
    
    for font_path in font_paths:
        try:
            font = ImageFont.truetype(font_path, font_size)
            break
        except:
            continue
    
    if not font:
        try:
            font = ImageFont.load_default()
        except:
            font = None
    
    if font:
        # Calculate text position for centering
        bbox = draw.textbbox((0, 0), initials, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = (size[0] - text_width) // 2
        y = (size[1] - text_height) // 2
        
        # Draw black text (like ui-avatars.com)
        draw.text((x, y), initials, fill='#000000', font=font)
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    # Cache avatar in session storage
    avatar_data = f"data:image/png;base64,{img_str}"
    return avatar_data

def generate_token(user_data):
    """Generate JWT token for user"""
    import time
    now = time.time()
    payload = {
        'user_id': user_data['id'],
        'email': user_data['email'],
        'exp': int(now + TOKEN_EXPIRY.total_seconds()),
        'iat': int(now)
    }
    try:
        return jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    except AttributeError:
        # Handle different JWT library versions
        import json
        import hmac
        import hashlib
        import base64
        
        header = {'typ': 'JWT', 'alg': 'HS256'}
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload, default=str).encode()).decode().rstrip('=')
        
        message = f"{header_encoded}.{payload_encoded}"
        signature = hmac.new(JWT_SECRET.encode(), message.encode(), hashlib.sha256).digest()
        signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{message}.{signature_encoded}"

def verify_token(token):
    """Verify JWT token"""
    try:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except AttributeError:
            # Handle different JWT library versions
            import json
            import hmac
            import hashlib
            import base64
            
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError('Invalid token')
            
            header_encoded, payload_encoded, signature_encoded = parts
            
            # Verify signature
            message = f"{header_encoded}.{payload_encoded}"
            expected_signature = hmac.new(JWT_SECRET.encode(), message.encode(), hashlib.sha256).digest()
            expected_signature_encoded = base64.urlsafe_b64encode(expected_signature).decode().rstrip('=')
            
            if signature_encoded != expected_signature_encoded:
                raise ValueError('Invalid signature')
            
            # Decode payload
            payload_padded = payload_encoded + '=' * (4 - len(payload_encoded) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded).decode())
            
            # Check expiration
            import time
            if payload.get('exp', 0) < time.time():
                raise ValueError('Token expired')
        return payload
    except (jwt.ExpiredSignatureError if hasattr(jwt, 'ExpiredSignatureError') else ValueError):
        return None
    except (jwt.InvalidTokenError if hasattr(jwt, 'InvalidTokenError') else ValueError):
        return None
    except Exception:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    redirect_url = request.args.get('redirect')
    return render_template('login.html', redirect_url=redirect_url)

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/api/register', methods=['POST'])
@rate_limit(max_requests=3, window=300)
def register():
    data = request.json
    
    if not validate_input(data, ['firstName', 'lastName', 'email', 'password']):
        return jsonify({'error': 'All fields required'}), 400
    
    first_name = data.get('firstName').strip()
    last_name = data.get('lastName').strip()
    email_input = data.get('email').strip().lower()
    password = data.get('password')
    custom_avatar = data.get('avatar')
    
    # Auto-append @roxli.in if no @ symbol, reject other domains
    if '@' not in email_input:
        email = f"{email_input}@roxli.in"
    elif email_input.endswith('@roxli.in'):
        email = email_input
    else:
        return jsonify({'error': 'Only @roxli.in emails are allowed'}), 400
    
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    # Check if user exists
    users_ref = db.reference('users')
    try:
        existing_user = users_ref.order_by_child('email').equal_to(email).get()
    except Exception as e:
        # Fallback: check all users manually
        all_users = users_ref.get() or {}
        existing_user = {k: v for k, v in all_users.items() if v.get('email') == email}
    
    if existing_user:
        return jsonify({'error': 'User already exists'}), 400
    
    # Generate avatar using ui-avatars.com with consistent styling
    if custom_avatar:
        avatar = custom_avatar
    else:
        # Use ui-avatars.com for consistent avatar generation
        avatar_name = f"{first_name}+{last_name}"
        avatar = f"https://ui-avatars.com/api/?name={avatar_name}&background=667eea&color=fff&size=200&bold=true&rounded=true"
    
    # Hash password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Create user
    user_data = {
        'firstName': first_name,
        'lastName': last_name,
        'email': email,
        'password': password_hash,
        'avatar': avatar,
        'createdAt': datetime.now().isoformat(),
        'lastLogin': datetime.now().isoformat()
    }
    
    user_ref = users_ref.push(user_data)
    user_id = user_ref.key
    
    # Create session and token
    session['user_id'] = user_id
    session['email'] = email
    
    user_obj = {
        'id': user_id,
        'firstName': first_name,
        'lastName': last_name,
        'email': email,
        'avatar': avatar
    }
    
    token = generate_token(user_obj)
    
    # Send welcome email to new user
    try:
        import requests
        requests.post('https://mail.roxli.in/api/send-welcome-email', 
                     json={'user_id': user_id}, 
                     cookies={'roxli_token': token},
                     timeout=5)
    except Exception as e:
        print(f"Failed to send welcome email: {e}")
    
    response = jsonify({
        'success': True,
        'user': user_obj,
        'token': token
    })
    response.set_cookie('roxli_token', token, httponly=False, secure=False, samesite='Lax', path='/')
    return response

@app.route('/api/login', methods=['POST'])
@rate_limit(max_requests=5, window=300)
def login():
    data = request.json
    
    if not validate_input(data, ['email', 'password']):
        return jsonify({'error': 'Email and password required'}), 400
    
    email_input = data.get('email').strip().lower()
    password = data.get('password')
    
    # Auto-append @roxli.in if no @ symbol, reject other domains
    if '@' not in email_input:
        email = f"{email_input}@roxli.in"
    elif email_input.endswith('@roxli.in'):
        email = email_input
    else:
        return jsonify({'error': 'Only @roxli.in emails are allowed'}), 400
    
    # Find user
    users_ref = db.reference('users')
    try:
        users = users_ref.order_by_child('email').equal_to(email).get()
    except Exception as e:
        # Fallback: check all users manually
        all_users = users_ref.get() or {}
        users = {k: v for k, v in all_users.items() if v.get('email') == email}
    
    if not users:
        return jsonify({'error': 'User not found'}), 404
    
    user_id, user_data = next(iter(users.items()))
    
    # Verify password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user_data['password'] != password_hash:
        return jsonify({'error': 'Invalid password'}), 401
    
    # Update last login
    users_ref.child(user_id).update({'lastLogin': datetime.now().isoformat()})
    
    # Create session and token
    session['user_id'] = user_id
    session['email'] = email
    
    user_obj = {
        'id': user_id,
        'firstName': user_data['firstName'],
        'lastName': user_data['lastName'],
        'email': user_data['email'],
        'avatar': user_data['avatar']
    }
    
    token = generate_token(user_obj)
    
    response = jsonify({
        'success': True,
        'user': user_obj,
        'token': token
    })
    response.set_cookie('roxli_token', token, httponly=False, secure=False, samesite='Lax', path='/')
    return response

@app.route('/api/user')
def get_user():
    # Check token first
    token = request.cookies.get('roxli_token') or request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if token:
        payload = verify_token(token)
        if payload:
            user_ref = db.reference(f'users/{payload["user_id"]}')
            user_data = user_ref.get()
            
            if user_data:
                return jsonify({
                    'user': {
                        'id': payload['user_id'],
                        'firstName': user_data['firstName'],
                        'lastName': user_data['lastName'],
                        'email': user_data['email'],
                        'avatar': user_data['avatar']
                    }
                })
    
    # Fallback to session
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_ref = db.reference(f'users/{session["user_id"]}')
    user_data = user_ref.get()
    
    if not user_data:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user': {
            'id': session['user_id'],
            'firstName': user_data['firstName'],
            'lastName': user_data['lastName'],
            'email': user_data['email'],
            'avatar': user_data['avatar']
        }
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    response = jsonify({'success': True})
    response.set_cookie('roxli_token', '', expires=0, path='/')
    response.set_cookie('roxli_token', '', expires=0, domain='localhost')
    return response

@app.route('/api/verify', methods=['POST'])
def verify_token_endpoint():
    """Verify token for external applications"""
    data = request.json
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'Token required'}), 400
    
    payload = verify_token(token)
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    
    user_ref = db.reference(f'users/{payload["user_id"]}')
    user_data = user_ref.get()
    
    if not user_data:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'valid': True,
        'user': {
            'id': payload['user_id'],
            'firstName': user_data['firstName'],
            'lastName': user_data['lastName'],
            'email': user_data['email'],
            'avatar': user_data['avatar']
        }
    })

@app.route('/popup')
def popup():
    mode = request.args.get('mode', 'login')
    return render_template('popup.html', mode=mode)

@app.route('/integration')
def integration():
    return render_template('integration.html')

@app.route('/switch-account')
def switch_account_page():
    return render_template('account-switcher.html')

@app.route('/api/generate-avatar', methods=['POST'])
def generate_avatar_api():
    """Generate avatar for preview"""
    data = request.json
    first_name = data.get('firstName', '')
    last_name = data.get('lastName', '')
    
    if not first_name or not last_name:
        return jsonify({'error': 'First name and last name required'}), 400
    
    avatar_name = f"{first_name}+{last_name}"
    avatar = f"https://ui-avatars.com/api/?name={avatar_name}&background=667eea&color=fff&size=200&bold=true"
    return jsonify({'avatar': avatar})

@app.route('/api/refresh-avatar', methods=['POST'])
def refresh_avatar():
    """Refresh user avatar if missing"""
    token = request.cookies.get('roxli_token')
    if not token:
        return jsonify({'error': 'Not authenticated'}), 401
    
    payload = verify_token(token)
    if not payload:
        return jsonify({'error': 'Invalid token'}), 401
    
    user_ref = db.reference(f'users/{payload["user_id"]}')
    user_data = user_ref.get()
    
    if user_data:
        # Regenerate avatar using ui-avatars.com with consistent styling
        avatar_name = f"{user_data['firstName']}+{user_data['lastName']}"
        new_avatar = f"https://ui-avatars.com/api/?name={avatar_name}&background=667eea&color=fff&size=200&bold=true&rounded=true"
        user_ref.update({'avatar': new_avatar})
        return jsonify({'success': True, 'avatar': new_avatar})
    
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/available-accounts')
def get_available_accounts():
    """Get available accounts for account switcher"""
    emails = request.args.getlist('emails')
    
    if not emails:
        return jsonify({'accounts': []})
    
    users_ref = db.reference('users')
    all_users = users_ref.get() or {}
    
    available_accounts = []
    for user_id, user_data in all_users.items():
        if user_data.get('email') in emails:
            available_accounts.append({
                'id': user_id,
                'firstName': user_data['firstName'],
                'lastName': user_data['lastName'],
                'email': user_data['email'],
                'avatar': user_data['avatar']
            })
    
    return jsonify({'accounts': available_accounts})

@app.route('/api/find-user', methods=['POST'])
def find_user():
    """Find user by email for mail service"""
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email required'}), 400
    
    # Find user by email
    users_ref = db.reference('users')
    try:
        users = users_ref.order_by_child('email').equal_to(email).get()
    except Exception as e:
        # Fallback: check all users manually
        all_users = users_ref.get() or {}
        users = {k: v for k, v in all_users.items() if v.get('email') == email}
    
    if users:
        user_id, user_data = next(iter(users.items()))
        return jsonify({
            'found': True,
            'user': {
                'id': user_id,
                'firstName': user_data['firstName'],
                'lastName': user_data['lastName'],
                'email': user_data['email'],
                'avatar': user_data['avatar']
            }
        })
    
    return jsonify({'found': False})

@app.route('/api/switch-account', methods=['POST'])
def switch_account():
    data = request.json
    email = data.get('email')
    
    # Find user by email
    users_ref = db.reference('users')
    try:
        users = users_ref.order_by_child('email').equal_to(email).get()
    except Exception as e:
        # Fallback: check all users manually
        all_users = users_ref.get() or {}
        users = {k: v for k, v in all_users.items() if v.get('email') == email}
    
    if not users:
        return jsonify({'error': 'User not found'}), 404
    
    user_id, user_data = next(iter(users.items()))
    
    # Don't clear existing session, just switch to new user
    session['user_id'] = user_id
    session['email'] = email
    
    # Update last login
    users_ref.child(user_id).update({'lastLogin': datetime.now().isoformat()})
    
    user_obj = {
        'id': user_id,
        'firstName': user_data['firstName'],
        'lastName': user_data['lastName'],
        'email': user_data['email'],
        'avatar': user_data['avatar']
    }
    
    token = generate_token(user_obj)
    
    response = jsonify({
        'success': True,
        'user': user_obj,
        'token': token
    })
    response.set_cookie('roxli_token', token, httponly=False, secure=False, samesite='Lax', path='/')
    return response

@app.route('/api/sync-avatar', methods=['POST'])
def sync_avatar():
    """Endpoint for syncing avatar updates across services"""
    data = request.json
    user_id = data.get('user_id')
    avatar_url = data.get('avatar')
    email = data.get('email')
    
    if not user_id or not avatar_url:
        return jsonify({'error': 'User ID and avatar URL required'}), 400
    
    try:
        # Update user avatar in auth database
        user_ref = db.reference(f'users/{user_id}')
        user_ref.update({'avatar': avatar_url})
        
        return jsonify({'success': True, 'message': 'Avatar synced successfully'})
    except Exception as e:
        print(f"Error syncing avatar in auth service: {e}")
        return jsonify({'error': 'Failed to sync avatar'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
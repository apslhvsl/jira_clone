import jwt
from datetime import datetime, timedelta
from flask import request, jsonify, current_app
from functools import wraps
from models.user import User
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

# =====================
# 🔐 Generate JWT Token
# =====================
def generate_jwt(user):
    payload = {
        'sub': str(user.id),  # subject
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'iat': datetime.utcnow(),  # issued at
        'exp': datetime.utcnow() + timedelta(days=1)  # expires in 1 day
    }

    token = jwt.encode(
        payload,
        current_app.config['SECRET_KEY'],
        algorithm='HS256'
    )

    # PyJWT >= 2.0 returns bytes when SECRET_KEY is string
    return token if isinstance(token, str) else token.decode('utf-8')


# =====================
# 🔍 Decode JWT Token
# =====================
def decode_jwt(token):
    try:
        payload = jwt.decode(
            token,
            current_app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        return payload
    except ExpiredSignatureError:
        return None
    except InvalidTokenError:
        return None


# =============================
# 🛡️ JWT Authentication Wrapper
# =============================
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            return '', 200

        auth_header = request.headers.get('Authorization', None)

        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401

        token = auth_header.split(' ')[1]
        payload = decode_jwt(token)

        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401

        user_id = payload.get('sub') or payload.get('user_id')

        if not user_id:
            return jsonify({'error': 'Invalid token: missing user ID'}), 401

        user = User.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Attach user to request context
        request.user = user

        return f(*args, **kwargs)
    return decorated

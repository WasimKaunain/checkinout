import jwt
from flask import current_app
from datetime import datetime, timedelta
from datetime import datetime, timedelta, timezone

def generate_jwt(member_id, role):
    expiry = datetime.now(timezone.utc) + timedelta(seconds=current_app.config['JWT_EXP_DELTA_SECONDS'])
    payload = {
        'member_id': member_id,
        'role': role,
        'exp': expiry
    }
    token = jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm=current_app.config['JWT_ALGORITHM'])
    return token

def decode_jwt(token):
    try:
        payload = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=[current_app.config['JWT_ALGORITHM']])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, 'Token has expired'
    except jwt.InvalidTokenError:
        return None, 'Invalid token'

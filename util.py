import jwt
from datetime import datetime, timedelta

SECRET_KEY =()

def encode_token(user_id, role):
    
    payload = {
        'exp': datetime.utcnow() + timedelta(days=1), 
        'iat': datetime.utcnow(),
        'sub': user_id,
        'role': role  
    }
    return jwt.encode(payload,SECRET_KEY,algorithm='HS256')
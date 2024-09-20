from flask import Flask, request, jsonify
from functools import wraps
import jwt
from models import User
from util import encode_token

app = Flask(__name__)

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('Authorization') 

            if not token:
                return jsonify({'message': 'Token is missing'}), 401

            try:
                data = jwt.decode(token, SECRET_KEY, algorithms=['HS256']) 

                user_id = data['sub']
                user = User.query.get(user_id) 

                if user and user.role in allowed_roles:
                    return f(*args, **kwargs)
                else:
                    return jsonify({'message': 'Unauthorized'}), 403

            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token has expired'}), 401
            except jwt.InvalidTokenError:   

                return jsonify({'message': 'Invalid token'}), 401

        return decorated_function
    return decorator

def login(username, password):
    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        token = encode_token(user.id, user.role) 
        return {'token': token, 'message': 'Login successful'} 
    else:
        return {'message': 'Invalid username or password'}, 401

@app.route('/login', methods=['POST'])
def login_route():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    result = login(username, password)
    return jsonify(result), result.get('status_code', 200) 

@app.route('/some_endpoint/save', methods=['POST'])
@role_required(['admin']) 
def save_data():

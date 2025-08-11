import re, os
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from flask_mail import Mail, Message
import random
import string

app = Flask(__name__)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

load_dotenv()

# Database Connection
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User Model
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    # role = db.Column(db.String(20), nullable=False)

# OTP Model
class OTP(db.Model):
    __tablename__ = 'otp'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    expires_at = db.Column(db.DateTime, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)

# OTP Generation
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Email Verification
def send_verification_email(email, otp):
    try:
        msg = Message(
            'Account Verification',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f'''
        Welcome to our platform!
        
        Your verification OTP is: {otp}
        
        This OTP will expire in 10 minutes.
        Please do not share this OTP with anyone.
        '''
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {str(e)}")
        return False

# User Registration
@app.route('/register_user', methods=['POST'])
def register_user():
    try: 
        data = request.get_json()

        # Validate required fields
        required_fields = ['username', 'firstName', 'lastName', 'email', 'password']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
    
        username = data['username']
        first_name = data['firstName']
        last_name = data['lastName']
        email = data['email']
        password = data['password']

        # Validate email format
        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_pattern, email):
            return jsonify({"error": "Invalid email format"}), 400

        # Validate password strength
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters long"}), 400
        if not any(c.isupper() for c in password):
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not any(c.isdigit() for c in password):
            return jsonify({"error": "Password must contain at least one number"}), 400
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            return jsonify({"error": "Password must contain at least one special character"}), 400
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 409
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already exists"}), 409

        # Create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password,
            status='pending'
        )

        # Save to database
        otp = generate_otp()
        db.session.add(new_user)
        db.session.flush()

        new_otp = OTP(
            user_id=new_user.id,
            otp_code=otp,
            expires_at=datetime.utcnow() + timedelta(minutes=10)
        )

        # Send verification email   
        if not send_verification_email(email, otp):
            db.session.rollback()
            return jsonify({"error": "Failed to send verification email"}), 500

        db.session.add(new_otp)
        db.session.commit()

        return jsonify({
            "message": "User registered successfully"
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# Add new verification endpoint
@app.route('/verify_email', methods=['POST'])
def verify_email():
    try:
        data = request.get_json()
        if not data or not data.get('user_id') or not data.get('otp'):
            return jsonify({"error": "Missing user_id or OTP"}), 400

        user_id = data['user_id']
        otp_code = data['otp']

        # Find the latest OTP for the user
        otp_record = OTP.query.filter_by(
            user_id=user_id,
            is_verified=False
        ).order_by(OTP.created_at.desc()).first()

        if not otp_record:
            return jsonify({"error": "No OTP found"}), 404

        if otp_record.expires_at < datetime.utcnow():
            return jsonify({"error": "OTP has expired"}), 400

        if otp_record.otp_code != otp_code:
            return jsonify({"error": "Invalid OTP"}), 400

        # Mark OTP as verified and activate user
        otp_record.is_verified = True
        user = User.query.get(user_id)
        user.status = 'active'
        db.session.commit()

        return jsonify({"message": "Email verified successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Add these configurations after app initialization
app.config['SECRET_KEY'] = os.getenv('JWT_KEY')  
app.config['JWT_EXPIRATION_MINUTES'] = 1000  # Token expiration time in minutes

# User Login
@app.route('/login', methods=['POST'])
def login():
    try:
        auth = request.get_json()

        if not auth or not auth.get('username') or not auth.get('password'):
            return jsonify({'error': 'Missing username or password'}), 400

        user = User.query.filter_by(username=auth.get('username')).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.status != 'active':
            return jsonify({'error': 'Please verify your email before logging in'}), 403

        if check_password_hash(user.password, auth.get('password')):
            # Generate JWT token
            token = jwt.encode({
                'user_id': user.id,
                'username': user.username,
                'exp': datetime.utcnow() + timedelta(minutes=app.config['JWT_EXPIRATION_MINUTES'])
            }, app.config['SECRET_KEY'], algorithm="HS256")

            # Create response with token in cookie
            response = make_response(jsonify({
                'message': 'Login successful',
                'user': {
                    'username': user.username,
                    'email': user.email
                }
            }))

            # Set secure cookie with token
            response.set_cookie(
                'x-access-token',
                token,
                httponly=True,
                secure=True,  # Enable in production with HTTPS
                samesite='Strict',
                max_age=app.config['JWT_EXPIRATION_MINUTES'] * 60
            )

            return response, 200

        return jsonify({'error': 'Invalid password'}), 401

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Add this decorator function for protected routes
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.cookies:
            token = request.cookies.get('x-access-token')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'error': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# Example protected route
@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    return jsonify({
        'message': 'This is a protected route',
        'user': current_user.username
    }), 200

# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({'message': 'Logout successful'}))
    response.delete_cookie('x-access-token')
    return response, 200

if __name__ == '__main__':
    app.run(debug=True)

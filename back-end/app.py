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
from flask_cors import CORS

app = Flask(__name__)

# Email Setup
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

CORS(app, 
     supports_credentials=True,
     resources={
         r"/*": {
             "origins": ["http://localhost:3000"],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Content-Type", "Authorization"]
         }
     })

# Load Env
load_dotenv()

# Database Connection
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# JWT Auth
app.config['SECRET_KEY'] = os.getenv('JWT_KEY')  
app.config['JWT_EXPIRATION_MINUTES'] = 1000  # In mins

# User Model
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    verification = db.Column(db.Boolean, default=False)
    status = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    role = db.Column(db.String(20), nullable=False) # Admin, Student, HR

# OTP Model
class OTP(db.Model):
    __tablename__ = 'otp'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    otp_code = db.Column(db.String(255), nullable=False)
    purpose = db.Column(db.String(20), nullable=False) # Reset password, verifiy email
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

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
        
        Your verification OTP is: {otp}
        
        This OTP will expire in 10 minutes.
        Please do not share this OTP with anyone.
        '''
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {str(e)}")
        return False

# For routes that required token
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

# User Registration
@app.route('/register-user', methods=['POST'])
def register_user():
    try: 
        data = request.get_json()

        # Validate required fields
        required_fields = ['username', 'first_name', 'last_name', 'email', 'password']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
    
        username = data['username']
        first_name = data['first_name']
        last_name = data['last_name']
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
            status=False,
            role='STD'
        )

        # Save to database
        otp = generate_otp()
        db.session.add(new_user)
        db.session.flush()

        new_otp = OTP(
            user_id=new_user.id,
            otp_code=otp,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            purpose='Activation'
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

# OTP Verification
@app.route('/verify-email', methods=['POST'])
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
            used=False
        ).order_by(OTP.created_at.desc()).first()

        if not otp_record:
            return jsonify({"error": "No OTP found"}), 404

        if otp_record.expires_at < datetime.utcnow():
            return jsonify({"error": "OTP has expired"}), 400

        if otp_record.otp_code != otp_code:
            return jsonify({"error": "Invalid OTP"}), 400

        # Mark OTP as verified and activate user
        otp_record.used = True
        user = User.query.get(user_id)
        user.verification = True
        db.session.commit()

        return jsonify({"message": "Email verified successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# User Login
@app.route('/login', methods=['POST'])
def login():
    try:
        auth = request.get_json()

        if not auth or not auth.get('email') or not auth.get('password'):
            return jsonify({'error': 'Missing email or password'}), 400

        user = User.query.filter_by(email=auth.get('email')).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not user.verification:
            return jsonify({'error': 'Please verify your email before logging in'}), 403

        if check_password_hash(user.password, auth.get('password')):
            # Generate JWT token
            token = jwt.encode({
                'user_id': user.id,
                'email': user.email,
                'exp': datetime.utcnow() + timedelta(minutes=app.config['JWT_EXPIRATION_MINUTES'])
            }, app.config['SECRET_KEY'], algorithm="HS256")

            user.status = True
            db.session.commit()

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

# Forget Password
@app.route('/forget-password', methods=['POST'])
def forget_password():
    try:
        data = request.get_json()
        if not data or not data.get('email'):
            return jsonify({"error": "Missing email"}), 400

        email = data['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "User with this email does not exist"}), 404

        # Generate OTP for password reset
        otp = generate_otp()
        new_otp = OTP(
            user_id=user.id,
            otp_code=otp,
            expires_at=datetime.utcnow() + timedelta(minutes=10),
            purpose='Forget Password'
        )

        db.session.add(new_otp)
        db.session.commit()

        # Generate password reset link
        reset_link = f"http://localhost:3000/reset-password?otp={otp}"

        # Send reset link email
        try:
            msg = Message(
                'Password Reset Request',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            msg.body = f"""
            You requested a password reset.

            Click the link below to reset your password (valid for 10 minutes):

            {reset_link}

            If you did not request this, please ignore this email.
            """
            mail.send(msg)
        except Exception as e:
            db.session.rollback()
            print(f"Email error: {str(e)}")
            return jsonify({"error": "Failed to send password reset email"}), 500

        return jsonify({"message": "Password reset link sent to your email"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# User Logout
@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    current_user.status = False
    db.session.commit()
    response = make_response(jsonify({'message': 'Logout successful'}))
    response.delete_cookie('x-access-token')
    return response, 200

# Reset Password
@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        if not data or not data.get('otp') or not data.get('new_password'):
            return jsonify({"error": "Missing OTP or new password"}), 400

        otp_code = data['otp']
        new_password = data['new_password']

        # Validate password strength
        if len(new_password) < 8:
            return jsonify({"error": "Password must be at least 8 characters long"}), 400
        if not any(c.isupper() for c in new_password):
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not any(c.isdigit() for c in new_password):
            return jsonify({"error": "Password must contain at least one number"}), 400
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in new_password):
            return jsonify({"error": "Password must contain at least one special character"}), 400

        # Find OTP record
        otp_record = OTP.query.filter_by(otp_code=otp_code, used=False).order_by(OTP.created_at.desc()).first()
        if not otp_record:
            return jsonify({"error": "Invalid or expired OTP"}), 400
        if otp_record.expires_at < datetime.utcnow():
            return jsonify({"error": "OTP has expired"}), 400

        # Find user by user_id from OTP
        user = User.query.get(otp_record.user_id)   
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Update password
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.password = hashed_password

        # Mark OTP as used
        otp_record.used = True
        otp_record.purpose = 'Reset'
        db.session.commit()

        return jsonify({"message": "Password reset successful"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# Change Password
@app.route('/change-password', methods=['POST'])
@token_required
def change_password(current_user):
    try:
        data = request.get_json()
        if not data or not data.get('old_password') or not data.get('new_password'):
            return jsonify({"error": "Missing old or new password"}), 400

        old_password = data['old_password']
        new_password = data['new_password']

        # Check old password
        if not check_password_hash(current_user.password, old_password):
            return jsonify({"error": "Old password is incorrect"}), 401

         # Validate new password strength
        if len(new_password) < 8:
            return jsonify({"error": "Password must be at least 8 characters long"}), 400
        if not any(c.isupper() for c in new_password):
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not any(c.isdigit() for c in new_password):
            return jsonify({"error": "Password must contain at least one number"}), 400
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in new_password):
            return jsonify({"error": "Password must contain at least one special character"}), 400

        # Update password
        current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()

        return jsonify({"message": "Password changed successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    
# Profile

if __name__ == '__main__':
    app.run(debug=True)

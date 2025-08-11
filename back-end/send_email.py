import os
import random
import string
from flask import Flask, request, jsonify
from flask_mail import Mail, Message
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

mail = Mail(app)

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
    
@app.route('/send-email', methods=['POST'])
def send_email():
    try:
        data = request.get_json()
        otp = generate_otp()

        if not data.get('email'):
            return jsonify({'error': 'Email is required'}), 400

        if not send_verification_email(data['email'], otp):
            return jsonify({"error": "Failed to send verification email"}), 500
        
        return jsonify({'message': 'Email sent successfully!'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)

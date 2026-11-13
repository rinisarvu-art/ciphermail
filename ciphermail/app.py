import os
import json
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ciphermail-secret-key-final-year-2026-super-secure')

# Vercel uses /tmp for writable storage; local uses instance/ciphermail.db
if os.environ.get('VERCEL'):
    db_path = '/tmp/ciphermail.db'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ciphermail.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ----------------- Database Models ----------------- #

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    duress_password_hash = db.Column(db.String(256), nullable=True) # Decoy panic password
    rsa_public_key = db.Column(db.Text, nullable=False) # JSON JWK
    ecdsa_public_key = db.Column(db.Text, nullable=False) # JSON JWK
    encrypted_private_keys = db.Column(db.Text, nullable=False) # Encrypted with derived master key
    key_salt = db.Column(db.String(128), nullable=False)
    vault_access = db.Column(db.Boolean, default=True)
    organization_domain = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class EmailMessage(db.Model):
    __tablename__ = 'emails'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sender_email = db.Column(db.String(120), nullable=False)
    recipient_email = db.Column(db.String(120), nullable=False)
    
    # Mode: 0 = Normal Email (Part 1), 1 = Shadow Vault Secret Mail (Part 2)
    is_vault = db.Column(db.Boolean, default=False)
    
    # Cryptographic Status Progression: 'sealed' -> 'vaulted' -> 'decrypted' -> 'shredded'
    status = db.Column(db.String(20), default='vaulted')
    decrypted_at = db.Column(db.DateTime, nullable=True)
    
    # All fields below are encrypted ciphertext (Base64) - Zero-Knowledge
    encrypted_subject = db.Column(db.Text, nullable=False)
    encrypted_body = db.Column(db.Text, nullable=False)
    encrypted_key_for_recipient = db.Column(db.Text, nullable=False)
    encrypted_key_for_sender = db.Column(db.Text, nullable=False)
    iv = db.Column(db.String(64), nullable=False)
    signature = db.Column(db.Text, nullable=False) # ECDSA digital signature
    
    # Attachment details (also encrypted)
    has_attachment = db.Column(db.Boolean, default=False)
    attachment_name_encrypted = db.Column(db.Text, nullable=True)
    attachment_data_encrypted = db.Column(db.Text, nullable=True)
    attachment_type = db.Column(db.String(100), nullable=True)
    
    # Ephemeral / Burn-After-Reading features
    is_burn_after_reading = db.Column(db.Boolean, default=False)
    view_count = db.Column(db.Integer, default=0)
    expires_at = db.Column(db.DateTime, nullable=True)
    
    # Status
    is_read = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

with app.app_context():
    db.create_all()

# ----------------- Helper Functions ----------------- #

def clean_expired_emails():
    """Auto-purges emails that have exceeded their TTL (Time to Live)"""
    now = datetime.now(timezone.utc)
    expired = EmailMessage.query.filter(
        EmailMessage.expires_at.isnot(None),
        EmailMessage.expires_at <= now
    ).all()
    for e in expired:
        db.session.delete(e)
    if expired:
        db.session.commit()

# ----------------- Authentication Routes ----------------- #

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username', '').strip().lower()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    duress_password = data.get('duress_password', '').strip()
    
    rsa_pub = data.get('rsa_public_key')
    ecdsa_pub = data.get('ecdsa_public_key')
    enc_priv = data.get('encrypted_private_keys')
    salt = data.get('key_salt')

    if not all([username, email, password, rsa_pub, ecdsa_pub, enc_priv, salt]):
        return jsonify({'error': 'Missing required registration or cryptographic parameters'}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'Username or Email already registered'}), 409

    pwd_hash = generate_password_hash(password)
    duress_hash = generate_password_hash(duress_password) if duress_password else None

    # Derive organization domain cleanly from email (e.g. alice@tcs.com -> tcs.com)
    org_domain = email.split('@')[1] if '@' in email else 'ciphermail.local'

    user = User(
        username=username,
        email=email,
        password_hash=pwd_hash,
        duress_password_hash=duress_hash,
        rsa_public_key=json.dumps(rsa_pub) if isinstance(rsa_pub, dict) else rsa_pub,
        ecdsa_public_key=json.dumps(ecdsa_pub) if isinstance(ecdsa_pub, dict) else ecdsa_pub,
        encrypted_private_keys=json.dumps(enc_priv) if isinstance(enc_priv, dict) else enc_priv,
        key_salt=salt,
        organization_domain=org_domain,
        vault_access=True
    )
    db.session.add(user)
    db.session.commit()

    session['user_id'] = user.id
    session['email'] = user.email
    session['is_duress'] = False

    return jsonify({
        'message': 'Registration successful',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'organization_domain': user.organization_domain,
            'vault_access': user.vault_access,
            'is_duress': False
        }
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json or {}
    identifier = data.get('identifier', '').strip().lower()
    password = data.get('password', '')

    user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
    if not user:
        return jsonify({'error': 'Invalid email/username or password'}), 401

    is_duress = False
    # Check if duress password was entered (Panic / Decoy mode)
    if user.duress_password_hash and check_password_hash(user.duress_password_hash, password):
        is_duress = True
    elif check_password_hash(user.password_hash, password):
        is_duress = False
    else:
        return jsonify({'error': 'Invalid email/username or password'}), 401

    session['user_id'] = user.id
    session['email'] = user.email
    session['is_duress'] = is_duress

    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'organization_domain': user.organization_domain,
            'vault_access': user.vault_access and not is_duress,
            'is_duress': is_duress,
            'rsa_public_key': json.loads(user.rsa_public_key),
            'ecdsa_public_key': json.loads(user.ecdsa_public_key),
            'encrypted_private_keys': json.loads(user.encrypted_private_keys),
            'key_salt': user.key_salt
        }
    })

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/me', methods=['GET'])
def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'authenticated': False}), 200
    user = db.session.get(User, user_id)
    if not user:
        session.clear()
        return jsonify({'authenticated': False}), 200

    is_duress = session.get('is_duress', False)
    return jsonify({
        'authenticated': True,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'organization_domain': user.organization_domain,
            'vault_access': user.vault_access and not is_duress,
            'is_duress': is_duress,
            'rsa_public_key': json.loads(user.rsa_public_key),
            'ecdsa_public_key': json.loads(user.ecdsa_public_key),
            'encrypted_private_keys': json.loads(user.encrypted_private_keys),
            'key_salt': user.key_salt
        }
    })

@app.route('/api/user/keys/<email>', methods=['GET'])
def get_user_public_keys(email):
    email = email.strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': f'Recipient {email} not found in key directory'}), 404
    return jsonify({
        'email': user.email,
        'username': user.username,
        'organization_domain': user.organization_domain,
        'rsa_public_key': json.loads(user.rsa_public_key),
        'ecdsa_public_key': json.loads(user.ecdsa_public_key)
    })

@app.route('/api/users/directory', methods=['GET'])
def user_directory():
    users = User.query.with_entities(User.username, User.email).all()
    return jsonify([{'username': u.username, 'email': u.email} for u in users])

# ----------------- Email Routes ----------------- #

@app.route('/api/emails', methods=['GET'])
def list_emails():
    clean_expired_emails()
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    user = db.session.get(User, user_id)
    is_duress = session.get('is_duress', False)

    # Duress mode shows decoy dummy emails!
    if is_duress:
        decoy_emails = [
            {
                'id': 9901,
                'sender_email': 'orders@amazon-prime.com',
                'recipient_email': user.email,
                'is_vault': False,
                'status': 'decrypted',
                'encrypted_subject': 'PLAIN:Your Amazon.in order #402-91823 has shipped',
                'encrypted_body': 'PLAIN:Hello, your wireless earbuds order is out for delivery today.',
                'created_at': (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
                'is_read': True,
                'is_decoy': True
            },
            {
                'id': 9902,
                'sender_email': 'news@techcrunch.org',
                'recipient_email': user.email,
                'is_vault': False,
                'status': 'decrypted',
                'encrypted_subject': 'PLAIN:Weekly Tech Bulletin: Cloud Security Updates',
                'encrypted_body': 'PLAIN:Explore the top 10 trends in enterprise networking and data privacy.',
                'created_at': (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                'is_read': False,
                'is_decoy': True
            }
        ]
        return jsonify({'emails': decoy_emails})

    box = request.args.get('box', 'inbox') # 'inbox' or 'sent'
    mode = request.args.get('mode', 'normal') # 'normal' or 'vault'
    is_vault = (mode == 'vault')

    query = EmailMessage.query.filter_by(is_vault=is_vault, is_deleted=False)
    if box == 'inbox':
        query = query.filter_by(recipient_email=user.email)
    else:
        query = query.filter_by(sender_email=user.email)

    emails = query.order_by(EmailMessage.created_at.desc()).all()

    result = []
    for e in emails:
        result.append({
            'id': e.id,
            'sender_email': e.sender_email,
            'recipient_email': e.recipient_email,
            'is_vault': e.is_vault,
            'status': e.status, # 'sealed', 'vaulted', 'decrypted', 'shredded'
            'decrypted_at': e.decrypted_at.isoformat() if e.decrypted_at else None,
            'encrypted_subject': e.encrypted_subject,
            'encrypted_body': e.encrypted_body,
            'encrypted_key': e.encrypted_key_for_recipient if box == 'inbox' else e.encrypted_key_for_sender,
            'iv': e.iv,
            'signature': e.signature,
            'has_attachment': e.has_attachment,
            'attachment_name_encrypted': e.attachment_name_encrypted,
            'attachment_type': e.attachment_type,
            'is_burn_after_reading': e.is_burn_after_reading,
            'expires_at': e.expires_at.isoformat() if e.expires_at else None,
            'is_read': e.is_read,
            'created_at': e.created_at.isoformat()
        })

    return jsonify({'emails': result})

@app.route('/api/emails/<int:email_id>', methods=['GET'])
def get_single_email(email_id):
    clean_expired_emails()
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    user = db.session.get(User, user_id)
    email = db.session.get(EmailMessage, email_id)
    if not email or email.is_deleted:
        return jsonify({'error': 'Email not found or shredded'}), 404

    # Security check: only sender or recipient can access
    if email.recipient_email != user.email and email.sender_email != user.email:
        return jsonify({'error': 'Access denied'}), 403

    is_recipient = (email.recipient_email == user.email)
    key_for_user = email.encrypted_key_for_recipient if is_recipient else email.encrypted_key_for_sender

    response_data = {
        'id': email.id,
        'sender_email': email.sender_email,
        'recipient_email': email.recipient_email,
        'is_vault': email.is_vault,
        'status': email.status,
        'decrypted_at': email.decrypted_at.isoformat() if email.decrypted_at else None,
        'encrypted_subject': email.encrypted_subject,
        'encrypted_body': email.encrypted_body,
        'encrypted_key': key_for_user,
        'iv': email.iv,
        'signature': email.signature,
        'has_attachment': email.has_attachment,
        'attachment_name_encrypted': email.attachment_name_encrypted,
        'attachment_data_encrypted': email.attachment_data_encrypted,
        'attachment_type': email.attachment_type,
        'is_burn_after_reading': email.is_burn_after_reading,
        'expires_at': email.expires_at.isoformat() if email.expires_at else None,
        'created_at': email.created_at.isoformat()
    }

    # Cryptographic Read Progression:
    # When recipient opens it, record decryption timestamp and transition state to 'decrypted'
    if is_recipient:
        email.is_read = True
        email.status = 'decrypted'
        email.decrypted_at = datetime.now(timezone.utc)
        response_data['status'] = 'decrypted'
        response_data['decrypted_at'] = email.decrypted_at.isoformat()

        # Burn-after-reading: if enabled, shred immediately upon 1st viewing
        if email.is_burn_after_reading:
            email.view_count += 1
            email.status = 'shredded'
            # Shred immediately from storage
            db.session.delete(email)
            db.session.commit()
            response_data['shredded_on_read'] = True
            response_data['status'] = 'shredded'
            return jsonify(response_data)

    db.session.commit()
    return jsonify(response_data)

@app.route('/api/emails/send', methods=['POST'])
def send_email():
    clean_expired_emails()
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    sender = db.session.get(User, user_id)
    data = request.json or {}

    recipient_email = data.get('recipient_email', '').strip().lower()
    is_vault = bool(data.get('is_vault', False))
    encrypted_subject = data.get('encrypted_subject')
    encrypted_body = data.get('encrypted_body')
    key_recipient = data.get('encrypted_key_for_recipient')
    key_sender = data.get('encrypted_key_for_sender')
    iv = data.get('iv')
    signature = data.get('signature')

    if not all([recipient_email, encrypted_subject, encrypted_body, key_recipient, key_sender, iv, signature]):
        return jsonify({'error': 'Missing required encrypted payload attributes'}), 400

    recipient = User.query.filter_by(email=recipient_email).first()
    if not recipient:
        return jsonify({'error': f'Recipient {recipient_email} does not exist'}), 404

    # Calculate expiration if burn timer is set
    burn_timer_minutes = data.get('burn_timer_minutes')
    expires_at = None
    if burn_timer_minutes and int(burn_timer_minutes) > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=int(burn_timer_minutes))

    email = EmailMessage(
        sender_id=sender.id,
        sender_email=sender.email,
        recipient_email=recipient_email,
        is_vault=is_vault,
        status='vaulted', # Delivered to recipient vault
        encrypted_subject=encrypted_subject,
        encrypted_body=encrypted_body,
        encrypted_key_for_recipient=key_recipient,
        encrypted_key_for_sender=key_sender,
        iv=iv,
        signature=signature,
        has_attachment=bool(data.get('has_attachment', False)),
        attachment_name_encrypted=data.get('attachment_name_encrypted'),
        attachment_data_encrypted=data.get('attachment_data_encrypted'),
        attachment_type=data.get('attachment_type'),
        is_burn_after_reading=bool(data.get('is_burn_after_reading', False)),
        expires_at=expires_at
    )

    db.session.add(email)
    db.session.commit()

    return jsonify({'message': 'Encrypted email dispatched successfully', 'email_id': email.id}), 201

@app.route('/api/emails/<int:email_id>', methods=['DELETE'])
def delete_email(email_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    user = db.session.get(User, user_id)
    email = db.session.get(EmailMessage, email_id)
    if not email:
        return jsonify({'error': 'Email not found'}), 404

    if email.recipient_email != user.email and email.sender_email != user.email:
        return jsonify({'error': 'Unauthorized'}), 403

    db.session.delete(email)
    db.session.commit()
    return jsonify({'message': 'Email permanently shredded'})

# ----------------- Database / Audit Inspection Route for Viva ----------------- #

@app.route('/api/system/audit', methods=['GET'])
def audit_database():
    emails = EmailMessage.query.order_by(EmailMessage.id.desc()).limit(8).all()
    records = []
    for e in emails:
        records.append({
            'id': e.id,
            'is_vault': e.is_vault,
            'status': e.status,
            'sender': e.sender_email,
            'recipient': e.recipient_email,
            'raw_encrypted_subject': e.encrypted_subject[:45] + '... (BASE64 CIPHERTEXT)',
            'raw_encrypted_body': e.encrypted_body[:60] + '... (BASE64 CIPHERTEXT)',
            'session_key_recipient': e.encrypted_key_for_recipient[:45] + '...',
            'iv_nonce': e.iv,
            'signature': e.signature[:45] + '... (ECDSA DIGITAL SIGNATURE)',
            'is_burn_after_reading': e.is_burn_after_reading,
            'expires_at': str(e.expires_at) if e.expires_at else 'None'
        })
    return jsonify({
        'server_state': 'Zero-Knowledge Storage Active',
        'encryption_mode': 'AES-256-GCM + RSA-OAEP + ECDSA Non-Repudiation',
        'raw_database_records': records
    })

# ----------------- Web UI Route ----------------- #

@app.route('/')
def index():
    return render_template('index.html')

# Vercel needs the app object at module level (already defined above as 'app')
# Local dev server
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print("================================================================")
    print(" CipherMail - Zero-Knowledge E2EE Webmail System")
    print(f" Server running at: http://0.0.0.0:{port}")
    print("================================================================")
    app.run(host='0.0.0.0', debug=False, port=port)

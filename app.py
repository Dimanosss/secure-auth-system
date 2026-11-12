import os
import re
import io
import base64
import random
import string
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, redirect, url_for, request, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from PIL import Image, ImageDraw
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(20), default='user')
    
    is_active_account = db.Column(db.Boolean, default=False)
    activation_token = db.Column(db.String(100), nullable=True)
    activation_expires = db.Column(db.DateTime, nullable=True)
    
    is_blocked_by_admin = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    two_factor_enabled = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    
    reset_token = db.Column(db.String(100), nullable=True)
    reset_expires = db.Column(db.DateTime, nullable=True)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_attempted = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

COMMON_PASSWORDS = {'password', '12345678', 'qwerty123', 'admin123', 'password1!'}

def validate_password(password):
    if len(password) < 8:
        return False, "Пароль повинен містити щонайменше 8 символів."
    if not re.search(r"[A-Z]", password):
        return False, "Пароль повинен містити хоча б одну велику літеру."
    if not re.search(r"[a-z]", password):
        return False, "Пароль повинен містити хоча б одну малу літеру."
    if not re.search(r"\d", password):
        return False, "Пароль повинен містити хоча б одну цифру."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Пароль повинен містити хоча б один спеціальний символ."
    if password.lower() in COMMON_PASSWORDS:
        return False, "Цей пароль занадто поширений і слабкий."
    return True, "OK"

def generate_captcha():
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    session['captcha_code'] = code
    img = Image.new('RGB', (150, 50), color=(240, 240, 240))
    d = ImageDraw.Draw(img)
    for _ in range(5):
        d.line([(random.randint(0, 150), random.randint(0, 50)),
                (random.randint(0, 150), random.randint(0, 50))], fill=(180, 180, 180), width=2)
    for i, char in enumerate(code):
        d.text((15 + i * 25, random.randint(10, 20)), char, fill=(20, 20, 100))
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('utf-8')

def log_login_attempt(email, status):
    log = LoginLog(
        email_attempted=email,
        ip_address=request.remote_addr or '127.0.0.1',
        status=status
    )
    db.session.add(log)
    db.session.commit()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        captcha_input = request.form.get('captcha', '').strip().upper()

        if captcha_input != session.get('captcha_code'):
            flash('Невірний код CAPTCHA!', 'danger')
            return render_template('register.html', captcha_img=generate_captcha())

        is_valid, msg = validate_password(password)
        if not is_valid:
            flash(msg, 'danger')
            return render_template('register.html', captcha_img=generate_captcha())

        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash('Користувач з таким email або логіном вже існує.', 'danger')
            return render_template('register.html', captcha_img=generate_captcha())

        token = secrets.token_urlsafe(32)
        role = 'admin' if User.query.count() == 0 else 'user'

        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256', salt_length=16),
            role=role,
            is_active_account=False,
            activation_token=token,
            activation_expires=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(new_user)
        db.session.commit()

        activation_link = url_for('activate_account', token=token, _external=True)
        print(f"\n[EMAIL SIMULATION] Лист для {email}. Посилання активації: {activation_link}\n")
        flash(f'Реєстрація успішна! (Емуляція Email: перейдіть за посиланням для активації: {activation_link})', 'info')
        return redirect(url_for('login'))

    return render_template('register.html', captcha_img=generate_captcha())

@app.route('/activate/<token>')
def activate_account(token):
    user = User.query.filter_by(activation_token=token).first()
    if not user:
        flash('Недійсний токен активації.', 'danger')
        return redirect(url_for('login'))
    if user.activation_expires < datetime.utcnow():
        flash('Термін дії токену активації вичерпано.', 'danger')
        return redirect(url_for('login'))

    user.is_active_account = True
    user.activation_token = None
    user.activation_expires = None
    db.session.commit()
    flash('Обліковий запис успішно активовано! Тепер ви можете увійти.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not user:
            log_login_attempt(email, 'USER_NOT_FOUND')
            flash('Невірний email або пароль.', 'danger')
            return redirect(url_for('login'))

        if user.is_blocked_by_admin:
            log_login_attempt(email, 'BLOCKED_BY_ADMIN')
            flash('Ваш обліковий запис заблоковано адміністратором.', 'danger')
            return redirect(url_for('login'))

        if user.locked_until and user.locked_until > datetime.utcnow():
            remaining = int((user.locked_until - datetime.utcnow()).total_seconds() // 60) + 1
            log_login_attempt(email, 'BRUTE_FORCE_LOCKED')
            flash(f'Забагато невдалих спроб. Спробуйте через {remaining} хв.', 'danger')
            return redirect(url_for('login'))

        if not user.password_hash or not check_password_hash(user.password_hash, password):
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=5)
                log_login_attempt(email, 'LOCKED_AFTER_5_ATTEMPTS')
                flash('Перевищено ліміт спроб (5). Акаунт заблоковано на 5 хвилин.', 'danger')
            else:
                log_login_attempt(email, f'FAILED_PASSWORD ({user.failed_attempts}/5)')
                flash(f'Невірний пароль. Залишилось спроб: {5 - user.failed_attempts}', 'danger')
            db.session.commit()
            return redirect(url_for('login'))

        user.failed_attempts = 0
        user.locked_until = None
        db.session.commit()

        if user.two_factor_enabled:
            session['pre_2fa_user_id'] = user.id
            return redirect(url_for('verify_2fa'))

        login_user(user)
        log_login_attempt(email, 'SUCCESS')
        return redirect(url_for('profile'))

    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = User.query.get(user_id)

    if request.method == 'POST':
        otp_code = request.form.get('otp_code').strip()
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(otp_code):
            session.pop('pre_2fa_user_id', None)
            login_user(user)
            log_login_attempt(user.email, 'SUCCESS_WITH_2FA')
            return redirect(url_for('profile'))
        else:
            log_login_attempt(user.email, 'FAILED_2FA')
            flash('Невірний код двофакторної автентифікації.', 'danger')

    return render_template('verify_2fa.html')

@app.route('/login/google')
def google_login():
    if app.config['GOOGLE_CLIENT_ID'] == 'YOUR_GOOGLE_CLIENT_ID':
        flash('Увага: Не налаштовано GOOGLE_CLIENT_ID у змінних середовища (див. app.py).', 'warning')
        return redirect(url_for('login'))
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/callback')
def google_callback():
    token = google.authorize_access_token()
    user_info = token.get('userinfo')
    email = user_info['email'].lower()
    
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            username=user_info.get('name', email.split('@')[0]),
            email=email,
            is_active_account=True,
            role='admin' if User.query.count() == 0 else 'user'
        )
        db.session.add(user)
        db.session.commit()

    if user.is_blocked_by_admin:
        flash('Ваш обліковий запис заблоковано адміністратором.', 'danger')
        return redirect(url_for('login'))

    login_user(user)
    log_login_attempt(email, 'SUCCESS_OAUTH_GOOGLE')
    return redirect(url_for('profile'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_expires = datetime.utcnow() + timedelta(minutes=30)
            db.session.commit()
            
            reset_link = url_for('reset_password', token=token, _external=True)
            print(f"\n[EMAIL SIMULATION] Скидання пароля для {email}: {reset_link}\n")
            flash(f'Інструкцію надіслано! (Емуляція Email: {reset_link})', 'info')
        else:
            flash('Якщо такий email зареєстровано, ми надіслали посилання для відновлення.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or user.reset_expires < datetime.utcnow():
        flash('Недійсний або прострочений токен відновлення пароля.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        is_valid, msg = validate_password(new_password)
        if not is_valid:
            flash(msg, 'danger')
            return render_template('reset_password.html')

        user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
        user.reset_token = None
        user.reset_expires = None
        user.failed_attempts = 0
        user.locked_until = None
        db.session.commit()
        flash('Пароль успішно змінено! Увійдіть з новим паролем.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/profile')
@login_required
def profile():
    qr_b64 = None
    if not current_user.two_factor_enabled:
        if not current_user.totp_secret:
            current_user.totp_secret = pyotp.random_base32()
            db.session.commit()
        totp_uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
            name=current_user.email, issuer_name="SecureAuthApp"
        )
        img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('profile.html', qr_b64=qr_b64)

@app.route('/toggle-2fa', methods=['POST'])
@login_required
def toggle_2fa():
    if current_user.two_factor_enabled:
        current_user.two_factor_enabled = False
        current_user.totp_secret = None
        flash('Двофакторну автентифікацію вимкнено.', 'warning')
    else:
        code = request.form.get('otp_code', '').strip()
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(code):
            current_user.two_factor_enabled = True
            flash('Двофакторну автентифікацію успішно увімкнено!', 'success')
        else:
            flash('Невірний код підтвердження з додатку.', 'danger')
    db.session.commit()
    return redirect(url_for('profile'))

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    users = User.query.all()
    logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(50).all()
    return render_template('admin.html', users=users, logs=logs)

@app.route('/admin/toggle-block/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_block_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Ви не можете заблокувати самого себе.', 'danger')
    else:
        user.is_blocked_by_admin = not user.is_blocked_by_admin
        db.session.commit()
        status = "заблоковано" if user.is_blocked_by_admin else "розблоковано"
        flash(f'Користувача {user.email} {status}.', 'info')
    return redirect(url_for('admin_panel'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ви вийшли із системи.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

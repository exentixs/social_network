from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import SQLAlchemyError
import logging
import socket

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social_network.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    profile_description = db.Column(db.String(500), nullable=True)
    avatar = db.Column(db.String(150), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already in use. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    profile_description = StringField('Profile Description', validators=[Length(max=500)])
    avatar = StringField('Avatar URL')
    submit = SubmitField('Update Profile')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is already in use. Please choose a different one.')

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.')
            logger.info(f'New user registered: {form.username.data}')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f'Error during registration: {e}')
            flash('An error occurred during registration. Please try again.')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('profile'))
        else:
            flash('Login unsuccessful. Please check your email and password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        try:
            current_user.username = form.username.data
            current_user.profile_description = form.profile_description.data
            current_user.avatar = form.avatar.data
            db.session.commit()
            flash('Profile updated successfully.')
            logger.info(f'Profile updated for user: {current_user.username}')
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f'Error updating profile: {e}')
            flash('An error occurred while updating your profile. Please try again.')
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form)

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

def get_local_ip():
    """Получает локальный IP-адрес для доступа в локальной сети."""
    try:
        # Создаём временный сокет для получения IP-адреса
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))  # Подключаемся к публичному DNS-серверу
            local_ip = s.getsockname()[0]
        return local_ip
    except Exception as e:
        logger.error(f"Could not determine local IP: {e}")
        return "127.0.0.1"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Создание таблиц в базе данных

    # Определяем порт и локальный IP
    port = 5000
    local_ip = get_local_ip()

    # Выводим ссылки для доступа
    print("\n=== Access URLs ===")
    print(f"Local access:      http://127.0.0.1:{port}")
    print(f"Local network:     http://{local_ip}:{port}")
    print("===================\n")

    # Запускаем сервер
    app.run(debug=True, host='0.0.0.0', port=port)

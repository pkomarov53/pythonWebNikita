from datetime import datetime

from flask import Flask, render_template, flash, redirect, url_for, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Optional
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    middle_name = db.Column(db.String(64))
    conscription_certificate = db.Column(db.String(64), nullable=True)
    military_id = db.Column(db.String(64), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    appointment_type = db.Column(db.String(50), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime)


class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


class RegisterFormStep1(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    confirm_password = PasswordField('Повтор пароля', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Далее')


class RegisterFormStep2(FlaskForm):
    first_name = StringField('Имя', validators=[DataRequired()])
    middle_name = StringField('Фамилия', validators=[DataRequired()])
    last_name = StringField('Отчество (при наличии)', validators=[Optional()])
    conscription_certificate = StringField('Номер приписного свидетельства (при наличии)', validators=[Optional()])
    military_id = StringField('Номер военного билета (при наличии)', validators=[Optional()])
    submit = SubmitField('Регистрация')


@app.route('/')
def index():
    return render_template('index.html', title='Главная')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title='Авторизация', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterFormStep1()
    if form.validate_on_submit():
        session['username'] = form.username.data
        session['password'] = form.password.data
        return redirect(url_for('register_step2'))
    return render_template('register.html', title='Регистрация', form=form)


@app.route('/register_step2', methods=['GET', 'POST'])
def register_step2():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterFormStep2()
    if form.validate_on_submit():
        user = User(username=session['username'])
        user.set_password(session['password'])
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.middle_name = form.middle_name.data
        user.conscription_certificate = form.conscription_certificate.data
        user.military_id = form.military_id.data
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register_about.html', title='О вас', form=form)


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Profile', user=current_user)


if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('app.db'):
            db.create_all()
    app.run(debug=True)

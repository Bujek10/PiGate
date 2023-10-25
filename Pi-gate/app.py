from flask import Flask, render_template, session, redirect, url_for, flash
from flask_bs4 import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
import os

# konfiguracja aplikacji
app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = 'fghjklpoiuy%^&*())(*UYTGHI*&'
bcrypt = Bcrypt(app)

# konfiguracja bazy danych użytkowników i tablic
baseDir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(baseDir, 'data/database.db')
db = SQLAlchemy(app)
path2='sqlite:///' + os.path.join(baseDir, 'data/databasePlates.db')
app.config['SQLALCHEMY_BINDS'] = {
        'dbPlates': path2
}

# tabela bazy danych użytkowników
class Users(db.Model, UserMixin):
    """
    Tabela z użytkownikami
    """
    id = db.Column(db.Integer, primary_key=True)
    userLogin = db.Column(db.String(50), unique=True)
    userPass = db.Column(db.String(50))
    firstName = db.Column(db.String(50))
    lastName = db.Column(db.String(50))

    def is_authenticated(self):
        return True


# tabela bazy danych tablic rejestracyjnych
class UsersPlates(db.Model, UserMixin):
    """
    Tabela z użytkownikami i rejestracjami
    """
    __bind_key__ = 'dbPlates'
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(50))
    lastName = db.Column(db.String(50))
    userPlate = db.Column(db.String(10), unique=True)


# konfiguracja Flask-Login
logInManager = LoginManager()
logInManager.init_app(app)
logInManager.login_view = 'login'
logInManager.login_message = 'Nie jesteś zalogowany'
logInManager.login_message_category = 'warning'

@logInManager.user_loader
def loadUser(id):
    return Users.query.filter_by(id=id).first()

class Register(FlaskForm):
    """
    Formularz rejestracji użytkowników
    """
    userLogin = StringField('Login:', validators=[DataRequired(), Length(min=3, max=50)])
    userPass = PasswordField('Hasło:', validators=[DataRequired(), Length(min=3, max=50)])
    firstName = StringField('Imię:', validators=[DataRequired(), Length(min=3, max=50)])
    lastName = StringField('Nazwisko:', validators=[DataRequired(), Length(min=3, max=50)])
    submit = SubmitField('Rejestruj')

class Login(FlaskForm):
    """
    Formularz logowania użytkowników
    """
    userLogin = StringField('Login:', validators=[DataRequired(), Length(min=3, max=50)])
    userPass = PasswordField('Hasło:', validators=[DataRequired(), Length(min=3, max=50)])
    submit = SubmitField('Zaloguj')

class RegisterPlates(FlaskForm):
    """
    Formularz dodawania użytkowników i tablic
    """
    firstName = StringField('Imię:', validators=[DataRequired(), Length(min=3, max=50)])
    lastName = StringField('Nazwisko:', validators=[DataRequired(), Length(min=3, max=50)])
    userPlate = StringField('Tablica rejestracyjna:', validators=[DataRequired(), Length(min=3, max=10)])
    submit = SubmitField('Dodaj')

@app.route('/')
def index():
    return render_template('index.html', title='Home')



@app.route('/login', methods=['POST', 'GET'])
def login():
    user = Users.query.all()
    if not user:
        return redirect(url_for('register'))
    else:
        loginForm = Login()
        if loginForm.validate_on_submit():
            user = Users.query.filter_by(userLogin=loginForm.userLogin.data).first()
            if user:
                if bcrypt.check_password_hash(user.userPass, loginForm.userPass.data):
                    login_user(user)
                    return redirect(url_for('dashboard'))
    return render_template('login.html', title='Logowanie', loginForm=loginForm)


@app.route('/registerPlates', methods=['POST', 'GET'])
@login_required
def registerPlates():
    registerFormPlates = RegisterPlates()
    if registerFormPlates.validate_on_submit():
        try:
            newUserPlate = UsersPlates(
                firstName=registerFormPlates.firstName.data,
                lastName=registerFormPlates.lastName.data,
                userPlate=registerFormPlates.userPlate.data
            )
            db.session.add(newUserPlate)
            db.session.commit()
            flash('Rejestracja została dodana poprawnie', 'success')
            return redirect(url_for('platesTable'))
        except Exception:
            db.session.rollback()
            registerFormPlates.userPlate.data=""
            flash('Rejestracja już istnieje w bazie. Proszę wybrać inną.', 'danger')
    return render_template('registerPlates.html', title='Dodawanie tablic', registerFormPlates=registerFormPlates)

@app.route('/register', methods=['POST', 'GET'])
def register():
    registerForm = Register()
    if registerForm.validate_on_submit():
        try:
            hashedPass = bcrypt.generate_password_hash(registerForm.userPass.data)
            newUser = Users(
                userLogin=registerForm.userLogin.data,
                userPass=hashedPass,
                firstName=registerForm.firstName.data,
                lastName=registerForm.lastName.data
            )
            db.session.add(newUser)
            db.session.commit()
            flash('Konto zostało utworzone poprawnie', 'success')
            return redirect(url_for('dashboard'))
        except Exception:
            db.session.rollback()
            registerForm.userLogin.data = ""
            flash('Nazwa użytkownika istnieje. Proszę wybrać inną.', 'danger')
    return render_template('register.html', title='Rejestracja', registerForm=registerForm)

@app.route('/platesTable')
@login_required
def platesTable():
    databasePlates = UsersPlates.query.all()
    return render_template('platesTable.html', title='Tablice', databasePlates=databasePlates)


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', title='Dashboard')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        db.create_all(bind='dbPlates')
    app.run(debug=True)
from flask import Flask, render_template, session, redirect, url_for, flash, request
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
path2='sqlite:///' + os.path.join(baseDir, 'data/databaseUsers.db')
app.config['SQLALCHEMY_BINDS'] = {
        'dbUsers': path2
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
class UsersData(db.Model, UserMixin):
    """
    Tabela z użytkownikami i rejestracjami
    """
    __bind_key__ = 'dbUsers'
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(50))
    lastName = db.Column(db.String(50))
    userPlate = db.Column(db.String(10), unique=True)
    userTag = db.Column(db.String(15), unique=True)


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

class administratorEdit(FlaskForm):
    """
    Formularz edycji administratorów
    """
    userLogin = StringField('Login:', validators=[DataRequired(), Length(min=3, max=50)])
    firstName = StringField('Imię:', validators=[DataRequired(), Length(min=3, max=50)])
    lastName = StringField('Nazwisko:', validators=[DataRequired(), Length(min=3, max=50)])
    submit = SubmitField('Edytuj')

class RegisterAdminDel(FlaskForm):
    """
    Przycisk do usuwania wpisu
    """
    submit = SubmitField('Usuń')

class passwordChange(FlaskForm):
    """
    Formularz do zmiany hasła
    """
    userPass = PasswordField('Stare hasło:', validators=[DataRequired(), Length(min=3, max=50)])
    newPass = PasswordField('Nowe hasło:', validators=[DataRequired(), Length(min=3, max=50)])
    repeatPass = PasswordField('Powtórz nowe hasło:', validators=[DataRequired(), Length(min=3, max=50)])
    submit = SubmitField('Potwierdź')


class Login(FlaskForm):
    """
    Formularz logowania użytkowników
    """
    userLogin = StringField('Login:', validators=[DataRequired(), Length(min=3, max=50)])
    userPass = PasswordField('Hasło:', validators=[DataRequired(), Length(min=3, max=50)])
    submit = SubmitField('Zaloguj')

class RegisterUsers(FlaskForm):
    """
    Formularz dodawania użytkowników i tablic
    """
    firstName = StringField('Imię:', validators=[DataRequired(), Length(min=3, max=50)])
    lastName = StringField('Nazwisko:', validators=[DataRequired(), Length(min=3, max=50)])
    userPlate = StringField('Tablica rejestracyjna:', validators=[Length(min=0, max=10)])
    userTag = StringField('Tag RFID/NFC:', validators=[Length(min=0, max=15)])
    submit = SubmitField('Potwierdź')

class RegisterUsersDel(FlaskForm):
    """
    Przycisk do usuwania wpisu
    """
    submit = SubmitField('Usuń')



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


@app.route('/registerUsers', methods=['POST', 'GET'])
@login_required
def registerUsers():
    registerFormUsers = RegisterUsers()
    if registerFormUsers.validate_on_submit():
        try:
            if (registerFormUsers.userPlate.data == "" or registerFormUsers.userPlate.data.capitalize() == "Brak")  and (registerFormUsers.userTag.data == "" or registerFormUsers.userTag.data.capitalize() == "Brak"):
                flash('Dodaj conajmniej jeden sposób autoryzacji', 'danger')
            elif registerFormUsers.userPlate.data == "":
                newUserPlate = UsersData(
                    firstName=registerFormUsers.firstName.data.capitalize(),
                    lastName=registerFormUsers.lastName.data.capitalize(),
                    userTag=registerFormUsers.userTag.data
                )
                db.session.add(newUserPlate)
                db.session.commit()
                flash('Użytkowmik został dodany poprawnie', 'success')
                return redirect(url_for('usersTable'))
            elif registerFormUsers.userTag.data=="":
                newUserPlate = UsersData(
                    firstName=registerFormUsers.firstName.data.capitalize(),
                    lastName=registerFormUsers.lastName.data.capitalize(),
                    userPlate=registerFormUsers.userPlate.data.upper(),
                )
                db.session.add(newUserPlate)
                db.session.commit()
                flash('Użytkowmik został dodany poprawnie', 'success')
                return redirect(url_for('usersTable'))
            else:
                newUserPlate = UsersData(
                    firstName=registerFormUsers.firstName.data.capitalize(),
                    lastName=registerFormUsers.lastName.data.capitalize(),
                    userPlate=registerFormUsers.userPlate.data.upper(),
                    userTag=registerFormUsers.userTag.data
                )
                db.session.add(newUserPlate)
                db.session.commit()
                flash('Użytkownik został dodany poprawnie', 'success')
                return redirect(url_for('usersTable'))

        except Exception:
            db.session.rollback()
            registerFormUsers.userTag.data = ""
            registerFormUsers.userPlate.data = ""
            flash('Rejestracja lub Tag już istnieje w bazie. Podaj dane ponownie.', 'danger')

    return render_template('registerUsers.html', title='Dodawanie tablic', registerFormUsers=registerFormUsers)

@app.route('/register', methods=['POST', 'GET'])
def register():
    registerForm = Register()
    if registerForm.validate_on_submit():
        try:
            hashedPass = bcrypt.generate_password_hash(registerForm.userPass.data)
            newUser = Users(
                userLogin=registerForm.userLogin.data,
                userPass=hashedPass,
                firstName=registerForm.firstName.data.capitalize(),
                lastName=registerForm.lastName.data.capitalize()
            )
            db.session.add(newUser)
            db.session.commit()
            flash('Konto zostało utworzone poprawnie', 'success')
            return redirect(url_for('adminTable'))
        except Exception:
            db.session.rollback()
            registerForm.userLogin.data = ""
            flash('Nazwa użytkownika istnieje. Proszę wybrać inną.', 'danger')
    return render_template('register.html', title='Rejestracja', registerForm=registerForm)

@app.route('/usersTable', methods=['GET', 'POST'])
@login_required
def usersTable():
    databaseUsers = UsersData.query.order_by(UsersData.lastName.asc()).all()
    registerFormUsersDel = RegisterUsersDel()
    registerFormUsersEdit = RegisterUsers()
    if registerFormUsersEdit.validate_on_submit():
        try:
            targetId = request.form.get('ID')
            userEdit=UsersData.query.get(targetId)

            userEdit.firstName = registerFormUsersEdit.firstName.data.capitalize()
            userEdit.lastName = registerFormUsersEdit.lastName.data.capitalize()

            if (registerFormUsersEdit.userTag.data.capitalize() == "Brak" or registerFormUsersEdit.userTag.data == "") and (registerFormUsersEdit.userPlate.data.capitalize() == "Brak" or registerFormUsersEdit.userPlate.data == ""):
                flash ('Podaj conajmniej jeden sposób autoryzacji', 'danger')
            elif registerFormUsersEdit.userTag.data.capitalize=="Brak" or registerFormUsersEdit.userTag.data=="":
                userEdit.userTag = None
                userEdit.userPlate = registerFormUsersEdit.userPlate.data.upper()
                db.session.commit()
                flash('Wpis został edytowany', 'success')
                return redirect(url_for('usersTable'))
            elif registerFormUsersEdit.userPlate.data.capitalize()=="Brak" or registerFormUsersEdit.userPlate.data=="":
                userEdit.userPlate = None
                userEdit.userTag = registerFormUsersEdit.userTag.data
                db.session.commit()
                flash('Wpis został edytowany', 'success')
                return redirect(url_for('usersTable'))
            else:
                userEdit.userPlate = registerFormUsersEdit.userPlate.data.upper()
                userEdit.userTag = registerFormUsersEdit.userTag.data
                db.session.commit()
                flash('Wpis został edytowany', 'success')
                return redirect(url_for('usersTable'))

        except Exception:
            db.session.rollback()
            flash('Błąd edycji', 'danger')

    elif registerFormUsersDel.validate_on_submit():
        try:
            targetIdDel = request.form.get('IDdel')
            userDel=UsersData.query.get(targetIdDel)
            db.session.delete(userDel)
            db.session.commit()
            flash('Wpis został usunięty', 'success')
            return redirect(url_for('usersTable'))
        except Exception:
            db.session.rollback()
            flash('Błąd usuwania', 'danger')
    else:
        pass

    return render_template('usersTable.html', title='Tablice', databaseUsers=databaseUsers, registerFormUsersEdit=registerFormUsersEdit, registerFormUsersDel=registerFormUsersDel)


@app.route('/adminTable', methods=['GET', 'POST'])
@login_required
def adminTable():
    databaseAdmin = Users.query.order_by(Users.lastName.asc()).all()
    registerFormAdminDel = RegisterAdminDel()
    registerFormAdminEdit = administratorEdit()
    if registerFormAdminEdit.validate_on_submit():
        try:
            targetId = request.form.get('ID')
            adminEdit=Users.query.get(targetId)

            if (registerFormAdminEdit.userLogin.data=="Brak" or registerFormAdminEdit.userLogin.data=="" or registerFormAdminEdit.firstName.data=="Brak" or registerFormAdminEdit.firstName.data=="" or registerFormAdminEdit.lastName.data=="Brak" or registerFormAdminEdit.lastName.data==""):
                flash('Wypełnij wszystkie pola.', 'danger')
            else:
                adminEdit.userLogin = registerFormAdminEdit.userLogin.data
                adminEdit.firstName = registerFormAdminEdit.firstName.data.capitalize()
                adminEdit.lastName = registerFormAdminEdit.lastName.data.capitalize()
                db.session.commit()
                flash('Wpis został edytowany', 'success')
                return redirect(url_for('adminTable'))
        except Exception:
            db.session.rollback()
            flash('Błąd edycji', 'danger')
    elif registerFormAdminDel.validate_on_submit():
        try:
            targetIdDel = request.form.get('IDdel')
            adminDel=Users.query.get(targetIdDel)
            print(current_user.id, targetIdDel)
            if int(targetIdDel)==int(current_user.id):
                flash('Nie można usunąć swojego konta', 'danger')
            else:
                db.session.delete(adminDel)
                db.session.commit()
                flash('Administrator został usunięty', 'success')
                return redirect(url_for('adminTable'))
        except Exception:
            db.session.rollback()
            flash('Błąd usuwania', 'danger')
    else:
        pass

    return render_template('adminTable.html', title='Administratorzy', databaseAdmin=databaseAdmin, registerFormAdminEdit=registerFormAdminEdit, registerFormAdminDel=registerFormAdminDel)


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', title='Dashboard')

@app.route('/passChange', methods=['POST', 'GET'])
@login_required
def passChange():
    currentUser = Users.query.filter_by(id=current_user.id).first()
    passChangeForm = passwordChange()
    if passChangeForm.validate_on_submit():
        try:
            hashedPassOldGood = bcrypt.check_password_hash(currentUser.userPass, passChangeForm.userPass.data)
            hashedPassNew = bcrypt.generate_password_hash(passChangeForm.newPass.data)
            hashedPassRepeatGood = bcrypt.check_password_hash(hashedPassNew, passChangeForm.repeatPass.data)

            if hashedPassOldGood:
                if hashedPassRepeatGood:
                    currentUser.userPass=hashedPassNew
                    db.session.commit()
                    flash('Hasło zostało zmienione.', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Hasła się nie zgadzają.', 'danger')
            else:
                flash('Błędne stare hasło.', 'danger')

        except Exception:
            flash('Hasło nie zostało zmienione.', 'danger')
            return redirect(url_for('dashboard'))

    return render_template('passChange.html', title='Zmiana hasła', passChangeForm=passChangeForm)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        db.create_all(bind='dbUsers')
    app.run(debug=True)




from flask import Flask, render_template, redirect, url_for, flash, request, Response
from flask_bs4 import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Length, StopValidation, NumberRange
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from datetime import datetime
import os
import cv2


# konfiguracja bazy danych użytkowników i tablic

baseDir = os.path.abspath(os.path.dirname(__file__))
# dataFolder = os.path.join(baseDir, 'data')
# os.mkdir(dataFolder)
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(baseDir, 'data/database.db')
path2 = 'sqlite:///' + os.path.join(baseDir, 'data/databaseUsers.db')
SQLALCHEMY_BINDS = {
    'dbUsers': path2
}

# konfiguracja aplikacji
app = Flask(__name__)
app.config.from_object(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = 'fghjklpoiuy%^&*())(*UYTGHI*&'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

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
    monChk = db.Column(db.Boolean)
    monFromH = db.Column(db.String(2))
    monFromM = db.Column(db.String(2))
    monToH = db.Column(db.String(2))
    monToM = db.Column(db.String(2))
    tueChk = db.Column(db.Boolean)
    tueFromH = db.Column(db.String(2))
    tueFromM = db.Column(db.String(2))
    tueToH = db.Column(db.String(2))
    tueToM = db.Column(db.String(2))
    wedChk = db.Column(db.Boolean)
    wedFromH = db.Column(db.String(2))
    wedFromM = db.Column(db.String(2))
    wedToH = db.Column(db.String(2))
    wedToM = db.Column(db.String(2))
    thuChk = db.Column(db.Boolean)
    thuFromH = db.Column(db.String(2))
    thuFromM = db.Column(db.String(2))
    thuToH = db.Column(db.String(2))
    thuToM = db.Column(db.String(2))
    friChk = db.Column(db.Boolean)
    friFromH = db.Column(db.String(2))
    friFromM = db.Column(db.String(2))
    friToH = db.Column(db.String(2))
    friToM = db.Column(db.String(2))
    satChk = db.Column(db.Boolean)
    satFromH = db.Column(db.String(2))
    satFromM = db.Column(db.String(2))
    satToH = db.Column(db.String(2))
    satToM = db.Column(db.String(2))
    sunChk = db.Column(db.Boolean)
    sunFromH = db.Column(db.String(2))
    sunFromM = db.Column(db.String(2))
    sunToH = db.Column(db.String(2))
    sunToM = db.Column(db.String(2))


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
    submit = SubmitField('Dodaj')

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

def hourCheck(form, field):
    if not((int(field.data) >= 0) and (int(field.data) <= 23)):
        raise StopValidation("Podaj godzine od 0 do 23")

def minuteCheck(form, field):
    if not ((int(field.data) >= 0) and (int(field.data) <= 59)):
        raise StopValidation("Podaj minuty od 0 do 59")

class hours(FlaskForm):
    """Formularz godzin dostępu"""
    monFromH = IntegerField(validators=[NumberRange(min=0, max=23)])
    monFromM = IntegerField(validators=[NumberRange(min=0, max=59)])
    monToH = IntegerField(validators=[NumberRange(min=0, max=23)])
    monToM = IntegerField(validators=[NumberRange(min=0, max=59)])
    tueFromH = IntegerField(validators=[NumberRange(min=0, max=23)])
    tueFromM = IntegerField(validators=[NumberRange(min=0, max=59)])
    tueToH = IntegerField(validators=[NumberRange(min=0, max=23)])
    tueToM = IntegerField(validators=[NumberRange(min=0, max=59)])
    wedFromH = IntegerField(validators=[NumberRange(min=0, max=23)])
    wedFromM = IntegerField(validators=[NumberRange(min=0, max=59)])
    wedToH = IntegerField(validators=[NumberRange(min=0, max=23)])
    wedToM = IntegerField(validators=[NumberRange(min=0, max=59)])
    thuFromH = IntegerField(validators=[NumberRange(min=0, max=23)])
    thuFromM = IntegerField(validators=[NumberRange(min=0, max=59)])
    thuToH = IntegerField(validators=[NumberRange(min=0, max=23)])
    thuToM = IntegerField(validators=[NumberRange(min=0, max=59)])
    friFromH = IntegerField(validators=[NumberRange(min=0, max=23)])
    friFromM = IntegerField(validators=[NumberRange(min=0, max=59)])
    friToH = IntegerField(validators=[NumberRange(min=0, max=23)])
    friToM = IntegerField(validators=[NumberRange(min=0, max=59)])
    satFromH = IntegerField(validators=[NumberRange(min=0, max=23)])
    satFromM = IntegerField(validators=[NumberRange(min=0, max=59)])
    satToH = IntegerField(validators=[NumberRange(min=0, max=23)])
    satToM = IntegerField(validators=[NumberRange(min=0, max=59)])
    sunFromH = IntegerField(validators=[NumberRange(min=0, max=23)])
    sunFromM = IntegerField(validators=[NumberRange(min=0, max=59)])
    sunToH = IntegerField(validators=[NumberRange(min=0, max=23)])
    sunToM = IntegerField(validators=[NumberRange(min=0, max=59)])
    monChk = BooleanField()
    tueChk = BooleanField()
    wedChk = BooleanField()
    thuChk = BooleanField()
    friChk = BooleanField()
    satChk = BooleanField()
    sunChk = BooleanField()
    submit = SubmitField('Zapisz')


def canAccess(user_id):
    checkUser = UsersData.query.filter_by(id=user_id).first()
    day = datetime.today().weekday()
    hour = datetime.now().hour
    minute = datetime.now().minute
    if day == 0:
        if (int(checkUser.monFromH) <= hour) and (int(checkUser.monFromM <= minute)) and (int(checkUser.monToH) >= hour) and (int(checkUser.monToM >= minute)) and (checkUser.monChk == True):
            return True
    elif day == 1:
        if (int(checkUser.tueFromH <= hour)) and (int(checkUser.tueFromM <= minute)) and (int(checkUser.tueToH >= hour)) and (int(checkUser.tueToM >= minute)) and (checkUser.tueChk == True):
            return True
    elif day == 2:
        if (int(checkUser.wedFromH <= hour)) and (int(checkUser.wedFromM <= minute)) and (int(checkUser.wedToH >= hour)) and (int(checkUser.wedToM >= minute)) and (checkUser.wedChk == True):
            return True
    elif day == 3:
        if (int(checkUser.thuFromH <= hour)) and (int(checkUser.thuFromM <= minute)) and (int(checkUser.thuToH >= hour)) and (int(checkUser.thuToM >= minute)) and (checkUser.thuChk == True):
            return True
    elif day == 4:
        if (int(checkUser.friFromH <= hour)) and (int(checkUser.friFromM <= minute)) and (int(checkUser.friToH >= hour)) and (int(checkUser.friToM >= minute)) and (checkUser.friChk == True):
            return True
    elif day == 5:
        if (int(checkUser.satFromH <= hour)) and (int(checkUser.satFromM <= minute)) and (int(checkUser.satToH >= hour)) and (int(checkUser.satToM >= minute)) and (checkUser.satChk == True):
            return True
    elif day == 6:
        if (int(checkUser.sunFromH <= hour)) and (int(checkUser.sunFromM <= minute)) and (int(checkUser.sunToH >= hour)) and (int(checkUser.sunToM >= minute)) and (checkUser.sunChk == True):
            return True
    else:
        return False


def defaultHours(user_id):
    currUser = UsersData.query.filter_by(id=user_id).first()
    currUser.monChk = True
    currUser.monFromH = "00"
    currUser.monFromM = "00"
    currUser.monToH = "23"
    currUser.monToM = "59"
    currUser.tueChk = True
    currUser.tueFromH = "00"
    currUser.tueFromM = "00"
    currUser.tueToH = "23"
    currUser.tueToM = "59"
    currUser.wedChk = True
    currUser.wedFromH = "00"
    currUser.wedFromM = "00"
    currUser.wedToH = "23"
    currUser.wedToM = "59"
    currUser.thuChk = True
    currUser.thuFromH = "00"
    currUser.thuFromM = "00"
    currUser.thuToH = "23"
    currUser.thuToM = "59"
    currUser.friChk = True
    currUser.friFromH = "00"
    currUser.friFromM = "00"
    currUser.friToH = "23"
    currUser.friToM = "59"
    currUser.satChk = True
    currUser.satFromH = "00"
    currUser.satFromM = "00"
    currUser.satToH = "23"
    currUser.satToM = "59"
    currUser.sunChk = True
    currUser.sunFromH = "00"
    currUser.sunFromM = "00"
    currUser.sunToH = "23"
    currUser.sunToM = "59"
    db.session.commit()


@app.route('/')
def index():
    return render_template('index.html', title='Home')


@app.route('/login', methods=['POST', 'GET'])
def login():
    user = Users.query.all()
    if not user:
        firstUser = Users(
            userLogin="Admin",
            userPass=bcrypt.generate_password_hash("Admin"),
            firstName="Administrator",
            lastName="Admin"
        )
        db.session.add(firstUser)
        db.session.commit()
        return redirect(url_for('login'))
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
                temp = UsersData.query.filter_by(userTag=registerFormUsers.userTag.data).first()
                defaultHours(temp.id)
                flash('Użytkownik został dodany poprawnie', 'success')
                return redirect(url_for('usersTable'))
            elif registerFormUsers.userTag.data=="":
                newUserPlate = UsersData(
                    firstName=registerFormUsers.firstName.data.capitalize(),
                    lastName=registerFormUsers.lastName.data.capitalize(),
                    userPlate=registerFormUsers.userPlate.data.upper(),
                )
                db.session.add(newUserPlate)
                db.session.commit()
                temp = UsersData.query.filter_by(userPlate=registerFormUsers.userPlate.data.upper()).first()
                print(temp)
                defaultHours(temp.id)
                flash('Użytkownik został dodany poprawnie', 'success')
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
                temp = UsersData.query.filter_by(userTag=registerFormUsers.userTag.data).first()
                defaultHours(temp.id)
                flash('Użytkownik został dodany poprawnie', 'success')
                return redirect(url_for('usersTable'))

        except Exception:
            db.session.rollback()
            registerFormUsers.userTag.data = ""
            registerFormUsers.userPlate.data = ""
            flash('Rejestracja lub Tag już istnieje w bazie. Podaj dane ponownie.', 'danger')

    return render_template('registerUsers.html', title='Dodawanie tablic', registerFormUsers=registerFormUsers)

@app.route('/register', methods=['POST', 'GET'])
@login_required
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
            userEdit=UsersData.query.filter_by(id=targetId).first()
            userEdit.firstName = registerFormUsersEdit.firstName.data.capitalize()
            userEdit.lastName = registerFormUsersEdit.lastName.data.capitalize()

            if (registerFormUsersEdit.userTag.data.capitalize() == "Brak" or registerFormUsersEdit.userTag.data == "") and (registerFormUsersEdit.userPlate.data.capitalize() == "Brak" or registerFormUsersEdit.userPlate.data == ""):
                flash ('Podaj conajmniej jeden sposób autoryzacji', 'danger')
            elif registerFormUsersEdit.userTag.data.capitalize() == "Brak" or registerFormUsersEdit.userTag.data == "":
                userEdit.userTag = None
                userEdit.userPlate = registerFormUsersEdit.userPlate.data.upper()
                db.session.commit()
                flash('Wpis został edytowany', 'success')
                return redirect(url_for('usersTable'))
            elif registerFormUsersEdit.userPlate.data.capitalize() == "Brak" or registerFormUsersEdit.userPlate.data == "":
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
            userDel=UsersData.query.filter_by(id=targetIdDel).first()
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
            adminEdit=Users.query.filter_by(id=targetId).first()

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
            adminDel=Users.query.filter_by(id=targetIdDel).first()
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

    return render_template('adminTableOld.html', title='Administratorzy', databaseAdmin=databaseAdmin, registerFormAdminEdit=registerFormAdminEdit, registerFormAdminDel=registerFormAdminDel)


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

@app.route('/setTime/id/<int:user_id>', methods=['POST', 'GET'])
@login_required
def setTime(user_id):
    currentUser = UsersData.query.filter_by(id=user_id).first()
    hoursForm=hours()
    if hoursForm.validate_on_submit():
        try:
            #poniedziałek
            currentUser.monFromH = hoursForm.monFromH.data
            currentUser.monFromM = hoursForm.monFromM.data
            currentUser.monToH = hoursForm.monToH.data
            currentUser.monToM = hoursForm.monToM.data
            #wtorek
            currentUser.tueFromH = hoursForm.tueFromH.data
            currentUser.tueFromM = hoursForm.tueFromM.data
            currentUser.tueToH = hoursForm.tueToH.data
            currentUser.tueToM = hoursForm.tueToM.data
            #środa
            currentUser.wedFromH = hoursForm.wedFromH.data
            currentUser.wedFromM = hoursForm.wedFromM.data
            currentUser.wedToH = hoursForm.wedToH.data
            currentUser.wedToM = hoursForm.wedToM.data
            #czwartek
            currentUser.thuFromH = hoursForm.thuFromH.data
            currentUser.thuFromM = hoursForm.thuFromM.data
            currentUser.thuToH = hoursForm.thuToH.data
            currentUser.thuToM = hoursForm.thuToM.data
            #piątek
            currentUser.friFromH = hoursForm.friFromH.data
            currentUser.friFromM = hoursForm.friFromM.data
            currentUser.friToH = hoursForm.friToH.data
            currentUser.friToM = hoursForm.friToM.data
            #sobota
            currentUser.satFromH = hoursForm.satFromH.data
            currentUser.satFromM = hoursForm.satFromM.data
            currentUser.satToH = hoursForm.satToH.data
            currentUser.satToM = hoursForm.satToM.data
            #niedziela
            currentUser.sunFromH = hoursForm.sunFromH.data
            currentUser.sunFromM = hoursForm.sunFromM.data
            currentUser.sunToH = hoursForm.sunToH.data
            currentUser.sunToM = hoursForm.sunToM.data
            #przyciski
            currentUser.monChk = hoursForm.monChk.data
            currentUser.tueChk = hoursForm.tueChk.data
            currentUser.wedChk = hoursForm.wedChk.data
            currentUser.thuChk = hoursForm.thuChk.data
            currentUser.friChk = hoursForm.friChk.data
            currentUser.satChk = hoursForm.satChk.data
            currentUser.sunChk = hoursForm.sunChk.data

            db.session.commit()
            return redirect(url_for('usersTable'))
        except Exception:
            flash('Błąd przy zapisywaniu godzin dostępu.', 'danger')
            pass
    return render_template('setTime.html', title='Godziny dostępu', currentUser=currentUser, hoursForm=hoursForm)


#camera view
camera = cv2.VideoCapture(0)
def gen_frames():  # generate frame by frame from camera
    while True:
        success, frame = camera.read()
        if success:
            try:
                ret, buffer = cv2.imencode('.jpg', cv2.flip(frame, 1))
                frame = buffer.tobytes()
                yield (b'--frame\r\n'
                    b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
            except Exception:
                pass
        else:
            pass

@app.route('/videoFeed')
@login_required
def videoFeed():
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/cameraView')
@login_required
def cameraView():
    return render_template('cameraView.html')





if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=80, debug=True)




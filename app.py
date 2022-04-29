from flask import Flask, render_template, redirect, request, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_pymongo import PyMongo
from flask_login import login_user, login_required, logout_user, current_user
from flask_login import LoginManager
from bson.objectid import ObjectId
from flask_login import UserMixin

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/amazon"
mongo = PyMongo(app)
app.config['SECRET_KEY'] = 'jajajajajaja'

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_json):
        self.user_json = user_json
    def get_id(self):
        object_id = self.user_json.get('_id')
        return str(object_id)

'''@login_manager.user_loader
def load_user(user_id):
    return  mongo.db.users.find_one({'_id': ObjectId(user_id)})'''

@login_manager.user_loader
def load_user(user_id):
    users = mongo.db.users
    user_json = users.find_one({'_id': ObjectId(user_id)})
    return User(user_json)

@app.route('/')
@login_required
def home():
    return render_template("menu.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        users = mongo.db.users.find()
        Usuario = False
        Contrasena = False
        User = {}
        for user in users:
            if user['email'] == email and check_password_hash(user['password'], password):
                Usuario = True
                Contrasena = True
                User = mongo.db.users.find({'password': user['password']})
                break
            else:
                Usuario = False
                Contrasena = False
        if Usuario == True:
            if Contrasena == True:
                flash("Usuario Logueado Correctamente", category='success')
                login_user(User, remember=True)
                return redirect(url_for('home'))
            else:
                flash("Contraseña Incorrecta. Intentalo nuevamente", category='error')
        else:
            flash("Gmail Incorrecto. Intentalo nuevamente", category='error')
    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        #All the values that we give in a form.
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        s_password = request.form.get('s_password')
        users = mongo.db.users.find()
        for user in users:
            hashing = check_password_hash(user['password'], password)
            if user['email'] == email and hashing != True:
                flash("El gmail ya se encuentra registrado", category='error')
                break
            elif user['email'] != email and hashing == True:
                flash("Ya existe esa contraseña", category='error')
                break
            elif user['email'] == email and hashing == True:
                flash("Algunos datos ya existen", category='error')
                break
        if len(email) < 15:
            flash("El gmail debe ser mayor de 4 caracteres", category='error')
        elif len(username) < 2:
            flash("El nombre debe ser mas grande que 2 caracteres", category='error')
        elif password != s_password:
            flash("Revisa la confirmación de tu contraseña", category='error')
        elif len(password) < 7:
            flash("La contraseña debe ser mayor que 7 caracteres", category='error')
        else:
            #Addition of the values to DB
            hash_password = generate_password_hash(password)
            hash_s_password = generate_password_hash(s_password)
            id = mongo.db.users.insert_one(
            {'username': username, 'email': email, 'password': hash_password, 's_password': hash_s_password}
            )
            response = {
                'id': str(id),
                'username': username,
                'email': email,
                'password': hash_password,
                's_password': hash_s_password
            }
            flash("Cuenta Creada con Exito!!", category = 'success')
            return redirect(url_for('home'))

    return render_template("register.html")

'''@app.route('/register', methods=['GET','POST'])
def register():
    global error, passw, gmail, access
    message = None
    #Variables obtenidas del HTML (menu.html)
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    s_password = request.form.get("s_password")
    #Verificación del email unico y la confirmación de la contraseña
    if request.method == "POST":
        users = mongo.db.users.find()
        for user in users:
            hashing = check_password_hash(user['password'], password)
            if (user['email'] == email or hashing == True) and password == s_password:
                error = True
                gmail = True
                break
            elif (user['email'] != email and hashing != True) and password != s_password:
                error = True
                passw = True
                break
            elif (user['email'] == email or hashing == True) and password != s_password:
                error = True
                passw = True
                gmail = True
                break

        if username and email and password and s_password:
            hash_password = generate_password_hash(password)
            hash_s_password = generate_password_hash(s_password)
            id = mongo.db.users.insert_one(
                {'username': username, 'email': email, 'password': hash_password, 's_password': hash_s_password}
            )
            response = {
                'id': str(id),
                'username': username,
                'email': email,
                'password': hash_password,
                's_password': hash_s_password
            }
            session["user"] = user
            return redirect(url_for("index"))
        else:
            return not_found()
    users = mongo.db.users.find()
    for user in users:
        hashing = check_password_hash(user['password'], password)
        if (user['email'] == email or hashing == True) and password == s_password:
            error = True
            gmail = True
            break
        elif (user['email'] != email and hashing != True) and password != s_password:
            error = True
            passw = True
            break
        elif (user['email'] == email or hashing == True) and password != s_password:
            error = True
            passw = True
            gmail = True
            break
    if error == True and passw == True and gmail == False:
        error = False
        pasw = False
        message = 'Revisar la confirmación de la contraseña'
    elif error == True and gmail == True and passw == False:
        error = False
        gmail = False
        message = 'Ya existe un Usuario con ese gmail'
    elif error == True and gmail == True and passw == True:
        error = False
        gmail = False
        pasw = False
        message = 'Volver a confirmar la contraseña o cambiar de gmail'
    return render_template("register.html", message=message)

@app.route('/users', methods=['GET'])
def users():
    users = mongo.db.users.find()
    response = json_util.dumps(users)
    return Response(response, mimetype='application/json')

@app.route('/user')
def index():
    if "user" in session:
        user = session["user"]
        return render_template("menu.html")
    else:
        return redirect(url_for("login"))

@app.route('/users/<id>', methods=['GET'])
def menu(id):
    user = mongo.db.users.find_one({'_id': ObjectId(id)})
    response = json_util.dumps(user)
    return Response(response, mimetype='application/json')

@app.errorhandler(404)
def not_found(error = None):
    response = jsonify({
        'error': 'No encontrado',
        'message': 'Resource Not Found: '+request.url,
        'status': 404
    })
    response.status_code = 404
    return response

@app.errorhandler(404)
def not_equal(error = None):
    response = jsonify({
        'error': 'Not Password Confirmated',
        'message': 'Resource Not Found: '+request.url,
        'status': 404
    })
    response.status_code = 404
    return response

@app.errorhandler(404)
def not_allowed(error = None):
    response = jsonify({
        'error': 'This user already exists'
    })
    response.status_code = 404
    return response

'''
if __name__ == '__main__':
    app.run(debug = True)

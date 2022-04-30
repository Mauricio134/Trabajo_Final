from flask import Flask, render_template, redirect, request, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import timedelta

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/amazon"
mongo = PyMongo(app)
app.config['SECRET_KEY'] = 'hello'

app.permanent_session_lifetime = timedelta(hours = 3)


@app.route('/', defaults={'id': ""})
@app.route('/<id>')
def home(id):
    if "user" in session:
        user = session["user"]
        return render_template("menu.html")
    else:
        return redirect(url_for("login"))

@app.route('/login', methods=['GET', 'POST'])
def login():
    id_ = ""
    if request.method == 'POST':
        session.permanent = True
        email = request.form.get('email')
        password = request.form.get('password')
        users = mongo.db.users.find()
        Usuario = False
        Contrasena = False
        session["user"] = email
        for user in users:
            if user['email'] == email and check_password_hash(user['password'], password):
                Usuario = True
                Contrasena = True
                id_ = str(user['_id'])
                session["user"] = list(user)
                break
            else:
                Usuario = False
                Contrasena = False
        if Usuario == True:
            if Contrasena == True:
                flash("Usuario Logueado Correctamente", category='success')
                return redirect(url_for("home", id=id_ ))
            else:
                flash("Contraseña Incorrecta. Intentalo nuevamente", category='error')
        else:
            flash("Gmail Incorrecto. Intentalo nuevamente", category='error')
    else:
        if "user" in session:
            print("a=" , session["user"])
            return redirect(url_for("home", id=id_ ))
        return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop("user", None)
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
    else:
        if "user" in session:
            return redirect(url_for('home'))
        return render_template("register.html")

if __name__ == '__main__':
    app.run(debug = True)

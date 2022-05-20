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

@app.route('/')
def home():
    if "user" in session:
        user = session["user"]
        productos = mongo.db.products.find()
        users = mongo.db.users.find()
        return render_template("menu.html", productos = productos, users = users)
    else:
        return redirect(url_for("login"))

@app.route('/login', methods=['GET', 'POST'])
def login():
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
        if Usuario == True and Contrasena == True:
            flash("Usuario Logueado Correctamente", category='success')
            return redirect(url_for('home'))
        else:
            flash("Datos Incorrectos. Intentalo nuevamente", category='error')
        return render_template("login.html")
    else:
        if "user" in session:
            return redirect(url_for("home"))
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
            flash("Cuenta Creada con Exito!!", category = 'success')
            return redirect(url_for('home'))
        return render_template("register.html")
    else:
        if "user" in session:
            return redirect(url_for('home'))
        return render_template("register.html")

@app.route('/addbrand', methods=['GET', 'POST'])
def addbrand():
    if request.method == 'POST':
        contra = request.form.get('contra')
        productname = request.form.get('productname')
        prize = request.form.get('prize')
        discount = request.form.get('discount')
        description = request.form.get('description')
        image = request.form.get('image')
        users = mongo.db.users.find()
        user_id = None
        for user in users:
            hashing = check_password_hash(user['password'], contra)
            if hashing:
                user_id = user['_id']
        if user_id == None:
            flash("No eres el usuario", category='error')
            return redirect(url_for('addbrand'))
        else:
            id = mongo.db.products.insert_one({
                'name': productname, 
                'prize': prize, 
                'discount': discount, 
                'description': description,
                'file': image,
                'user_id': user_id
            })
        return redirect(url_for('home'))
    return render_template('addbrand.html')

@app.route('/delete/<id>')
def delete(id):
    productos = mongo.db.products.find_one_and_delete({"_id": ObjectId(id)})
    return redirect(url_for('home'))
if __name__ == '__main__':
    app.run(debug = True)
from flask import Flask, request, jsonify, Response
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson import json_util
from bson.objectid import ObjectId

app = Flask(__name__)

app.config["MONGO_URI"] = "mongodb://localhost:27017/amazon"
mongo = PyMongo(app)




'''@app.route('/register', methods=['POST'])
def register():

    username = request.json['username']
    email = request.json['email']
    password = request.json['password']
    s_password = request.json['s_password']

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
        if password == s_password:
            return response
        else:
            return not_equal()
    else:
        return not_found()

    return {'message': 'received'}

@app.route('/login', methods=['GET', 'POST'])
def login():
    email = request.json['email']
    user = mongo.db.users.find_one({
        'email': email
    })



    response = json_util.dumps(user)
    return Response(response, mimetype='application/json')

@app.route('/users', methods=['GET'])
def users():
    users = mongo.db.users.find()
    response = json_util.dumps(users)
    return Response(response, mimetype='application/json')

@app.route('/users/<id>', methods=['GET'])
def user(id):
    user = mongo.db.users.find_one({'_id': ObjectId(id)})
    response = json_util.dumps(user)
    return Response(response, mimetype='application/json')

@app.errorhandler(404)
def not_found(error = None):
    response = jsonify({
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
    return response'''


if __name__ == '__main__':
    app.run(debug=True)

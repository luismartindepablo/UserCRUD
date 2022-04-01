from flask import Flask
from flask import request
from flask import jsonify

from flask_sqlalchemy import SQLAlchemy

from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required
from flask_jwt_extended import create_access_token

import uuid
from werkzeug.security import generate_password_hash, check_password_hash

from datetime import timedelta


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.sqlite'
app.config["JWT_SECRET_KEY"] = "super-secret"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=2)

db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))


@app.route('/logup', methods=['POST'])
def create_user():
    
    data = request.form

    if not data['username'] or not data['password']:
        return jsonify(category="error", msg="Missing information!"), 400 

    user = User.query.filter_by(username=data['username']).one_or_none()
    if user:
         return jsonify(category="error", msg="User already exist!"), 400

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify(category="succes"), 200


@app.route('/login', methods=['GET'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify(category="error", msg="Could not verify!"), 401

    user = User.query.filter_by(username=auth.username).one_or_none()

    if not user:
        return jsonify(category="error", msg="User does not exist!"), 404

    if not check_password_hash(user.password, auth.password):
        return jsonify(category="error", msg="Could not verify!"), 401

    access_token = create_access_token(identity=user.public_id)
    
    return jsonify(category="succes", access_token=access_token), 200


@app.route('/unprotected')
def unprotected():
    return jsonify(category="succes"), 200


@app.route('/protected')
@jwt_required()
def protected():
    return jsonify(category="succes"), 200

if __name__ == '__main__':
    app.run(debug=True)
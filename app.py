from flask import Flask
from flask import request
from flask import jsonify

from flask_sqlalchemy import SQLAlchemy

from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required
from flask_jwt_extended import verify_jwt_in_request
from flask_jwt_extended import get_jwt, get_jwt_identity
from flask_jwt_extended import create_access_token,  create_refresh_token

import uuid
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash

from functools import wraps
from datetime import timedelta


app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///User.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50))
    usermail = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(50))
    is_admin = db.Column(db.Boolean)


def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims["is_admin"]:
                return fn(*args, **kwargs)
            else:
                return jsonify(category="error", msg="Admins only!"), 403

        return decorator

    return wrapper


@app.route("/logup", methods=["POST"])
def create_user():
    
    data = request.form

    if not data["username"] or not data["usermail"] or not data["password"]:
        return jsonify(category="error", msg="Missing information!"), 400 

    user = User.query.filter_by(usermail=data["usermail"]).one_or_none()
    if user:
         return jsonify(category="error", msg="User already exist!"), 400

    hashed_password = generate_password_hash(data["password"], method="sha256")
    new_user = User(public_id=str(uuid.uuid4()), username=data["username"], usermail=data["usermail"], password=hashed_password, is_admin=False)

    db.session.add(new_user)
    db.session.commit()

    return jsonify(category="succes"), 200


@app.route("/login", methods=["POST"])
def login():

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify(category="error", msg="Could not verify!"), 401

    user = User.query.filter_by(usermail=auth.username).one_or_none()

    if not user:
        return jsonify(category="error", msg="User does not exist!"), 404

    if not check_password_hash(user.password, auth.password):
        return jsonify(category="error", msg="Invalid password!"), 401

    access_token = create_access_token(identity=user.public_id, additional_claims={"is_admin": user.is_admin})
    refresh_token = create_refresh_token(identity=user.public_id, additional_claims={"is_admin": user.is_admin})
    
    return jsonify(category="succes", access_token=access_token, refresh_token=refresh_token), 200


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():

    identity = get_jwt_identity()
    claims = get_jwt()

    access_token = create_access_token(identity=identity, additional_claims ={"is_admin": claims["is_admin"]})

    return jsonify(category="succes", access_token=access_token), 200


@app.route("/unprotected")
def unprotected():
    return jsonify(category="succes"), 200

@app.route("/protected")
@jwt_required()
def protected():
    return jsonify(category="succes"), 200

@app.route("/admin_protected")
@admin_required()
def admin_protected():
    return jsonify(category="succes"), 200


if __name__ == "__main__":
    db.create_all()
    admin_user = User(public_id=str(uuid.uuid4()), username="admin", usermail="admin@admin.com", password=generate_password_hash("admin", method="sha256"), is_admin=True)
    db.session.add(admin_user)
    db.session.commit()

    app.run(debug=True)
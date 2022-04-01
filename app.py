from flask import Flask
from flask import request
from flask import jsonify

from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required
from flask_jwt_extended import create_access_token

from datetime import timedelta

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=2)

jwt = JWTManager(app)

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify(category="error", msg="Could not verify!"), 401

    if auth and auth.password != 'password':
        return jsonify(category="error", msg="Could not verify!"), 401

    access_token = create_access_token(identity=auth.username)

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
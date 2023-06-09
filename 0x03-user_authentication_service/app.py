#!/usr/bin/env python3
"""
API Route Module
"""

from flask import Flask, abort, jsonify, redirect, request
from auth import Auth

AUTH = Auth()
app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def index() -> str:
    """returns a JSON payload"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """registers new users -> POST /users"""
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        new_user = AUTH.register_user(email, password)
        if new_user is not None:
            return jsonify({
                "email": f"{email}",
                "message": "user created"
            }), 200
    except Exception:
        return jsonify({
            "message": "email already registered"
        }), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """creates a new session for the user, store it in the
    session ID as a cookie with key "session_id" and returns JSON payload"""
    email = request.form.get('email')
    password = request.form.get('password')
    valid_login = AUTH.valid_login(email, password)

    if not valid_login:
        abort(401)
    session_id = AUTH.create_session(email)
    response = jsonify({"email": f"{email}", "message": "logged in"})
    response.set_cookie('session_id', session_id)
    return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """finds the user with requested session ID, destroys the
    session and redirect the user to GET /"""
    cookie = request.cookies.get("session_id", None)
    user = AUTH.get_user_from_session_id(cookie)
    if cookie is None or user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """gets user by using the session_id"""
    cookie = request.cookies.get("session_id", None)
    if cookie is None:
        abort(403)
    user = AUTH.get_user_from_session_id(cookie)
    if user:
        return jsonify({"email": user.email}), 200
    else:
        abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """checks if provided email is registered - if not respond
    with 403. Otherwise generate a token and respond with 200 and JSON payload
    with email and reset_token"""
    email = request.form.get('email')
    is_registered = AUTH.create_session(email)

    if is_registered:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token})
    else:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password():
    """updates password
    """
    email = request.form.get('email')
    token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    if email is None or token is None or new_password is None:
        abort(403)
    try:
        AUTH.update_password(token, new_password)
        return jsonify({"email": email, "message": "Password updated"})
    except Exception as e:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")

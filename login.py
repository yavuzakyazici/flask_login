from flask import Blueprint, request, make_response
from flask_bcrypt import check_password_hash, generate_password_hash
import jwt
from functools import wraps
from datetime import datetime, timedelta, timezone
from models import User, db
from app import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_MINUTES,
    JWT_SECRET_KEY,
    ALGORITHM,
    )

# Create a Blueprint named 'login'
login_bp = Blueprint("login", __name__)


def get_user_by_email( email:str ):
    user = db.session.query(User).filter(User.Email == email ).first()
    if user is not None:
        return user
    else:
        return False


# you can protect your app routes with @token_required decorator
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        # necessary if token is sent with bearer in the beginning
        if token.startswith("bearer "):
            token = token[7:]
        if not token:
            return make_response({"message": "Access token required!"}, 401)
        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
            current_user = User.query.filter_by(UserId=data["id"]).first()
            for scope in data["scopes"]:
                if scope=="user" not in data["scopes"]:
                    return make_response({"message": "Unable to verify token!"}, 401)
        except Exception as e:
            print(e)
            return make_response({"message": "Unable to verify token!"}, 401)
        kwargs['current_user'] = current_user
        return f(*args, **kwargs)
    return decorated_function


@login_bp.route("/token", methods=["POST"])
def login():
    auth = request.form
    if not auth or not auth.get("username") or not auth.get("password"):
        return make_response(
            {"message":"Username or Password can not be blank!"},
            400
        )
    user = get_user_by_email(auth.get("username"))
    if not user:
        return make_response(
            {"message":"User not found!"},
            404
        )
    if check_password_hash(user.UserPassword, auth.get("password")):
        access_token = jwt.encode({
            "id": user.UserId,
            "exp": datetime.utcnow() + timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES)),
            "scopes": ["user"]
        },
        JWT_SECRET_KEY,
        algorithm=ALGORITHM
        )
        refresh_token = jwt.encode({
            "id": user.UserId,
            "exp": datetime.utcnow() + timedelta(minutes=int(REFRESH_TOKEN_EXPIRE_MINUTES)),
            "scopes": ["user"]
        },
        JWT_SECRET_KEY,
        algorithm=ALGORITHM
        )
    else:
        return make_response(
            {"message":"Could not verify credentials!"},
            401
        )

    return make_response(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        },
        200
    )


@login_bp.route("/users/me/", methods=["GET"])
@token_required
def read_user_me(current_user):
    user = db.session.query(User).filter(User.UserId == current_user.UserId).first()
    return user.serialize


""" Our insert user method to be able to check login later"""
@login_bp.route("/register", methods=["POST"])
def register_user():
    email = request.form.get("email")
    pw = request.form.get("password")
    fullname = request.form.get("fullname")

    if not email:
        return make_response({"message":"email cannot be blank!"}, 400)
    if not pw:
        return make_response({"message":"password cannot be blank!"}, 400)
    if not fullname:
        return make_response({"message":"fullname cannot be blank!"}, 400)


    existing_user = db.session.query(User).filter(User.Email == email).first()

    if existing_user is not None:
        #if there is not user with that email, we can insert the user
        return make_response({"message":f"user with email {user_to_insert.Email} exists in databes!"}, 400)
    else:
        user_to_insert:User = User(
            FullName = fullname,
            Email = email,
            UserPassword = generate_password_hash(pw),
        )
        db.session.add(user_to_insert)
        db.session.commit()
        return make_response({"message":f"user {user_to_insert.Email} was created successfully"}, 201)


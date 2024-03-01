First you need to open your terminal and create project folder.
```py
mkdir flask_login
```

then cd to the directory.
```
cd flask_login
````
then create your virtual environment.
```
python3 -m venv env
```

then if you are using vs code start it by typing ```code .```into command line.

I used factory pattern since circular imports can be problematic as the app grows.
A better approach would be creating another file called factory and putting the create_app() and configurations inside that folder.
You can use the same approach with any kind of sql database by changing SQLALCHEMY_DATABASE_URI.
We have a simple db, app and model.

I have added requirements text but you can just install flask, flask_sqlalchemy, flask_bcrypt by using at terminal inside project folder after you created your virtual anvironment.
```py
pip3 install flask flask_sqlalchemy flask_bcrypt
```
or you could also type...
```py
pip install -r requirements. txt
```
in to terminal


Here is our app.py file
```py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

"""
These variables below needs to be changed and stored in .env file
and .env should be in .gitignore list so they are not checked into git
Then the variables could be loaded into app with the code below:

import os
from dotenv import load_dotenv
load_dotenv()

To create your own JWT_SECRET_KEY you can open up terminal and type ..
openssl rand -hex
and you will get key similar to
"beed354b6483c2673f026c8e0089366c9634b5608d1d9dc5a2cb0f6157bd2fcc"
Then you copoy/paste the result inside .env file like
JWT_SECRET_KEY = "resulting_key_from_terminal_goes_here"
e.g.

JWT_SECRET_KEY = "beed354b6483c2673f026c8e0089366c9634b5608d1d9dc5a2cb0f6157bd2fcc"

"""

# a short 60 min is enough for access token
ACCESS_TOKEN_EXPIRE_MINUTES = "60"
# 30 days (60 * 24 * 30)
REFRESH_TOKEN_EXPIRE_MINUTES = "43200"
JWT_SECRET_KEY = "my_super_secret_key"
ALGORITHM = "HS256"

my_db_name = "flask_login_example"


db = SQLAlchemy()

def create_app():
    app = Flask(__name__, static_folder="../assets", template_folder='../templates')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config["SQLALCHEMY_DATABASE_URI"] =  'sqlite:///' + my_db_name
    app.config["JWT_ALGORITHM"] = ALGORITHM
    app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
    db.init_app(app)

    return app


app = create_app()


@app.route("/")
def app_message():
    return {"message":"Please login to use API"}

from login import login_bp
app.register_blueprint(login_bp, url_prefix="/user/login")


if __name__ == "__main__":
    app.run(debug=True)

from models import User

""" Creating Database with App Context"""
def create_db():
    with app.app_context():
        db.create_all()

create_db()


```

Here is our models.py with user model.

```py
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String
from app import db

class User(db.Model):
    __tablename__ = "users"

    UserId: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    FullName:Mapped[str] = mapped_column(String(40), nullable=True)
    Email:Mapped[str] = mapped_column(String(50), unique=True, index=False)
    UserPassword:Mapped[str] = mapped_column(String(255))

    def __str__(self):
        return self.Email
    
    @property
    def serialize(self):
        return {
            "UserId": self.UserId,
            "FullName": self.FullName,
            "Email": self.Email,
        }

```
Here is our login.py
```py
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
            """included scopes in case you may need to use it for bigger apps, if not skip/exclude the scope part up to exceptions"""
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
```

Now you can check it with postman api tool
https://www.postman.com/

now... if you run the app on port 8000 with this command
```
flask run --debug --port 8000
```
the example addresses below work.
The default port is 5000 for flask.

if you just type 
```
flask run --debug
```
change the port adress to 5000

Here is my screenshots with this example project


<img width="1042" alt="1" src="https://github.com/yavuzakyazici/flask_login/assets/148442912/b1294b4d-8878-43d2-b28f-8d512a6385f8">

<img width="1040" alt="2" src="https://github.com/yavuzakyazici/flask_login/assets/148442912/98366b0e-bcc3-41bb-bcf7-f7eb3fd14153">

<img width="1083" alt="3" src="https://github.com/yavuzakyazici/flask_login/assets/148442912/cd86f8d3-7b6f-4660-a960-c3dd154cc968">

Good luck to all :)

The reason why I did not use the built in flask manager was, this may be simpler for smaller projects with less learning curve.



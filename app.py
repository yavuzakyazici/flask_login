from flask import Flask
from flask_sqlalchemy import SQLAlchemy

"""
These variables below needs to change and stored in .env file
and .env should be in .gitignore list so they are not checked into git
Then they could be loaded with the code below:
import os
from dotenv import load_dotenv
load_dotenv()

To create your own JWT_SECRET_KEY you can open up terminal and type ..
openssl rand -hex 32 on 01 dec 2023
Then you copoy/paste the result inside .env file like
JWT_SECRET_KEY = "resulting_key_from_terminal_goes_here"

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


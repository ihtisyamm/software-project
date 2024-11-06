from flask import Flask
from flask_login import LoginManager

app = Flask(__name__)
app.config.from_object('config')
#app.config['UPLOAD_FOLDER'] = 'static/files'

from app import views

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
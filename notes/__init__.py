from flask import Flask
from flask_login import LoginManager
from config import DevelopmentConfig


app = Flask(__name__)
app.config.from_object(DevelopmentConfig)

from notes import routes

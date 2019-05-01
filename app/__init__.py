from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from redis import Redis
import simplify
import rq
from flask_mail import Mail


app = Flask(__name__)
app.config.from_object(Config)
mail = Mail(app)
db = SQLAlchemy(app)
migrate =Migrate(app,db)

login = LoginManager(app)
login.login_view = 'login'

app.redis = Redis.from_url(app.config['REDIS_URL'])
app.task_queue = rq.Queue('ewallet-tasks', connection=app.redis)

simplify.public_key = app.config['SIMPLIFY_PUBLIC_KEY']
simplify.private_key = app.config['SIMPLIFY_PRIVATE_KEY']

queue = rq.Queue(connection=Redis.from_url('redis://'))
queue = rq.Queue('tasks', connection=Redis.from_url('redis://'))


from app import routes, models

if __name__ == "__main__":
	app.run()
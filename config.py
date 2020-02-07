import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
	PUBLIC_KEY = "PUBLIC_KEY"
	PRIVATE_KEY = "PRIVATE_KEY"
	SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
	SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
	'sqlite:///' + os.path.join(basedir, 'app.db')
	SQLALCHEMY_TRACK_MODIFICATIONS = False

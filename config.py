import os
import pymysql
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
	PUBLIC_KEY = "sbpb_Njc3ZDkyMmYtYTE0OS00MTRjLWE5YmUtZjQ3MTI5ZWUzNmE3"
	PRIVATE_KEY = "3KzZq8dCCUhQMh1dTCU6jPrwdG0O4wwwizAP82LcfpN5YFFQL0ODSXAOkNtXTToq"
	SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
	REDIS_URL = os.environ.get('REDIS_URL') or 'redis://'
	#SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \'sqlite:///' + os.path.join(basedir, 'app.db')

	SQLALCHEMY_DATABASE_URI = "mysql+pymysql://ezwallet:ezwallet@db-instance.c798x8idlrk0.us-east-1.rds.amazonaws.com/ezwallet-db" 

	SQLALCHEMY_TRACK_MODIFICATIONS = False

	#<<<<<<<<<<<<<< NEW CODE >>>>>>>>>>>>>>>>#
	SIMPLIFY_PUBLIC_KEY = os.environ.get('SIMPLIFY_PUBLIC_KEY') or "sbpb_Njc3ZDkyMmYtYTE0OS00MTRjLWE5YmUtZjQ3MTI5ZWUzNmE3"
	SIMPLIFY_PRIVATE_KEY = os.environ.get('SIMPLIFY_PRIVATE_KEY') or "3KzZq8dCCUhQMh1dTCU6jPrwdG0O4wwwizAP82LcfpN5YFFQL0ODSXAOkNtXTToq"

	ALPHAVANTAGE_API_KEY = os.environ.get('ALPHAVANTAGE_API_KEY') or "OYL0XNT0O85E76PM"

	MAIL_SERVER = 'smtp.gmail.com'
	MAIL_PORT = 465
	MAIL_USE_TLS = False
	MAIL_USE_SSL = True
	MAIL_USERNAME = 'EZwalletservices@gmail.com'
	MAIL_PASSWORD = 'CUS1166ezwallet'
	MAIL_DEFAULT_SENDER = 'EZwalletservices@gmail.com'

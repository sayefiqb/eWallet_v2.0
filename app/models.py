from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from app import db, login
from flask_login import UserMixin
import redis
import rq

class Customer(UserMixin, db.Model):
	__tablename__="customer" #NEW
	id = db.Column(db.Integer, primary_key=True) #NEW
	email = db.Column(db.String(120), index=True, unique=True) #NEW
	password_hash = db.Column(db.String(128))
	lname = db.Column(db.String(120))
	fname = db.Column(db.String(120))
	phone = db.Column(db.String(12))
	cards = db.relationship('Card',backref='cardholder',lazy='dynamic') #NEW
	payments = db.relationship('Payment', backref='paymentMaker',lazy='dynamic')
	
	def set_password(self,password):
		self.password_hash = generate_password_hash(password)

	def check_password(self,password):
		return check_password_hash(self.password_hash,password)

def __repr__(self):
	return '<Customer {}>'.format(self.body)

class Card(db.Model):
	__tablename__="card"
	addressState = db.Column(db.String(120))
	expMonth = db.Column(db.Integer)
	expYear = db.Column(db.Integer)
	addressCity = db.Column(db.String(40))
	addressZip = db.Column(db.Integer)
	cvv =db.Column(db.Integer)
	number = db.Column(db.String(16), primary_key=True)
	cardHolderRef = db.Column(db.Integer, db.ForeignKey('customer.id')) #NEW

class UtilityBill(db.Model):
	__tablename__="utilitybill"
	billId = db.Column(db.String(36), primary_key=True)
	accountNumber = db.Column(db.String(40))
 	accountHolder = db.Column(db.String(120))
 	billingAddress = db.Column(db.String(120))
 	usage = db.Column(db.String(20))
 	duePayment = db.Column(db.String(40))
 	complete = db.Column(db.Boolean, default=False)

 	def get_rq_job(self):
 		try:
 			rq_job = rq.job.Job.fetch(self.id, connection=current_app.redis)
 		except (redis.exceptions.RedisError, rq.exceptions.NoSuchJobError):
 			return None
 		return rq_job
	def get_progress(self):
		job = self.get_rq_job()
		return job.meta.get('progress', 0) if job is not None else 100

def __repr__(self):
	return '<Card {}>'.format(self.body)

@login.user_loader #NEW
def load_user(id): #NEW
	return Customer.query.get(int(id))

class Payment(db.Model):
	__tablename__="payment"
	id = db.Column(db.Integer, primary_key=True)
	company = db.Column(db.String(40))
	amount = db.Column(db.String(40))
	description =db.Column(db.String(32))
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
	paymentMakerRef = db.Column(db.Integer, db.ForeignKey('customer.id'))
	paymentCardRef =db.Column(db.String(20)) #May Cayse trouble

class Comment(db.Model):
	__tablename__="comment"
	name = db.Column(db.String(120))
	timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
	comment = db.Column(db.String(1000))
	commentID = db.Column(db.Integer, primary_key=True)

db.create_all()
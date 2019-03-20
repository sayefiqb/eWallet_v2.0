from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo
from app.models import User

class RegistrationForm(FlaskForm):
	# username = StringField('Email', validators=[DataRequired()])
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired()])
	retypePassword = PasswordField('Retype Password', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Register')

	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user is not None:
			raise ValidationError('Please use a different email address')


class LoginForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	remember_me = BooleanField('Remember Me')
	submit = SubmitField('Sign In')

class AddCustomerForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired()])
	number = StringField('Number', validators=[DataRequired()])
	addressState = StringField('State', validators=[DataRequired()])
	expMonth = StringField('Expiration Month', validators=[DataRequired()])
	expYear = StringField('Expiration Year', validators=[DataRequired()])
	addressCity = StringField('City', validators=[DataRequired()])
	addressZip = StringField('Zip Code', validators=[DataRequired()])
	cvv = StringField('CVV', validators=[DataRequired()])
	submit = SubmitField('Add Card')

class AddCardForm(FlaskForm):
	number = StringField('Number', validators=[DataRequired()])
	addressState = StringField('State', validators=[DataRequired()])
	expMonth = StringField('Expiration Month', validators=[DataRequired()])
	expYear = StringField('Expiration Year', validators=[DataRequired()])
	addressCity = StringField('City', validators=[DataRequired()])
	addressZip = StringField('Zip Code', validators=[DataRequired()])
	cvv = StringField('CVV', validators=[DataRequired()])
	submit = SubmitField('Add Card')

class PayBillForm(FlaskForm):
	amount = StringField("Amount", validators=[DataRequired()])
	description = StringField("Description", validators=[DataRequired()])
	submit = SubmitField('Pay')

# def validate_username(self, username):
# 	user = User.query.filter_by(username=username.data).first()
# 	if user is not None:
# 		raise ValidationError('Please use a different username')

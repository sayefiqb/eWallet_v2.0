from flask import render_template, flash, redirect, url_for, request 
from app.forms import RegistrationForm, LoginForm, AddCustomerForm, AddCardForm, PayBillForm 
from app import app, db
from flask_login import current_user, login_user, login_required, logout_user
from app.models import User, Card, UtilityBill
from celery import Celery #added a new Celery import statement
import simplify
import json
import requests
import time

simplify.public_key = "sbpb_Njc3ZDkyMmYtYTE0OS00MTRjLWE5YmUtZjQ3MTI5ZWUzNmE3"
simplify.private_key = "3KzZq8dCCUhQMh1dTCU6jPrwdG0O4wwwizAP82LcfpN5YFFQL0ODSXAOkNtXTToq"

@app.route('/')
@app.route('/index')
# @login_required
def index():
	return render_template('index.html')

@app.route('/login',methods=['GET','POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is None or not user.check_password(form.password.data):
			flash('Invalid username or password')
			return redirect(url_for('login'))
		login_user(user, remember= form.remember_me.data)
		next_page = request.args.get('next')
		if not next_page or url_parse(next_page).netloc != '':
			next_page = url_for('index')
	return redirect(url_for('index'))
	return render_template('login.html',title='Sign In', form=form)


@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('index'))


@app.route('/register', methods=['GET','POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(email = form.email.data)
		user.set_password(form.password.data)
		db.session.add(user)
		db.session.commit()
		flash('Congratulations, you are now registered!')
		return redirect(url_for('login'))
	return render_template('register.html', title='Register', form=form)

@app.route('/manageCard',methods=['GET','POST'])
def manageCard():
	return render_template('manageCard.html',title='Manage Card')

@app.route('/manageBill',methods=['GET','POST'])
def manageBill():
	return render_template('manageBill.html',title='Manage Bill')

@app.route('/selectBill', methods=['GET','POST'])
def selectBill():
	return render_template('selectBill.html', title='Select Bill')

@app.route('/selectUtility', methods=['GET','POST'])
def selectUtility():

	return render_template('selectUtility.html', title='Select Utility')

@app.route('/viewBills')
def viewBills():
	bills = UtilityBill.query.all()
	for bill in bills:
		bill.paid = True	
	return render_template('viewBills.html', title='View Bill', bills=bills)

@app.route('/viewRecentBills', methods=['GET','POST'])
def viewRecentBills():
	headers = {"Authorization": "Bearer 82aa45097ea54fbc89237acbd43f4979"}

	uid_response = requests.post("https://utilityapi.com/api/v2/forms" ,headers=headers)
	time.sleep(3)
	uid_json_data_response = json.loads(uid_response.text)
	uid = uid_json_data_response["uid"]

	referral_url = "https://utilityapi.com/api/v2/forms/"+uid+"/test-submit"
	referral_code_response = requests.post(referral_url, headers=headers, data='{"utility": "DEMO", "scenario": "residential"}')
	time.sleep(3)
	referral_code_json_data_response = json.loads(referral_code_response.text)
	referral_code = referral_code_json_data_response["referral"]

	meter_uid_url = "https://utilityapi.com/api/v2/authorizations?referrals="+referral_code+"&include=meters"
	meter_uid_response = requests.get(meter_uid_url, headers=headers)
	time.sleep(5)
	meter_uid_json_data_response = json.loads(meter_uid_response.text)
	meter_uid = meter_uid_json_data_response["authorizations"][0]["meters"]["meters"][0]["uid"]
	meter_uid = str(meter_uid)

		# # print(uid)
		# # print(referral_code)
		# print(meter_uid_json_data_response)
		# print(meter_uid)
	historical_data_url = "https://utilityapi.com/api/v2/meters/historical-collection"
		# uid = [meter_uid]
	data = {"meters": [meter_uid]}
	json_data = json.dumps(data)
	time.sleep(5)
	historical_data_response = requests.post(historical_data_url, headers = headers,  data = json_data)
	historical_data_json_response = json.loads(historical_data_response.text)
		# print(historical_data_json_response)

	success = historical_data_json_response["success"]
	if success is True:
		polling_url = "https://utilityapi.com/api/v2/meters/"+meter_uid
		time.sleep(3)
		polling_data_response = requests.get(polling_url, headers = headers)
		polling_data_json_response = json.loads(polling_data_response.text)
			# status = polling_data_json_response["status"]
			# bill_count = polling_data_json_response["bill_count"]
			# # count = 0
			# while status != "updated" and bill_count>0:
			# 	count = count + 1
			# 	print(count)
			# 	polling_data_response = requests.get(polling_url, headers = headers)
			#  	polling_data_json_response = json.loads(polling_data_response.text)
			# print(polling_data_json_response)
		bills_url = "https://utilityapi.com/api/v2/bills?meters="+meter_uid
		time.sleep(3)
		bills_response = requests.get(bills_url, headers=headers)
		bills_json_data_response = json.loads(bills_response.text)
		bills = bills_json_data_response["bills"][-1]["base"]

		mybills = []
		billing_account = bills["billing_account"]
		mybills.append(billing_account)
		billing_contact = bills["billing_contact"]
		mybills.append(billing_contact)
		billing_address = bills["billing_address"]
		mybills.append(billing_address)
		bill_total_kwh = bills["bill_total_kwh"]
		mybills.append(bill_total_kwh)
		bill_total_cost = bills["bill_total_cost"]
		mybills.append(bill_total_cost)
		bill = UtilityBill(accountNumber=billing_account,
		accountHolder=billing_contact,
		billingAddress=billing_address,
		usage=bill_total_kwh,
		duePayment=bill_total_cost)
		db.session.add(bill)
		db.session.commit()
		mybills = UtilityBill.query.all()
	return render_template('viewRecentBills.html', title='Due Bill', mybills=mybills)

@app.route('/viewCards',methods=['GET','POST'])
def viewCards():
	cards = Card.query.all()
	return render_template('viewCards.html',title='View Cards', cards=cards)

@app.route('/addCardForm',methods=['GET','POST'])
def cardform():
	form = AddCardForm()
	if form.validate_on_submit():
		card = Card(addressState=form.addressState.data,expMonth=form.expMonth.data, expYear=form.expYear.data,
			addressCity=form.addressCity.data,addressZip=form.addressZip.data,cvv=form.cvv.data, number=form.number.data)
		db.session.add(card)
		db.session.commit()
		flash ('Card was added succesfully!')
		# flash('Add requested for the card {}'.format(
		# 	form.number.data))
		return redirect(url_for('index'))
	return render_template('addCardForm.html',title='Add Card', form=form)

@app.route('/payBillForm',methods=['GET','POST'])
def payBillForm():
	form = PayBillForm()
	cards = Card.query.all()
	if form.validate_on_submit():
		mycard = request.form.get('card')
		mycard = mycard.split(",")
		payment = {
		"amount": form.amount.data,
		"description": form.description.data, 
		"card": 
		{"number": mycard[0],
		"cvv": mycard[1], 
		"expMonth": mycard[2],
		"expYear": mycard[3]}
		 }
		payment = simplify.Payment.create(payment)
		# card = Card(addressState=form.addressState.data,expMonth=form.expMonth.data, expYear=form.expYear.data,
		# 	addressCity=form.addressCity.data,addressZip=form.addressZip.data,cvv=form.cvv.data, number=form.number.data)
		flash ('Card was added succesfully!')
		return redirect(url_for('index'))
	return render_template('payBillForm.html',title='Pay Bill', form=form,cards=cards)

@app.route('/',methods=["POST"])
def getValue():
	number = request.form['number']
	cvv = request.form['cvv']
	expMonth = request.form['expMonth']
	expYear = request.form['expYear']
	amount = request.form['amount']
	description = request.form['description']
	currency = request.form['currency']

	payment = simplify.Payment.create({
       "card" : {
            "number": number,
            "expMonth": expMonth,
            "expYear": expYear,
            "cvc": cvv
        },
        "amount" : amount,
        "description" : description,
        "currency" : currency
	})
	return redirect(url_for('index'))

# Imaya's Code	
@app.route('/recentpayments', methods=["GET"])
def recentpayments():
	payments = simplify.Payment.list({"max": 1000 })
	return render_template('recentpayments.html',title='Recent Payments', payments = payments)

@app.route('/payments', methods=["GET"])
def paymentdetail():
	payment_detail = simplify.Payment.find(request.args.get(id))
	return render_template('paymentdetail.html', payment_detail = payment_detail)
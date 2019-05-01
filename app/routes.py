from flask import render_template, flash, redirect, url_for, request, jsonify 
from app.forms import RegistrationForm, LoginForm, AddCustomerForm, AddCardForm, PayBillForm, CommentsForm 
from app import app, db, queue
from flask_login import current_user, login_user, login_required, logout_user
from app.models import Customer, Card, UtilityBill, Comment, Payment
from tasks import getUtilityBill
from redis import Redis
from twilio.rest import Client
from alpha_vantage.timeseries import TimeSeries
from alpha_vantage.foreignexchange import ForeignExchange
from alpha_vantage.cryptocurrencies import CryptoCurrencies
from pprint import pprint, PrettyPrinter
from newsapi.newsapi_client import NewsApiClient
from newsapi.articles import Articles
from datetime import datetime, timedelta
from werkzeug.urls import url_parse
from app.emails import send_email
import rq
from rq import get_current_job, Queue
from rq.job import Job
import simplify
import json
import requests
import time
import base64
import calendar
import io

utility_referral = ''
# simplify.public_key = "sbpb_Njc3ZDkyMmYtYTE0OS00MTRjLWE5YmUtZjQ3MTI5ZWUzNmE3"
# simplify.private_key = "3KzZq8dCCUhQMh1dTCU6jPrwdG0O4wwwizAP82LcfpN5YFFQL0ODSXAOkNtXTToq"
#ALPHAVANTAGE_API_KEY = "OYL0XNT0O85E76PM"
newsapi = Articles(API_KEY='3c0850b9cd1041989ae33dd295793c51')
job_id = ''
# queue = rq.Queue(connection=Redis.from_url('redis://'))
# queue.delete(delete_jobs=True)
# queue = rq.Queue('tasks', connection=Redis.from_url('redis://'))


@app.route('/')
@app.route('/index')
# @login_required
def index():
	return render_template('index.html')


##################### BEGIN SPRINT 1 CODE ##########################

@app.route('/manageCard/viewCards',methods=['GET','POST'])
@login_required
def viewCards():
	cards = Card.query.all()
	customer = current_user.id
	mycards = []
	#username = str(current_user.fname) + " "+ str(current_user.lname)
	print(current_user.fname,current_user.lname)
	for card in cards:
		print(card.cardHolderRef)
		if card.cardHolderRef == current_user.id:
			print(card.cardHolderRef)
			mycards.append(card)
		#if card.cardHolderRef == username:
	return render_template('viewCards.html',title='View Cards', mycards=mycards)

@app.route('/manageCard/addCardForm',methods=['GET','POST'])
@login_required
def cardform():
	form = AddCardForm()
	if form.validate_on_submit():
		card = Card(addressState=form.addressState.data,expMonth=form.expMonth.data, expYear=form.expYear.data,
			addressCity=form.addressCity.data,addressZip=form.addressZip.data,cvv=form.cvv.data, number=form.number.data,
			cardHolderRef=current_user.id)
		print(form.number.data)
		db.session.add(card)
		db.session.commit()
		flash ('Card was added succesfully!')
		# flash('Add requested for the card {}'.format(
		# 	form.number.data))
		return redirect(url_for('index'))
	return render_template('addCardForm.html',title='Add Card', form=form)

@app.route('/payBillForm',methods=['GET','POST'])
@login_required
def payBillForm():
	form = PayBillForm()
	allCards = Card.query.all()
	cards = []
	for card in allCards:
		if card.cardHolderRef == current_user.id:
			cards.append(card)
	if form.validate_on_submit():
		mycard = request.form.get('card')
		mycard = mycard.split(",")
		amount = float(form.amount.data)*100
		str(amount)
		print(amount)
		payment = {
		"amount": amount,
		"description": form.description.data, 
		"card": 
		{"number": mycard[0],
		"cvv": mycard[1], 
		"expMonth": mycard[2],
		"expYear": mycard[3]}
		 }
		###############Add payment to it's database here#########
		dbpayment = Payment(company="Utility",amount=form.amount.data,
			description=form.description.data,
			paymentMakerRef=current_user.id,
			paymentCardRef=mycard[0])
		db.session.add(dbpayment)
		db.session.commit()
		###############Add payment to it's database here#########
		payment = simplify.Payment.create(payment)
		# card = Card(addressState=form.addressState.data,expMonth=form.expMonth.data, expYear=form.expYear.data,
		# 	addressCity=form.addressCity.data,addressZip=form.addressZip.data,cvv=form.cvv.data, number=form.number.data)
		
		flash ('Payment was succesfully!')
		amount = form.amount.data
		#sms(amount)

		user = Customer.query.get(current_user.id)
		email = user.email
		send_email('Payment Recieved',
					[email],
					#render_template("payment_email.txt", fname = user.fname),
					render_template("payment_email.html", fname = user.fname))

		return redirect(url_for('index'))
	return render_template('payBillForm.html',title='Pay Bill', form=form,cards=cards)

@app.route('/manageCard',methods=['GET','POST'])
@login_required
def manageCard():
	return render_template('manageCard.html',title='Manage Card')

######################## END SPRINT 1 CODE #########################

######################## BEGIN SALMAN SPRINT 2A/B ##################
@app.route('/register', methods=['GET','POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = RegistrationForm()
	if form.validate_on_submit():
		customer = Customer(email = form.email.data, phone = form.phone.data, fname = form.fname.data, lname = form.lname.data)
		customer.set_password(form.password.data)


		send_email('Registration Complete',
					[form.email.data],
					# render_template("register_email.txt", fname=form.fname.data),
					render_template("register_email.html", fname=form.fname.data))

		db.session.add(customer)
		db.session.commit()
		flash('Congratulations, you are now registered!')
		return redirect(url_for('login'))
	return render_template('register.html', title='Register', form=form)

@app.route('/login',methods=['GET','POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('index'))
	form = LoginForm()
	if form.validate_on_submit():
		customer = Customer.query.filter_by(email=form.email.data).first()
		if customer is None or not customer.check_password(form.password.data):
			flash('Invalid username or password')
			return redirect(url_for('login'))
		login_user(customer, remember= form.remember_me.data)
		next_page = request.args.get('next')
		if not next_page or url_parse(next_page).netloc != '':
			next_page = url_for('index')
		return redirect(url_for('index'))
	return render_template('login2.html',title='Sign In', form=form)


@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('index'))
######################## END SALMAN SPRINT 2A/B ####################

######################## BEGIN SAYEF SPRINT 2A/B ###################
@app.route('/manageBill',methods=['GET','POST'])
@login_required
def manageBill():
	return render_template('manageBill.html',title='Manage Bill')

@app.route('/manageBill/selectBill', methods=['GET','POST'])
@login_required
def selectBill():
	return render_template('selectBill.html', title='Select Bill')

@app.route('/manageBill/selectBill/selectUtility', methods=['GET','POST'])
@login_required
def selectUtility():
	return render_template('selectUtility.html', title='Select Utility')

@app.route('/viewRecentBills', methods=['GET','POST'])
@login_required
def viewRecentBills():
	global utility_referral
	global queue
	global job_id
	utility_referral = request.args.get('referral')
	print(utility_referral)
	job = queue.enqueue('app.tasks.getUtilityBillv2',args=(utility_referral,))
	job.refresh()
	job_id = str(job.get_id())
	loading = """
	<div class="d-flex justify-content-center">
  		<div class="spinner-border" role="status">
    	<span class="sr-only">Loading...</span>
  		</div>
		</div>
	"""
	return render_template('viewRecentBills.html', title='Due Bill', loading=loading)	

# def utility():
# 	return utility_referral

@app.route('/notifications')
@login_required
def notifications():
	global queue
	global job_id
	result = ''	
	# myjobs = queue.jobs
	# mylength = len(myjobs)
	myJobId = job_id
	job = queue.fetch_job(myJobId)
	#job = Job.fetch("b3893fc8-a6ea-4637-abb9-2e01e19f8f97", connection=Redis.from_url('redis://'))
	job.refresh()
	if job.is_finished:
		utilityBills = UtilityBill.query.all()
		latestBill = utilityBills[-1]
		print(latestBill)
		billId = latestBill.billId
		result= """
		<div class="list-group">
  		<a href="#" class="list-group-item list-group-item-action active">
    	<div class="d-flex w-100 justify-content-between">
      	<h4 class="mb-1">Due Bill</h4>
    	</div>
		<a href="#" class="list-group-item list-group-item-action">
    	<div class="d-flex w-100 justify-content-between">
      	<h5 class="mb-1">ConEd</h5>
      	<small class="text-muted">"""+latestBill.usage+""" kwh</small>
    	</div>
    	<p class="mb-1">$"""+latestBill.duePayment+"""</p>
    	<small class="text-muted">Account: """+latestBill.accountNumber+"""
    	Contact: """+latestBill.accountHolder+"""</small>
    	<small class="text-muted">"""+"""</small>
  		</a>
  		<a href="/payBillForm" class="btn btn-primary">Pay Now</a>
		"""
		bill = UtilityBill.query.filter_by(billId=billId).first()
		bill.complete = True
		db.session.commit()
		queue.delete(delete_jobs=True)
	else:
		result = """
		<div align="center">
		<div class="spinner-grow text-primary" role="status">
  		<span class="sr-only">Loading...</span>
		</div>
		<br>
		<br>
		<span>Downloading...</span>
		</div>
		</div>"""
	return result
######################## END SAYEF SPRINT 2A/B #####################

######################## BEGIN IMAYA SPRINT 2A/B ###################

@app.route('/manageBill/recentpayments', methods=["GET"])
@login_required
def recentpayments():
	mypaymentlist = []
	payments = Payment.query.all()
	for payment in payments:
		if payment.paymentMakerRef == current_user.id:
			mypaymentlist.append(payment)
	return render_template('recentpayments.html',title='Recent Payments', paymentlist = mypaymentlist) 

@app.route('/about')
def about():
	return render_template('about.html')
######################## END IMAYA SPRINT 2A/B #####################

######################## BEGIN ANDREW SPRINT 2A/B ##################
######################## END ANDREW SPRINT 2A/B ####################


######################## BEGIN SALMAN SPRINT 3/4 ###################

@app.route('/cryptoCurrencyPrices', methods=['GET','POST'])
#@login_required
def cryptoCurrencyPrices():

	ts = TimeSeries(key='OYL0XNT0O85E76PM')
	cc = ForeignExchange(key='OYL0XNT0O85E76PM')

	data_BTC, _ = cc.get_currency_exchange_rate(from_currency='BTC',to_currency='USD')
	pprint(data_BTC)

	data_LTC, _ = cc.get_currency_exchange_rate(from_currency='LTC',to_currency='USD')
	pprint(data_LTC)

	data_ETH, _ = cc.get_currency_exchange_rate(from_currency='ETH',to_currency='USD')
	pprint(data_ETH)

	return render_template('cryptoCurrencyPrices.html', data_BTC=data_BTC, data_LTC=data_LTC, data_ETH=data_ETH)



@app.route('/stockPrices', methods=['GET','POST'])
#@login_required
def stockPrices():

	ts = TimeSeries(key='OYL0XNT0O85E76PM')

	#Get json object with the intraday data and another with  the call's metadata
	data, meta_data = ts.get_intraday('GOOGL')
	pprint(data)

	ts = TimeSeries(key='OYL0XNT0O85E76PM',retries='5')
	ts = TimeSeries(key='OYL0XNT0O85E76PM',output_format='pandas')

	#For the default date string index behavior
	ts = TimeSeries(key='OYL0XNT0O85E76PM',output_format='pandas', indexing_type='date')

	#For the default integer index behavior
	#ts = TimeSeries(key='OYL0XNT0O85E76PM',output_format='pandas', indexing_type='integer')
	#ts = TimeSeries(key='OYL0XNT0O85E76PM', output_format='pandas')

	#Prints Microsoft Stock Data
	#data, meta_data = ts.get_intraday(symbol='MSFT',interval='30min', outputsize='full')
	#pprint(data)
	return render_template('stockPrices.html', data=data)

@app.route('/getStockPrices', methods=['GET','POST'])
def getStockPrices():
	lowValues = []
	highValues = []
	closeValues= []
	ts = TimeSeries(key='OYL0XNT0O85E76PM')

	#Get json object with the intraday data and another with  the call's metadata
	data, meta_data = ts.get_intraday('GOOGL')
	pprint(data)

	ts = TimeSeries(key='OYL0XNT0O85E76PM',retries='5')
	ts = TimeSeries(key='OYL0XNT0O85E76PM',output_format='pandas')

	#For the default date string index behavior
	ts = TimeSeries(key='OYL0XNT0O85E76PM',output_format='pandas', indexing_type='date')

	paymentlist = payments.list
	for payment in paymentlist:
		bill = payment["amount"]
		values.append(bill)
	print(values)
	values.reverse()
	return jsonify(values)

@app.route('/topHeadlines')
#@login_required
def topHeadlines():

	business_insider_data = newsapi.get(source="business-insider", sort_by='top')
	articles = business_insider_data['articles']
	pprint(business_insider_data)

	#bbcNews_data = newsapi.get(source="bbc-news", sort_by='top')
	#bbcArticles = bbcNews_data['bbcArticles']
	#pprint(bbcNews_data)

	return render_template('topHeadlines.html', business_insider_data=business_insider_data, articles=articles) #bbcNews_data=bbcNews_data, bbcArticles=bbcArticles)

######################## END SALMAN SPRINT 3/4 #####################

######################## BEGIN SAYEF SPRINT 3/4 ####################

@app.route('/getDashboard',methods=['GET','POST'])
@login_required
def getDashboard():
	payments = getPayments()
	paymentlist = []
	for payment in payments:
		paymentlist.append(payment.amount)
	return jsonify(paymentlist)

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
	paymentlist = getPayments()
	paymentlist.reverse()
	if len(paymentlist)>=1:
		return render_template('dashboard.html', title='Dashboard', paymentlist=paymentlist)
	else:
		return render_template('dashboardv3.html', title='Dashboard', paymentlist=paymentlist)

@login_required
def getPayments():
	payments = Payment.query.all()
	paymentlist = []
	for payment in payments:
		if payment.paymentMakerRef==current_user.id:
			paymentlist.append(payment)
	return paymentlist

@app.route('/sms', methods=['GET','POST'])
def sms(amount):
	account_sid = 'AC56d7aa38ec93bed34b8334f3e1c092d8'
	auth_token = '4186b0d46f49204c54f32f897d77b371'
	user = Customer.query.get(current_user.id)
	phone="+1"+str(user.phone)
	client = Client(account_sid, auth_token)
	message = client.messages \
	.create(
		body="This is a twilio test sms. A payment of ${} was charged from youir account".format(amount),
		from_='+19292055913',
		to=phone)
	print(message.sid)
	flash ("An SMS was sent to your phone. Sayef.")

######################## END SAYEF SPRINT 3/4 ######################

######################## BEGIN IMAYA SPRINT 3/4 ####################

@app.route('/submitComments', methods=['GET', 'POST'])
@login_required
def submitComments():
	form = CommentsForm()
	print("Hello 1")
	if form.validate_on_submit():
		print("Hello 2")
	 	comment = Comment(name=form.name.data, comment=form.comment.data) #commentID=form.commentID.data)
		db.session.add(comment)
		db.session.commit()
		flash('Your comment has been posted!')
		print("Hello 3")
		return redirect(url_for('viewOtherComments'))
	print("Hello 4")
	return render_template('comments.html', title ='Comments', form=form)


@app.route('/viewOtherComments', methods=['GET', 'POST'])
def viewOtherComments():
	comments = Comment.query.all()
	return render_template('viewComments.html', comments=comments)

@app.route('/currency',methods=['GET','POST'])
def currency():
	result = requests.get("http://data.fixer.io/api/latest?access_key=4fd3b92b4b988227dbf4220208b14646")
	result = json.loads(result.text)
	rates = result['rates']
	return render_template('currency.html',title='Currency', rates=rates)

######################## END IMAYA SPRINT 3/4 ######################

######################## BEGIN ANDREW SPRINT 3/4 ###################

######################## END ANDREW SPRINT 3/4 #####################

# @app.route('/payments', methods=["GET"])
# @login_required
# def paymentdetail():
# 	payment_detail = simplify.Payment.find(request.args.get(id))
# 	return render_template('paymentdetail.html', payment_detail = payment_detail)




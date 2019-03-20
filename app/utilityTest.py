import json
import requests
import time

class Utility:
	headers = {"Authorization": "Bearer 82aa45097ea54fbc89237acbd43f4979"}

	uid_response = requests.post("https://utilityapi.com/api/v2/forms" ,headers=headers)
	time.sleep(5)
	uid_json_data_response = json.loads(uid_response.text)
	uid = uid_json_data_response["uid"]

	referral_url = "https://utilityapi.com/api/v2/forms/"+uid+"/test-submit"
	referral_code_response = requests.post(referral_url, headers=headers, data='{"utility": "DEMO", "scenario": "residential"}')
	time.sleep(5)
	referral_code_json_data_response = json.loads(referral_code_response.text)
	referral_code = referral_code_json_data_response["referral"]

	meter_uid_url = "https://utilityapi.com/api/v2/authorizations?referrals="+referral_code+"&include=meters"
	meter_uid_response = requests.get(meter_uid_url, headers=headers)
	time.sleep(10)
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
	time.sleep(10)
	historical_data_response = requests.post(historical_data_url, headers = headers,  data = json_data)
	historical_data_json_response = json.loads(historical_data_response.text)
	# print(historical_data_json_response)

	success = historical_data_json_response["success"]
	if success is True:
		polling_url = "https://utilityapi.com/api/v2/meters/"+meter_uid
		time.sleep(5)
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
		time.sleep(5)
		bills_response = requests.get(bills_url, headers=headers)
		bills_json_data_response = json.loads(bills_response.text)
		bills = bills_json_data_response["bills"][-1]["base"]

	def myBill():
		bill = [{"billing_account": bills["billing_account"]},
		{"billing_contact": bills["billing_contact"]},
		{"billing_address": bills["billing_address"]},
		{"bill_total_kwh": bills["bill_total_kwh"]},
		{"bill_total_cost": bills["bill_total_cost"]}]
		return bill
		

	# print("Account No. : " + str(billing_account))
	# print("Account Holder : " + str(billing_contact))
	# print("Billing Address : " +str(billing_address))
	# print("Usage : "+ str(bill_total_kwh))
	# print("Due Payment : "+ str(bill_total_cost))
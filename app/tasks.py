import time
from rq import get_current_job
from app import db
from app.models import UtilityBill
import json
import requests
from redis import Redis
import rq
import routes
import random

def example(seconds):
    job = get_current_job()
    print('Starting task')
    for i in range(seconds):
        job.meta['progress'] = 100.0 * i / seconds
        job.save_meta()
        print(i)
        time.sleep(1)
    job.meta['progress'] = 100
    job.save_meta()
    print('Task completed')

def getUtilityBillv2(args):
    headers = {"Authorization": "Bearer 82aa45097ea54fbc89237acbd43f4979"}
    meter_uid_url = "https://utilityapi.com/api/v2/authorizations?referrals="+str(args)+"&include=meters"
    meter_uid_response = requests.get(meter_uid_url, headers=headers)
    time.sleep(3)
    meter_uid_json_data_response = json.loads(meter_uid_response.text)
    meter_uid = meter_uid_json_data_response["authorizations"][0]["meters"]["meters"][0]["uid"]
    meter_uid = str(meter_uid)
    historical_data_url = "https://utilityapi.com/api/v2/meters/historical-collection"
    data = {"meters": [meter_uid]}
    json_data = json.dumps(data)
    time.sleep(3)
    historical_data_response = requests.post(historical_data_url, headers = headers,  data = json_data)
    historical_data_json_response = json.loads(historical_data_response.text)
    success = historical_data_json_response["success"]
    if success is True:
        polling_url = "https://utilityapi.com/api/v2/meters/"+meter_uid
        time.sleep(3)
        polling_data_response = requests.get(polling_url, headers = headers)
        polling_data_json_response = json.loads(polling_data_response.text)
        bills_url = "https://utilityapi.com/api/v2/bills?meters="+meter_uid
        print(bills_url)
        time.sleep(3)
        bills_response = requests.get(bills_url, headers=headers)
        bills_json_data_response = json.loads(bills_response.text)
        bills = bills_json_data_response

        print(bills["bills"][0])
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        print(bills["bills"][0]["authorization_uid"])
        print(bills["bills"][0]["base"]["billing_contact"])
        print(bills["bills"][0]["base"]["billing_address"])
        print(bills["bills"][0]["base"]["bill_total_kwh"])
        print(bills["bills"][0]["base"]["bill_total_cost"])
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        billing_id = bills["bills"][0]["uid"]
        billing_account = bills["bills"][0]["authorization_uid"]
        billing_contact = bills["bills"][0]["base"]["billing_contact"]
        billing_address = bills["bills"][0]["base"]["billing_address"]
        bill_total_kwh = bills["bills"][0]["base"]["bill_total_kwh"]
        bill_total_cost = bills["bills"][0]["base"]["bill_total_cost"]
        utilityBill = UtilityBill(
            billId=billing_id,
            accountNumber=billing_account,
            accountHolder=billing_contact,
            billingAddress=billing_address,
            usage=bill_total_kwh,
            duePayment=bill_total_cost,
            complete = False)
        db.session.add(utilityBill)
        db.session.commit()   

def getUtilityBill(args):
    print("args")
    print(args)
    headers = {"Authorization": "Bearer 82aa45097ea54fbc89237acbd43f4979"}
    # # data = {"customer_email": "Bearer 82aa45097ea54fbc89237acbd43f4979", ""}
    # uid_response = requests.post("https://utilityapi.com/api/v2/forms" ,headers=headers)
    # time.sleep(3)
    # uid_json_data_response = json.loads(uid_response.text)
    # uid = uid_json_data_response["uid"]

    # referral_url = "https://utilityapi.com/api/v2/forms/"+uid+"/test-submit"
    # referral_code_response = requests.post(referral_url, headers=headers, data='{"utility": "DEMO", "scenario": "residential"}')
    # time.sleep(3)
    # referral_code_json_data_response = json.loads(referral_code_response.text)
    # referral_code = referral_code_json_data_response["referral"]
    # # # referral_code = routes.utility()
    meter_uid_url = "https://utilityapi.com/api/v2/authorizations?referrals="+str(args)+"&include=meters"
    # time.sleep(3)
    print("hello")
    print(meter_uid_url)
    meter_uid_response = requests.get(meter_uid_url, headers=headers)
    time.sleep(3)
    meter_uid_json_data_response = json.loads(meter_uid_response.text)
    meter_uid = meter_uid_json_data_response["authorizations"][0]["meters"]["meters"][0]["uid"]
    meter_uid = str(meter_uid)
    print(meter_uid)

        # # print(uid)
        # # print(referral_code)
        # print(meter_uid_json_data_response)
        # print(meter_uid)
    historical_data_url = "https://utilityapi.com/api/v2/meters/historical-collection"
        # uid = [meter_uid]
    data = {"meters": [meter_uid]}
    json_data = json.dumps(data)
    time.sleep(3)
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
            #   count = count + 1
            #   print(count)
            #   polling_data_response = requests.get(polling_url, headers = headers)
            #   polling_data_json_response = json.loads(polling_data_response.text)
            # print(polling_data_json_response)
        bills_url = "https://utilityapi.com/api/v2/bills?meters="+meter_uid
        print(bills_url)
        time.sleep(3)
        bills_response = requests.get(bills_url, headers=headers)
        bills_json_data_response = json.loads(bills_response.text)
        print(bills_json_data_response)
        bills = bills_json_data_response["bills"][-1]["base"]

        billing_account = bills["billing_account"]
        billing_contact = bills["billing_contact"]
        billing_address = bills["billing_address"]
        bill_total_kwh = bills["bill_total_kwh"]
        bill_total_cost = bills["bill_total_cost"]

        # a = routes.utility_referrals
        print(billing_account)
        print(billing_contact)
        print(billing_address)
        print(bill_total_kwh)
        print(bill_total_cost)

        uid = random.randint(100000,200000)
        utilityBill = UtilityBill(
            billId=str(uid),
            accountNumber=billing_account,
            accountHolder=billing_contact,
            billingAddress=billing_address,
            usage=bill_total_kwh,
            duePayment=bill_total_cost,
            complete = False)
        db.session.add(utilityBill)
        db.session.commit()

def _set_task_progress(progress):
    job = get_current_job()
    if job:
        job.meta['progress']=progress
        job.save_meta()
        task = task.query.get(job.get_id())
        task.user.add_notification('task_progress', {'task_id': job.get_id(),'progress': progress})

        if progress>= 100:
            task.complete=True
        db.session.commit()
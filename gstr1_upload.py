import os
import sys
import random
import string
import pytz
import json
import traceback
import base64  # import base64 encodool0
from time import sleep
from datetime import datetime, timedelta
from bson import ObjectId
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from gst_sdk import security as views
from common import Common
import constants as CONSTANTS


def get_access_token():
    
    asp_user_data ={}
    response = {}
    requestData = {}    
    decodeResult = {} 
    asp_user_data['username'] = CONSTANTS.accessTokenInfo['username']
    asp_user_data['password'] = CONSTANTS.accessTokenInfo['password']
    asp_user_data['client_id'] = CONSTANTS.accessTokenInfo['client_id']
    asp_user_data['client_secret'] = CONSTANTS.accessTokenInfo['client_secret']
    asp_user_data['grant_type'] = CONSTANTS.accessTokenInfo['grant_type']
    
    json_data = json.dumps(asp_user_data)
    common_obj = Common()
    # generate 16 digit random key
    asp_app_key = common_obj.get_random_code(16) 
    # encrypt the credential data with 16 digit random key
    credential_data = views.encrypt_with_asp_key(asp_app_key, json_data)
    # encrypt 16 digit random key with the masters india sever.crt file
    encpt_asp_app_key = views.encrypt_with_public_key(asp_app_key, 'gst')             
    requestData['credentials_data'] = credential_data.decode('utf8')
    requestData['app_key'] = encpt_asp_app_key.decode('utf8')            
    url = CONSTANTS.gstr_urls["ACCESS_TOKEN"]

    payload = json.dumps(requestData) 
    result = views.send_request(url, payload, 'POST')
    decodeResult = json.loads(result)
    decodeResult['asp_app_key'] = asp_app_key
    return decodeResult

def otp_request():
    token = get_access_token()
    other_params = {
                    'access_token': token['accessToken']
                }
    other_parameters = json.dumps(other_params)
    # Other parameters
    encrptedOthrParam = views.encrypt_with_asp_key(token['asp_app_key'], other_parameters)
    
    common_obj = Common()
    app_key_data = common_obj.get_random_code(32)
    encrptedGstAppKey = views.encrypt_with_public_key(app_key_data, 'qa-gst')

    request = {}
    request['username']= CONSTANTS.GstinInfo['gst_username']
    request['action']= "OTPREQUEST"
    request['app_key']= encrptedGstAppKey.decode('utf8')
    request['other_parameters'] =encrptedOthrParam.decode('utf8')
    payload = json.dumps(request)

    header = dict()
    txn = common_obj.get_random_code(16)
    header['ip'] = "3.6.200.222"
    header['client-id'] = CONSTANTS.accessTokenInfo['client_id']
    header['username'] = CONSTANTS.GstinInfo['gst_username']
    header['state_cd'] = CONSTANTS.GstinInfo['state']
    header['txn'] = txn;

    url = CONSTANTS.gstr_urls['auth_url']
    
    result = views.send_request(url, payload, 'POST',header)
    if (result):
        decodeResult = json.loads(result)
        response = {}
        print("Decoded Result", decodeResult)
        if 'status_cd' in decoapp_key_datadeResult and decodeResult['status_cd'] == '1':
            response['flat_app_key'] = base64.b64encode(app_key_data.encode('utf8')).decode()
            response['encrypt_app_key'] = encrptedGstAppKey.decode('utf8')
            response['error'] = False
        else:
            if 'error' in decodeResult and 'message' in decodeResult['error']:
                msg = decodeResult['error']['message']
            elif 'error' in decodeResult and 'desc' in decodeResult['error']:
                msg = decodeResult['error']['desc']
            elif 'message' in decodeResult:
                msg = decodeResult['message']
            elif 'error_msg' in decodeResult:
                msg = decodeResult['error_msg']
            elif 'error' in decodeResult and 'error_cd' in decodeResult['error']:
                if 'error' in decodeResult and 'error_description' in decodeResult[
                    'error'] and 'error_description' in decodeResult['error']['error_description']:
                    msg = decodeResult['error']['error_description']['error_description']
                elif 'error' in decodeResult and 'error_description' in decodeResult['error']:
                    msg = decodeResult['error']['error_description']['error_description']
            else:
                msg = 'Service unavailable. Please try again later'

            response['error'] = True
            response['message'] = msg
    else:
        msg = 'Service unavailable. Please try again later'
        response['error'] = True
        response['message'] = msg

    print(response)
    exit()
    


def auth_token():
    token = get_access_token()
    other_params = {
                    'access_token': token['accessToken']
                }
    other_parameters = json.dumps(other_params)
    # Other parameters
    encrptedOthrParam = views.encrypt_with_asp_key(token['asp_app_key'], other_parameters)    
    
    otp = '788572'
    fields = dict()
    fields['action'] = "AUTHTOKEN"
    fields['username'] = CONSTANTS.GstinInfo['gst_username']
    # 32 character random app key which is encrypted with GSTIN public key and used at the time of OTP request
    encrypt_app_key = 'iRCPANgvYBnzMbK/sTkyOCAof8FacLbm6f4NX4I9vSyFcojqy/Nm4yw8f6vQ2TDzPcspgqe3rXOtQrQ+u44FElgo1N9c5BkwV3HA0iHgvMNW1ek2pr0oa5Y6rWSvyTFOvWA5ZWOylkUFfNGAIToASZ2ZvbOGPpI3Sea0/l2iihcXCJMlXoq8ZCaq01H/6ldPbItsDbMNBmuDqfOaviB2akq204lVKTXlJE6Ghb53mc/H4HRcPD0HYSHEzLdT8eig+jwIdeVCGMzZRVxK3gcQ7zsUi07nT8GnKkJhnT5F7LO/VpQWo6rBObG709sD67JNUlwdEyteMaElR2LReV1GCg=='
    fields['app_key'] = encrypt_app_key;
    # 32 character random app key which is base64 encode and used at the time of OTP request
    flatAppKey = 'Y2lqUjBWdUc5cDVYSEdJUlFZUGNhVzd0MGF0TU5VVmc='
    encptedOtp = views.encrypt_data(otp, flatAppKey,"str");

    fields['otp'] = encptedOtp.decode('utf8')        
    fields['other_parameters'] = encrptedOthrParam.decode('utf8');
    
    payload = json.dumps(fields)
    
    header = dict()
    common_obj = Common()
    txn = common_obj.get_random_code(16)
    header['ip'] = "3.6.200.222"
    header['client-id'] = CONSTANTS.accessTokenInfo['client_id']
    header['username'] = CONSTANTS.GstinInfo['gst_username']
    header['state_cd'] = CONSTANTS.GstinInfo['state']
    header['txn'] = txn;

    url = CONSTANTS.gstr_urls['auth_url']
    
    result = views.send_request(url, payload, 'POST',header)
    if result:        
        decodeResult = json.loads(result)
        response = {}
        if 'status_cd' in decodeResult and decodeResult['status_cd'] == '1':
            response['sek'] = decodeResult['sek']
            response['auth_token'] = decodeResult['auth_token']
            response['expiry'] = decodeResult['expiry']               
            response['flat_app_key'] = flatAppKey             
            response['error'] = False
        else:                
            if 'error' in decodeResult and 'message' in decodeResult['error']:
                msg = decodeResult['error']['message']
            elif 'error' in decodeResult and 'desc' in decodeResult['error']:
                msg = decodeResult['error']['desc']
            elif 'message' in decodeResult:
                msg = decodeResult['message']
            elif 'error_msg' in decodeResult:
                msg = decodeResult['error_msg']
            elif 'error' in decodeResult and 'error_cd' in decodeResult['error']:
                if 'error' in decodeResult and 'error_description' in decodeResult['error'] and 'error_description' in decodeResult['error']['error_description']:
                    msg = decodeResult['error']['error_description']['error_description']
                elif 'error' in decodeResult and 'error_description' in decodeResult['error']:
                    msg = decodeResult['error']['error_description']['error_description']
            else:
                msg = 'Service unavailable. Please try again later'

            response['error'] = True
            response['message'] = msg    
                
    else:
        msg = 'Service unavailable. Please try again later'
        response['error'] = True
        response['message'] = msg



    print("response===>",response)
    exit()

def save_gstr1():
    action = 'RETSAVE'
    method = "PUT"
    gstrType = 'GSTR1'

    url = CONSTANTS.gstr_urls['save_gstr_url']
    action = 'RETSAVE'
    gstUserName = CONSTANTS.GstinInfo['gst_username']
    client_id = CONSTANTS.accessTokenInfo['client_id']
    gstin = CONSTANTS.GstinInfo['gstin']
    state = CONSTANTS.GstinInfo['state']
    # 32 character random app key which is base64 encode and used at the time of OTP request
    flat_app_key = 'QzhhTFNBbUExM0NyTEJlWDFDNjZoRndQUlNLMnpYVDY='
    auth_token = "8c4c6eb3e5f84c69a81918e01d53564e"
    # sek received in auth token API 
    sek =  "GiRmTJDuP5ks4SyFlhvISk8MjorLxEumk4AOKi+hYzmJeoiimYVwM93eOJIb5c2x"
    ip = "3.6.200.222"
    return_period = '022020'
    common_obj = Common()
    txn = common_obj.get_random_code(16)
    token = get_access_token()
    other_params = {
                    'access_token': token['accessToken']
                }
    other_parameters = json.dumps(other_params)
    # Other parameters
    encrptedOthrParam = views.encrypt_with_asp_key(token['asp_app_key'], other_parameters)
    data_json = '{"gstin":"33GSPTN9511G3Z3","fp":"022020","gt":50000,"cur_gt":0,"b2b":[{"ctin":"18AAACD0132H1Z7","inv":[{"inum":"aug124","idt":"12-02-2020","val":590,"pos":"09","rchrg":"N","inv_typ":"R","itms":[{"itm_det":{"iamt":90,"txval":500,"rt":18,"csamt":0},"num":1}]}]}]}'
    ek = views.decrypt_data(sek, flat_app_key, 'byte')
    ek = base64.b64encode(ek).decode('utf8')
    
    data = views.encrypt_data(data_json, ek, type = 'str')
    data = base64.b64encode(data).decode('utf8')
    
    hmac = views.hash_hmac_256(data_json, ek)
    hmac = base64.b64encode(hmac).decode('utf8')
    
    # data = views.encrypt_data(base64.b64encode(data_json.encode('utf8')).decode(), ek, type = 'byte')
    # hmac = views.hash_hmac_256(base64.b64encode(data_json.encode('utf8')).decode(), ek)
    header = {}
    header['username'] = gstUserName
    header['client-id'] = client_id
    header['ret_period'] = return_period
    header['action'] = action
    header['gstin'] = gstin
    header['auth_token'] = auth_token
    header['ip'] = ip
    header['state_cd'] = state
    header['txn'] = txn
    request={
            'action':action,
            'data': data,
            'hmac': hmac,
            'other_parameters': encrptedOthrParam.decode('utf8')
        }

    payload = json.dumps(request)
    result= views.send_request(url, payload, method, header)
   
    print("GSTR1 save response",result)
    decodeResult = json.loads(result)
    if 'status_cd' in decodeResult and decodeResult['status_cd'] == '1':
            key = views.decrypt_data(decodeResult['rek'], ek,'byte')
            #decrypt Data from key
            encodedData = views.decrypt_data(decodeResult['data'], key)
            ref_id = base64.b64decode(encodedData).decode('utf8')
            ref_id = json.loads(ref_id)
    
    print("ref_id",ref_id)

    # Get Return Status 
    track_status_header={}
    txn = common_obj.get_random_code(16,'numeric')
    track_status_header['username'] = gstUserName
    track_status_header['client-id'] = client_id
    track_status_header['ret_period'] = return_period
    track_status_header['action'] = 'RETSTATUS'
    track_status_header['gstin'] = gstin
    track_status_header['auth_token'] = auth_token
    track_status_header['ip'] = ip
    track_status_header['state_cd'] = state
    track_status_header['txn'] = txn
    track_url =CONSTANTS.gstr_urls['Track_status_url']
    track_url = track_url+'?action=RETSTATUS&gstin='+gstin+'&ret_period='+return_period+'&ref_id='+ref_id['reference_id']+'&other_parameters='+encrptedOthrParam.decode('utf8')    
    
    track_result= views.send_request(track_url, '', '', track_status_header)
   
    if track_result:
        response={}
        decodeResult = json.loads(track_result)
        if 'status_cd' in decodeResult and decodeResult['status_cd'] == '1':
            key = views.decrypt_data(decodeResult['rek'], ek, 'byte')
            #decrypt Data from key
            encodedData = views.decrypt_data(decodeResult['data'], key)
            if encodedData:
                response['error'] = False
                response['data'] = base64.b64decode(encodedData).decode('utf8')
                # response['reqData'] = base64.b64encode(params_data_json)
            else:
                response['error'] = True
                response['message'] = "Received GST data not decrypted."
        else:                
            if 'error' in decodeResult and 'message' in decodeResult['error']:
                msg = decodeResult['error']['message']
            elif 'error' in decodeResult and 'desc' in decodeResult['error']:
                msg = decodeResult['error']['desc']
            elif 'message' in decodeResult:
                msg = decodeResult['message']
            elif 'error_msg' in decodeResult:
                msg = decodeResult['error_msg']
            elif 'error' in decodeResult and 'error_cd' in decodeResult['error']:
                if 'error' in decodeResult and 'error_description' in decodeResult['error'] and 'error_description' in decodeResult['error']['error_description']:
                    msg = decodeResult['error']['error_description']['error_description']
                elif 'error' in decodeResult and 'error_description' in decodeResult['error']:
                    msg = decodeResult['error']['error_description']['error_description']
            else:
                msg = 'Service unavailable. Please try again later'

            response['error'] = True
            response['message'] = msg 
    else:
        msg = 'Service unavailable. Please try again later'
        response['error'] = True
        response['message'] = msg
    print(response)
    exit()
    return response


def logout():
    token = get_access_token()
    other_params = {
                    'access_token': token['accessToken']
                }
    other_parameters = json.dumps(other_params)
    # Other parameters
    encrptedOthrParam = views.encrypt_with_asp_key(token['asp_app_key'], other_parameters)    
    
    
    fields = dict()
    fields['action'] = "LOGOUT"
    fields['username'] = CONSTANTS.GstinInfo['gst_username']
    # 32 character random app key which is encrypted with GSTIN public key and used at the time of OTP request
    encrypt_app_key = 'iRCPANgvYBnzMbK/sTkyOCAof8FacLbm6f4NX4I9vSyFcojqy/Nm4yw8f6vQ2TDzPcspgqe3rXOtQrQ+u44FElgo1N9c5BkwV3HA0iHgvMNW1ek2pr0oa5Y6rWSvyTFOvWA5ZWOylkUFfNGAIToASZ2ZvbOGPpI3Sea0/l2iihcXCJMlXoq8ZCaq01H/6ldPbItsDbMNBmuDqfOaviB2akq204lVKTXlJE6Ghb53mc/H4HRcPD0HYSHEzLdT8eig+jwIdeVCGMzZRVxK3gcQ7zsUi07nT8GnKkJhnT5F7LO/VpQWo6rBObG709sD67JNUlwdEyteMaElR2LReV1GCg=='
    auth_token = '8c4c6eb3e5f84c69a81918e01d53564e'
    fields['app_key'] = encrypt_app_key;
    fields['auth_token'] = auth_token
    
    fields['other_parameters'] = encrptedOthrParam.decode('utf8');
    
    payload = json.dumps(fields)
    
    header = dict()
    common_obj = Common()
    txn = common_obj.get_random_code(16)
    header['ip'] = "3.6.200.222"
    header['client-id'] = CONSTANTS.accessTokenInfo['client_id']
    header['username'] = CONSTANTS.GstinInfo['gst_username']
    header['state_cd'] = CONSTANTS.GstinInfo['state']
    header['auth_token'] = auth_token
    header['txn'] = txn;

    url = CONSTANTS.gstr_urls['auth_url']
    
    result = views.send_request(url, payload, 'POST',header)
    print(result)
    exit()


def get_gstr1():
    action = 'B2B'
    url = CONSTANTS.gstr_urls['save_gstr_url']    
    gstUserName = CONSTANTS.GstinInfo['gst_username']
    client_id = CONSTANTS.accessTokenInfo['client_id']
    gstin = CONSTANTS.GstinInfo['gstin']
    state = CONSTANTS.GstinInfo['state']
    # 32 character random app key which is base64 encode and used at the time of OTP request
    flat_app_key = 'dkRyUU1OdTNhc2ZKZGNBN0hSSmVTNDI1dmhUeHd6bGU='
    auth_token = "5e8c009761f845ec928e1467d4510ebd"
    sek =  "lExB92zA4IdYV7xXZSwxRSrVmeGoKujAcl3r+c2AIX4dL4IcscSRuVuzB1bSKsKf"
    ip = "::1"
    return_period = '082019'
    ek = views.decrypt_data(sek, flat_app_key, 'byte')
    ek = base64.b64encode(ek).decode('utf8')
    common_obj = Common()
    txn = common_obj.get_random_code(16,'numeric')
    token = get_access_token()
    other_params = {
                    'access_token': token['accessToken']
                }
    other_parameters = json.dumps(other_params)
    # Other parameters
    encrptedOthrParam = views.encrypt_with_asp_key(token['asp_app_key'], other_parameters)
    
    header = {}
    header['username'] = gstUserName
    header['client-id'] = client_id
    header['ret_period'] = return_period
    header['action'] = action
    header['gstin'] = gstin
    header['auth_token'] = auth_token
    header['ip'] = ip
    header['state_cd'] = state
    header['txn'] = txn


    url =CONSTANTS.gstr_urls['save_gstr_url']
    url = url+'?action='+action+'&gstin='+gstin+'&ret_period='+return_period+'&other_parameters='+encrptedOthrParam.decode('utf8')    
    result= views.send_request(url, '', '', header)

    if result:
        response={}
        decodeResult = json.loads(result)
        if 'status_cd' in decodeResult and decodeResult['status_cd'] == '1':
            key = views.decrypt_data(decodeResult['rek'], ek, 'byte')
            #decrypt Data from key
            encodedData = views.decrypt_data(decodeResult['data'], key)
            if encodedData:
                response['data'] = base64.b64decode(encodedData).decode('utf8')
    print(response)
    exit()
   




if __name__ == "__main__":
    #get_access_token()
    otp_request()
    # auth_token()
    # save_gstr1()
    # logout()
    # get_gstr1()

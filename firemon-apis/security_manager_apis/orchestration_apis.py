""" To call Orchestration API """
import json
import requests
import authenticate_user
from get_properties_data import get_properties_data


class OrchestrationApis():
    """ Adding code for calling orchestration APIs """

    def __init__(self,host,username,password,verify_ssl):
        """ User needs to pass host,username,password,and verify_ssl as parameters while
        creating instance of this class and internally Authentication class instance
        will be created which will set authentication token in the header to get firemon API access """
        self.parser=get_properties_data()
        self.api_instance= authenticate_user.Authentication(host,username,password,verify_ssl)
        self.headers=self.api_instance.get_auth_token()
        self.host=host
        self.verify_ssl=verify_ssl

    def rulerec_api(self,params,domain_id):
        """ Calling orchestration rulerec api by passing json data as request body, headers, params and domainId 
            which returns you list of rule recommendations for given input as response"""
        with open("./RuleRec/rulerec_request_payload.json") as req :
            data=json.load(req)
        rulerec_url= self.parser.get('REST','rulerec_api_url').format(self.host,domain_id)
        try:
            resp=requests.post(url=rulerec_url,
                headers=self.headers,params=params, json=data, verify=self.verify_ssl)
            print(">>>API Response Start>>>\n",resp.json(),"\n>>>API Response End>>>")
            return resp.json()
        except requests.exceptions.HTTPError as e:
            print("Exception occurred while getting rule recommendation \n Exception : {0}".
                  format(e.response.text))

    def pca_api(self,domain_id,device_id):
        """ Calling orchestration pca api by passing json data as request body, headers, deviceId and domainId 
            which returns you pre-change assessments for the given device """
        with open("./PCA/pca_request_payload.json") as req :
            data=json.load(req)
        pca_url= self.parser.get('REST','pca_api_url').format(self.host,domain_id,device_id)
        try:
            resp=requests.post(url=pca_url,
                headers=self.headers, json=data, verify=self.verify_ssl)
            print(">>>API Response Start>>>\n",resp.json(),"\n>>>API Response End>>>")
            return resp.json()
        except requests.exceptions.HTTPError as e:
            print("Exception occurred while getting pre change assessment \n Exception : {0}".
                  format(e.response.text))


# Creating instance of this class and calling orchestration api methods
parameters={'deviceGroupId':1,'addressMatchingStrategy':'INTERSECTS',
        'modifyBehavior':'MODIFY','strategy':None}

# User should update host,username,password,verify_ssl as per FMOS Instance
# set verify_ssl=False if you dont have a valid SSL certificate
orch=OrchestrationApis(host,username,password,verify_ssl)

# User should update domainId and parameters ( user can modify deviceGroupId as per requirement)
orch.rulerec_api(parameters,domainId) #domainId=1

# User should update domainId and deviceId 
# example: domain_id=1,deviceId=1
orch.pca_api(domainId,deviceId)

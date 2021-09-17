""" To Test Policy Planner APIs """
import json
import requests
import authenticate_user
from get_properties_data import get_properties_data


class PolicyPlannerApis():

    def __init__(self,host,username,password,verify_ssl):
        """ User needs to pass host,username,password,and verify_ssl as parameters while
            creating instance of this class and internally Authentication class instance
            will be created which will set authentication token in the header to get firemon API access 
        """
        self.parser=get_properties_data()
        self.api_instance= authenticate_user.Authentication(host,username,password,verify_ssl)
        self.headers=self.api_instance.get_auth_token()
        self.host=host
        self.verify_ssl=verify_ssl
        self.api_resp=''


    def create_pp_ticket(self,domain_id,workflow_name):
        """ making call to create pp ticket api which 
            creates a policy planner ticket on corresponding FMOS box """

        workflow_id= self.get_workflow_id_by_workflow_name(domain_id,workflow_name)
        with open("./PolicyPlanner/create_pp_ticket_request_payload.json") as req :
            data=json.load(req)
        pp_tkt_url= self.parser.get('REST','create_pp_tkt_api_url').format(self.host,domain_id,workflow_id)
        try:
            resp=requests.post(url=pp_tkt_url,
                headers=self.headers, json=data, verify=self.verify_ssl)
            print(">>>API Response Start>>>\n",resp.json(),"\n>>>API Response End>>>")
            return resp.json()
        except requests.exceptions.HTTPError as e:
            print("Exception occurred while creating policy planner ticket with workflow id '{0}'\n Exception : {1}".
                  format(workflow_id, e.response.text))

    
    def get_workflow_id_by_workflow_name(self,domain_id,workflow_name):
        """ Takes domainId and workflow name as input parameters and returns you 
            the workflowId for given workflow name """
        
        workflow_url= self.parser.get('REST','find_all_workflows_url').format(self.host,domain_id)
        try:

            self.api_resp=requests.get(url=workflow_url,headers=self.headers, verify=self.verify_ssl)
            count_of_workflows= self.api_resp.json().get('total')
            
            # Here, default pageSize is 10
            # CASE 1 :If total workflows > 10 then second call will be made to get all the remaining workflows
            # CASE 2 :No need to make a second call if total workflows < 10 as we already have all of them
            if(count_of_workflows>10):
                parameters={'includeDisabled':False,'pageSize':count_of_workflows}
                self.api_resp=requests.get(url=workflow_url,headers=self.headers,params=parameters, verify=self.verify_ssl)

            list_of_workflows= self.api_resp.json().get('results')
            for workflow in list_of_workflows:
                if(workflow['workflow']['name']==workflow_name):
                    workflow_id=workflow['workflow']['id']
                    return workflow_id
        except requests.exceptions.HTTPError as e:
            print("Exception occurred while fetching workflows with domain id '{0}'\n Exception : {1}".
                  format(domain_id, e.response.text))
            
# Creating PolicyPlanner instance and calling methods  
# User should update host,username,password,verify_ssl as per FMOS Instance
# set verify_ssl=False if you dont have a valid SSL certificate
policyplan=PolicyPlannerApis(host,username,password,verify_ssl)

# User should update domainId and workflowname available on ENV.
# example: domain_id=1,workflow_name='WorkflowForTest'
policyplan.create_pp_ticket(domain_id, workflow_name) 


import requests
import authenticate_user
from security_manager_apis.get_properties_data import get_properties_data


class PolicyOptimizerApis:

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool, domain_id: str, workflow_name: str,
                 suppress_ssl_warning=False):
        """ User needs to pass host,username,password,and verify_ssl as parameters while
            creating instance of this class and internally Authentication class instance
            will be created which will set authentication token in the header to get firemon API access
        """
        if suppress_ssl_warning:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.parser = get_properties_data()
        self.host = host
        self.fm_api_session = authenticate_user.Authentication(self.host, username, password, verify_ssl).get_auth_token()
        self.host = host
        self.domain_id = domain_id
        self.workflow_id = self.get_workflow_id_by_workflow_name(domain_id, workflow_name)
        self.workflow_task_id = ""
        self.workflow_packet_task_id = ""

    def __api_request(self, method: str, endpoint: str, payload=None, parameters=None, data=None, timeout=None, files=None):
        try:
            resp = self.fm_api_session.request(method, endpoint, json=payload, params=parameters, data=data, timeout=timeout, files=files)
            resp.raise_for_status()
            return resp
        except requests.exceptions.HTTPError:
            raise
        except requests.exceptions.Timeout:
            raise
        except Exception:
            raise

    def create_po_ticket(self, request_body: dict):
        """
        Method to create Policy Optimizer ticket
        :param request_body: JSON body for ticket.
        :return: Response code
        """
        endpoint = self.parser.get('REST', 'create_po_ticket').format(self.host, self.domain_id)
        resp = self.__api_request('POST', endpoint, request_body)
        return resp

    def get_po_ticket(self, ticket_id: str) -> dict:
        """
        Method to retrieve Policy Optimizer ticket JSON
        :param ticket_id: ID of ticket
        :return: JSON of ticket
        """
        endpoint = self.parser.get('REST', 'get_po_ticket').format(self.host, self.domain_id, self.workflow_id, ticket_id)
        resp = self.__api_request('GET', endpoint)
        self.get_workflow_packet_task_id(resp.json())
        self.get_workflow_task_id(resp.json())
        return resp.json()

    def assign_po_ticket(self, ticket_id: str, user_id: str):
        """
        Method to assign user to Policy Optimizer ticket
        :param ticket_id: ID of ticket
        :param user_id: ID of user
        :return: Response
        """
        self.get_po_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'assign_po_ticket').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id, self.workflow_packet_task_id)
        resp = self.__api_request('PUT', endpoint, None, None, user_id)
        return resp

    def complete_po_ticket(self, ticket_id: str, decision: dict):
        """
        Method to complete a Policy Optimizer ticket
        :param ticket_id: ID of ticket
        :param decision: Decision JSON
        :return: Response
        """
        self.get_po_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'complete_po_ticket').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id, self.workflow_packet_task_id, 'complete')
        resp = self.__api_request('PUT', endpoint, decision)
        return resp

    def cancel_po_ticket(self, ticket_id: str):
        """
        Method to cancel a Policy Optimizer ticket
        :param ticket_id: ID of ticket
        :return: Response
        """
        self.get_po_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'complete_po_ticket').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id, self.workflow_packet_task_id, 'cancelled')
        resp = self.__api_request('PUT', endpoint, {})
        return resp

    def siql_query_po_ticket(self, parameters: dict) -> dict:
        """
        Method to execute SIQL query for Policy Optimizer tickets
        :param parameters: search parameters
        :return: Response JSON
        """
        endpoint = self.parser.get('REST', 'siql_query_po').format(self.host, self.domain_id)
        resp = self.__api_request('GET', endpoint, None, parameters)
        return resp.json()

    def logout(self) -> list:
        """
        Method to logout of session
        """
        self.fm_api_session.headers['Connection'] = 'Close'
        endpoint = self.parser.get('REST', 'logout_api_url').format(self.host)
        resp = self.__api_request('POST', endpoint)
        return resp

    def get_workflow_packet_task_id(self, ticket_json: dict):
        """
        Retrieves workflowPacketTaskId value from current stage of provided ticket
        :param ticket_json: JSON of ticket, retrieved using pull_ticket function
        :return: workflowPacketTaskId of current stage for given ticket
        """
        curr_stage = ticket_json['status']
        workflow_packet_tasks = ticket_json['workflowPacketTasks']
        for t in workflow_packet_tasks:
            if t['workflowTask']['name'] == curr_stage and 'completed' not in t:
                self.workflow_packet_task_id = str(t['id'])

    def get_workflow_task_id(self, ticket_json: dict):
        """
        Retrieves workflowTaskId value from current stage of provided ticket
        :param ticket_json: JSON of ticket, retrieved using pull_ticket function
        :return: workflowTaskId of current stage for given ticket
        """
        curr_stage = ticket_json['status']
        workflow_packet_tasks = ticket_json['workflowPacketTasks']
        for t in workflow_packet_tasks:
            if t['workflowTask']['name'] == curr_stage and 'completed' not in t:
                self.workflow_task_id = str(t['workflowTask']['id'])

    def get_workflow_id_by_workflow_name(self, domain_id: str, workflow_name: str) -> str:
        """ Takes domainId and workflow name as input parameters and returns you
            the workflowId for given workflow name """
        endpoint = self.parser.get('REST', 'find_all_po_workflows_url').format(self.host, domain_id)
        resp = self.__api_request('GET', endpoint)
        count_of_workflows = resp.json().get('total')

        # Here, default pageSize is 10
        # CASE 1 :If total workflows > 10 then second call will be made to get all the remaining workflows
        # CASE 2 :No need to make a second call if total workflows < 10 as we already have all of them
        if count_of_workflows > 10:
            parameters = {'includeDisabled': False, 'pageSize': count_of_workflows}
            resp = self.__api_request('GET', endpoint, None, parameters)

        list_of_workflows = resp.json().get('results')
        for workflow in list_of_workflows:
            if workflow['workflow']['name'] == workflow_name:
                workflow_id = workflow['workflow']['id']
                return workflow_id

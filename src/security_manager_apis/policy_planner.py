from typing import Any
import requests
import authenticate_user
from security_manager_apis.get_properties_data import get_properties_data


def is_assigned(ticket_json: dict) -> bool:
    """
    Method to check if a ticket is assigned to the current user
    :param ticket_json: JSON of targeted ticket
    :return: True or False
    """
    if 'assignee' in ticket_json:
        return True
    else:
        return False


def parse_controls(controls: str) -> str:
    """
    Method to parse control string passed to a URL parameter
    :param controls: Comma delimited list of controls as string
    :return: URL query as string
    """
    output = ''
    controls_list = controls.split(',')
    for c in range(0, len(controls_list)):
        if len(controls_list) > 1 and c > 0:
            output = output + '&'
        output = output + 'controlTypes=' + controls_list[c]
    return output


class PolicyPlannerApis:

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool, domain_id: str, workflow_name: str, suppress_ssl_warning=False):
        """
        Method to create Policy Planner ticket
        :param host: Base URL
        :param username: Username
        :param password: Password
        :param verify_ssl: Verify SSL (True or False)
        :param domain_id: Domain ID, typically 1
        :param workflow_name: Name of targeted workflow
        :param suppress_ssl_warning: Suppress SSL warning (True or False), default to False
        :return: None
        """
        if suppress_ssl_warning:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.parser = get_properties_data()
        self.host = host
        self.fm_api_session = authenticate_user.Authentication(self.host, username, password, verify_ssl).get_auth_token()
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

    def create_pp_ticket(self, request_body: dict) -> dict:
        """
        Method to create Policy Planner ticket
        :param request_body: JSON body for ticket.
        :return: JSON of ticket
        """
        endpoint = self.parser.get('REST', 'create_pp_tkt_api_url').format(self.host, self.domain_id, self.workflow_id)
        resp = self.__api_request('POST', endpoint, request_body)
        return resp.json()

    def siql_query_pp_ticket(self, siql_query: str, page_size: int) -> dict:
        """
        Method to execute a SIQL Query to search for Policy Planner tickets
        :param siql_query: SIQL query
        :param page_size: Number of results to return
        :return: JSON of results
        """
        endpoint = self.parser.get('REST', 'siql_query_pp_tkt_api').format(self.host, self.domain_id)
        parameters = {'q': siql_query, 'pageSize': page_size, 'domainid': self.domain_id}
        resp = self.__api_request('GET', endpoint, None, parameters)
        return resp.json()

    def update_pp_ticket(self, ticket_id: str, request_body: dict) -> str:
        """
        Method to update Policy Planner ticket
        :param request_body: JSON body for ticket update
        :param ticket_id: Ticket ID
        :return: Status code of API Call
        """
        endpoint = self.parser.get('REST', 'update_pp_tkt_api_url').format(self.host, self.domain_id, self.workflow_id, ticket_id)
        resp = self.__api_request('PUT', endpoint, request_body)
        return resp

    def pull_pp_ticket(self, ticket_id: str) -> dict:
        """
        Method to retrieve Policy Planner ticket
        :param ticket_id: ID of ticket
        :return: JSON of ticket
        """
        endpoint = self.parser.get('REST', 'pull_pp_tkt_api_url').format(self.host, self.domain_id, self.workflow_id, ticket_id)
        resp = self.__api_request('GET', endpoint).json()
        self.get_workflow_packet_task_id(resp)
        self.get_workflow_task_id(resp)
        return resp

    def pull_pp_ticket_attachments(self, ticket_id: str, page_size=100) -> dict:
        """
        Method to retrieve Policy Planner ticket attachments
        :param ticket_id: ID of ticket
        :param page_size: # of Results
        :return: JSON of attachments
        """
        endpoint = self.parser.get('REST', 'get_attachments_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, ticket_id, page_size)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def download_pp_ticket_attachment(self, ticket_id: str, attachment_id: str):
        """
        Method to download Policy Planner ticket attachments
        :param ticket_id: ID of ticket
        :param attachment_id: ID of attachment to download
        :return: JSON of ticket
        """
        endpoint = self.parser.get('REST', 'download_attachment_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, ticket_id, attachment_id)
        resp = self.__api_request('GET', endpoint)
        return resp

    def pull_pp_ticket_events(self, ticket_id: str, page_size=100) -> dict:
        """
        Method to retrieve Policy Planner ticket history events
        :param ticket_id: ID of ticket
        :param page_size: Number of results to retrieve
        :return: JSON of results
        """
        endpoint = self.parser.get('REST', 'get_events_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, ticket_id, page_size)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def assign_pp_ticket(self, ticket_id: str, user_id: str):
        """
        Method to assign user to Policy Planner ticket
        :param ticket_id: ID of ticket
        :param user_id: ID of user
        :return: API response object
        """
        self.pull_pp_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'assign_pp_tkt_api_url').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id, self.workflow_packet_task_id)
        self.fm_api_session.headers['Content-Type'] = 'text/plain'
        resp = self.__api_request('PUT', endpoint, None, None, user_id)
        self.fm_api_session.headers['Content-Type'] = 'applicationjson'
        return resp

    def unassign_pp_ticket(self, ticket_id: str):
        """
        Method to unassign user from Policy Planner ticket
        :param ticket_id: ID of ticket
        :return: Response status code
        """
        self.pull_pp_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'unassign_pp_tkt_api_url').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id, self.workflow_packet_task_id)
        resp = self.__api_request('PUT', endpoint)
        return resp

    def add_req_pp_ticket(self, ticket_id: str, req_json: dict):
        """
        Method to add requirement to Policy Planner ticket
        :param ticket_id: ID of ticket
        :param req_json: Requirement JSON
        :return: Response status code
        """
        self.pull_pp_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'add_req_pp_tkt_api_url').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id)
        resp = self.__api_request('POST', endpoint, req_json)
        return resp

    def replace_req_pp_ticket(self, ticket_id: str, req_json: dict):
        self.pull_pp_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'replace_req_pp_tkt_api_url').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id)
        resp = self.__api_request('POST', endpoint, req_json)
        return resp

    def complete_task_pp_ticket(self, ticket_id: str, button_action: str, timeout=None):
        """
        Method to complete Policy Planner ticket task
        :param ticket_id: Ticket ID
        :param button_action: button value as string, options are: submit, complete, autoDesign, verify, approved
        :param timeout:
        :return: Response object
        """
        self.pull_pp_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'comp_task_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id, self.workflow_packet_task_id, button_action)
        resp = self.__api_request('PUT', endpoint, {}, None, None, timeout)
        return resp

    def do_pca(self, ticket_id: str, control_types: str, enable_risk_sa: str, timeout=None):
        """
        Method to run Pre-Change Assessment for Policy Planner ticket changes
        :param ticket_id: Ticket ID
        :param control_types: Control types as string array. Options:
        ALLOWED_SERVICES, CHANGE_WINDOW_VIOLATION, DEVICE_ACCESS_ANALYSIS, DEVICE_PROPERTY, DEVICE_STATUS,
        NETWORK_ACCESS_ANALYSIS, REGEX, REGEX_MULITPATTERN, RULE_SEARCH, RULE_USAGE, SERVICE_RISK_ANALYSIS,
        ZONE_MATRIX, ZONE_BASED_RULE_SEARCH
        :param enable_risk_sa: true or false
        :param timeout: Timeout amount in seconds, default to None
        :return: response code and reason
        """
        controls_formatted = parse_controls(control_types)
        endpoint = self.parser.get('REST', 'run_pca_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, ticket_id, controls_formatted, enable_risk_sa)
        resp = self.__api_request('POST', endpoint, None, None, None, timeout)
        return resp

    def retrieve_pca(self, ticket_id: str) -> dict:
        """
        Method to retrieve Pre-Change Assessment results for Policy Planner ticket
        :param ticket_id: Ticket ID as string
        :return: JSON response of PCA
        """
        endpoint = self.parser.get('REST', 'get_pca_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, ticket_id)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def run_pca(self, ticket_id: str, control_types: str, enable_risk_sa: str) -> dict:
        """
        Method to run and retrieve Pre-Change Assessment results for Policy Planner ticket
        :param ticket_id: Ticket ID
        :param control_types: Control types as string array. Options:
        ALLOWED_SERVICES, CHANGE_WINDOW_VIOLATION, DEVICE_ACCESS_ANALYSIS, DEVICE_PROPERTY, DEVICE_STATUS,
        NETWORK_ACCESS_ANALYSIS, REGEX, REGEX_MULITPATTERN, RULE_SEARCH, RULE_USAGE, SERVICE_RISK_ANALYSIS,
        ZONE_MATRIX, ZONE_BASED_RULE_SEARCH
        :param enable_risk_sa: true or false
        :return: JSON response of PCA
        """
        self.do_pca(ticket_id, control_types, enable_risk_sa)
        return self.retrieve_pca(ticket_id)

    def stage_attachment(self, file_name: str, f) -> dict:
        """
        Method to stage attachment to Policy Planner ticket
        :param file_name: File Name
        :param f: file stream
        :return: JSON response
        """
        endpoint = self.parser.get('REST', 'stage_att_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id)
        self.fm_api_session.headers['Content-Type'] = 'multipart/form-data'
        resp = self.__api_request('POST', endpoint, None, None, None, None, {file_name: f})
        self.fm_api_session.headers['Content-Type'] = 'applicationjson'
        return resp.json()

    def post_attachment(self, ticket_id: str, attachment_json: dict) -> dict:
        """
        Method to post attachment to Policy Planner ticket
        :param ticket_id: ID of ticket
        :param attachment_json: staged file JSON
        :return: JSON response
        """
        endpoint = self.parser.get('REST', 'post_att_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, ticket_id)
        resp = self.__api_request('PUT', endpoint, attachment_json)
        return resp.json()

    def add_attachment(self, ticket_id: str, file_name: str, f, description: str):
        """
        Method to add attachment to Policy Planner ticket
        :param ticket_id: ID of ticket
        :param file_name: File name
        :param f: File stream
        :param description: File description
        """
        attachment_staged = self.stage_attachment(file_name, f)
        attachment_staged['attachments'][0]['description'] = description
        attachment_posted = self.post_attachment(ticket_id, attachment_staged)
        return attachment_posted

    def csv_req_upload(self, ticket_id: str, file_name: str, f, behavior="append"):
        """
        Method to bulk CSV upload Policy Planner requirements
        :param ticket_id: ID of ticket
        :param file_name: File name
        :param f: File stream
        :param behavior: Add requirement behavior, either append or replace
        """
        endpoint = self.parser.get('REST', 'parse_csv_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id)
        self.fm_api_session.headers['Content-Type'] = 'multipart/form-data'
        resp = self.__api_request('POST', endpoint, None, None, None, None, {file_name: f})
        requirements_parsed = resp.json()
        requirements_formatted = {'requirements': []}
        for r in requirements_parsed['policyPlanRequirementErrorDTOs']:
            requirements_formatted['requirements'].append(r['policyPlanRequirementDTO'])
        self.fm_api_session.headers['Content-Type'] = 'application/json; charset=utf-8'
        if behavior == "replace":
            post_req = self.replace_req_pp_ticket(ticket_id, requirements_formatted)
        else:
            post_req = self.add_req_pp_ticket(ticket_id, requirements_formatted)
        f.seek(0)
        self.fm_api_session.headers['Content-Type'] = 'multipart/form-data'
        self.add_attachment(ticket_id, file_name, f, 'Attached original CSV file')
        self.fm_api_session.headers['Content-Type'] = 'applicationjson'
        return post_req

    def get_reqs(self, ticket_id: str) -> dict:
        """
        Method to retrieve JSON object of Policy Planner ticket requirements
        :param ticket_id: Ticket ID
        :return: JSON of requirements
        """
        self.pull_pp_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'get_recs_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def get_changes(self, ticket_id: str) -> dict:
        """
        Method to retrieve JSON of changes for a Policy Planner ticket
        :param ticket_id: Ticket ID
        :return: JSON of changes
        """
        self.pull_pp_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'get_pp_tkt_changes').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def del_all_reqs(self, ticket_id: str) -> dict:
        """
        Method to delete all requirements for a Policy Planner ticket
        :param ticket_id: Ticket ID as string
        :return: dictionary of response codes
        """
        self.pull_pp_ticket(ticket_id)
        req_json = self.get_reqs(ticket_id)
        reqs = {}
        for r in req_json['results']:
            endpoint = self.parser.get('REST', 'del_recs_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id, str(r['id']))
            resp = self.__api_request('DELETE', endpoint)
            reqs[r['id']] = resp.status_code
        return reqs

    def approve_req(self, ticket_id: str, req_id: str):
        """
        Method to approve a Policy Planner requirement
        :param ticket_id: ID of ticket
        :param req_id: ID of requirement
        :return: Response code, reason, JSON as tuple
        """
        endpoint = self.parser.get('REST', 'app_req_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, ticket_id, req_id)
        resp = self.__api_request('PUT', endpoint, {})
        return resp

    def add_change(self, ticket_id: str, req_id: str, change: dict) -> tuple[int, str, Any]:
        """
        Method to add change to a Policy Planner requirement
        :param ticket_id: ID of ticket
        :param req_id: ID of requirement
        :param change: JSON of change
        :return: Response code, reason, JSON as list
        """
        self.pull_pp_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'add_change_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id, req_id)
        resp = self.__api_request('POST', endpoint, change)
        return resp.status_code, resp.reason, resp.json()

    def update_change(self, ticket_id: str, req_id: str, change_id: str, change_json: dict):
        """
        Method to update a change on a Policy Planner requirement
        :param ticket_id: ID of ticket
        :param req_id: ID of requirement
        :param change_id: ID of change
        :param change_json: JSON of change
        :return: Response code, reason, JSON as list
        """
        self.pull_pp_ticket(ticket_id)
        endpoint = self.parser.get('REST', 'update_pp_tkt_change').format(self.host, self.domain_id, self.workflow_id, self.workflow_task_id, ticket_id, req_id, change_id)
        resp = self.__api_request('PUT', endpoint, change_json)
        return resp

    def add_comment(self, ticket_id: str, comment: str):
        """
        Method to add comment to Policy Planner ticket
        :param ticket_id: Ticket ID
        :param comment: Comment string
        """
        comment_json = {
            'comment': comment
        }
        endpoint = self.parser.get('REST', 'add_comment_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, ticket_id)
        resp = self.__api_request('POST', endpoint, comment_json)
        return resp

    def get_comments(self, ticket_id: str) -> dict:
        """
        Method to retrieve comments from Policy Planner ticket
        :param ticket_id: Ticket ID
        :return: Comment JSON
        """
        endpoint = self.parser.get('REST', 'get_comments_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, ticket_id)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def del_comment(self, ticket_id: str, comment_id: str):
        """
        Method to delete Policy Planner ticket comment
        :param ticket_id: Ticket ID
        :param comment_id: Comment ID
        """
        endpoint = self.parser.get('REST', 'del_comment_pp_tkt_api').format(self.host, self.domain_id, self.workflow_id, ticket_id, comment_id)
        resp = self.__api_request('DELETE', endpoint)
        return resp

    def logout(self):
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
        endpoint = self.parser.get('REST', 'find_all_workflows_url').format(self.host, domain_id)
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
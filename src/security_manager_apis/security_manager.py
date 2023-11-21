import json
import requests
import csv
import authenticate_user
from security_manager_apis.get_properties_data import get_properties_data


def verify_route_json(route_input: dict):
    """
    Verifying validity of JSON
    :param route_input: JSON passed
    :return: 0
    """
    if 'interfaceName' in route_input and 'virtualRouter' in route_input:
        raise Exception("Supplemental routes cannot use both an Interface and Virtual Router")
    if 'interfaceName' not in route_input and route_input['virtualRouter'] == '':
        raise Exception("Supplemental routes must use Interface or Virtual Router. JSON is missing value for "
                        "virtualRouter.")
    if 'virtualRouter' not in route_input and route_input['interfaceName'] == '':
        raise Exception("Supplemental routes must use Interface or Virtual Router. JSON is missing value for "
                        "interfaceName.")
    return 0


def mk_int(s: str) -> int:
    """
    Converting str to int, empty string returns None
    :param s: string input
    :return: int or None
    """
    s = s.strip()
    return int(s) if s else None


def build_route_json(line_input: list) -> dict:
    """
    Building JSON from Line input
    :param line_input: Line from Text File
    :return: JSON of supplemental route
    """
    if line_input[1] != '':
        supp_route = {
            "destination": line_input[2],
            "deviceId": line_input[0],
            "drop": json.loads(line_input[7].lower()),
            "gateway": line_input[3],
            "interfaceName": line_input[1],
            "metric": mk_int(line_input[6])
        }
    else:
        supp_route = {
            "destination": line_input[2],
            "deviceId": line_input[0],
            "drop": json.loads(line_input[7].lower()),
            "gateway": line_input[3],
            "metric": mk_int(line_input[6]),
            "nextVirtualRouter": line_input[5],
            "virtualRouter": line_input[4]
        }
    return supp_route


class SecurityManagerApis:

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool, domain_id: str, suppress_ssl_warning=False):
        """ User needs to pass host,username,password,and verify_ssl as parameters while
            creating instance of this class and internally Authentication class instance
            will be created which will set authentication token in the header to get firemon API access
        """
        if suppress_ssl_warning:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.parser = get_properties_data()
        self.host = host
        self.fm_api_session = authenticate_user.Authentication(self.host, username, password, verify_ssl).get_auth_token()
        self.domain_id = domain_id

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

    def get_devices(self) -> dict:
        """
        Method to retrieve devices from Security Manager
        """
        endpoint = self.parser.get('REST', 'get_dev_sm_api').format(self.host, self.domain_id)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def manual_device_retrieval(self, device_id: str):
        """
        Method to execute manual device retrieval
        :device_id: Device ID
        :return: Response status code
        """
        endpoint = self.parser.get('REST', 'man_ret_dev_sm_api').format(self.host, self.domain_id, device_id)
        payload = {}
        resp = self.__api_request('POST', endpoint, payload)
        return resp

    def siql_query(self, query_type: str, query: str, page_size: int) -> dict:
        """
        Method to execute SIQL query of Security Manager objects
        :param query_type: What type of object to query. Options are: secrule, policy, serviceobj, networkobj, device
        :param query: SIQL query to run
        :param page_size: Number of results to return
        :return: JSON of results
        """
        endpoint = self.parser.get('REST', 'siql_query_sm_api').format(self.host, query_type)
        parameters = {'q': query, 'pageSize': page_size}
        resp = self.__api_request('GET', endpoint, None, parameters)
        return resp.json()

    def create_device_group(self, device_group_name: str):
        """
        Method to create device group in Security Manager
        :param device_group_name: name of device group
        :return: Response object
        """
        endpoint = self.parser.get('REST', 'create_device_group').format(self.host, self.domain_id)
        payload = {'name': device_group_name, 'domainId': self.domain_id}
        resp = self.__api_request('POST', endpoint, payload)
        return resp

    def add_to_device_group(self, device_group_id: str, device_id: str):
        """
        Method to add device to device group
        :param device_group_id: ID of Device Group
        :param device_id: Device ID
        :return: Response object
        """
        endpoint = self.parser.get('REST', 'add_device_to_group').format(self.host, self.domain_id, device_group_id, device_id)
        resp = self.__api_request('POST', endpoint)
        return resp

    def get_device_group_by_name(self, device_group_name: str):
        """
        Method to retrieve device group by name
        :param device_group_name: Name of Device Group
        :return: Response object
        """
        endpoint = self.parser.get('REST', 'get_device_group_name').format(self.host, self.domain_id, device_group_name)
        resp = self.__api_request('GET', endpoint)
        return resp

    def zone_search(self, device_id: str, page_size: int) -> dict:
        """
        Method to retrieve zones for device
        :param device_id: Device ID
        :param page_size: Number of results to return
        :return: JSON of results
        """
        endpoint = self.parser.get('REST', 'zone_search_sm_api').format(self.host, self.domain_id, device_id)
        parameters = {'pageSize': page_size}
        resp = self.__api_request('GET', endpoint, None, parameters)
        return resp.json()

    def get_fw_obj(self, obj_type: str, device_id: str, match_id: str) -> dict:
        """
        Method to retrieve firewall object JSON
        :param obj_type: Type of firewall object. Options: NETWORK, SERVICE, ZONE, APP, PROFILE, SCHEDULE, URL_MATCHER, USER
        :param device_id: Device ID
        :param match_id: Match ID of targeted object
        :return: Firewall object JSON
        """
        endpoint = self.parser.get('REST', 'fw_obj_sm_api').format(self.host, obj_type, device_id, match_id)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def get_device_obj(self, device_id: str) -> dict:
        """
        Method to retrieve device object JSON
        :param device_id: Device ID
        :return: Device object JSON
        """
        endpoint = self.parser.get('REST', 'dev_obj_sm_api').format(self.host, self.domain_id, device_id)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def add_supp_route(self, device_id: str, supplemental_route: dict):
        """
        Method to add Supplemental Route to Device
        :param device_id: ID of device
        :param supplemental_route: JSON of Supplemental Route
        :return: List containing status code, reason, json
        """
        verify_route_json(supplemental_route)
        endpoint = self.parser.get('REST', 'supp_route_sm_api').format(self.host, device_id)
        resp = self.__api_request('POST', endpoint, supplemental_route)
        return resp

    def get_rule_doc(self, device_id: str, rule_id: str) -> dict:
        """
        Method to retrieve rule documentation
        :param device_id: ID of device
        :param rule_id: ID of rule
        :return: JSON response
        """
        endpoint = self.parser.get('REST', 'get_rule_doc').format(self.host, self.domain_id, device_id, rule_id)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def update_rule_doc(self, device_id: str, rule_doc: dict):
        """
        Method to update rule documentation
        :param device_id: ID of device
        :param rule_doc: Rule Doc JSON
        :return: JSON response code and reason as list
        """
        endpoint = self.parser.get('REST', 'update_rule_doc').format(self.host, self.domain_id, device_id)
        resp = self.__api_request('PUT', endpoint, rule_doc)
        return resp

    def get_all_users(self, page_size=20) -> dict:
        """
        Method to retrieve all users
        :param page_size: Number of results, defaulted to 20
        :return: JSON response
        """
        endpoint = self.parser.get('REST', 'get_all_users').format(self.host, self.domain_id, page_size)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def get_user_by_username(self, username: str, page_size=20) -> dict:
        """
        Method to retrieve user by username
        :param username: Username to search for
        :param page_size: Number of results, defaulted to 20
        :return: JSON response
        """
        endpoint = self.parser.get('REST', 'user_by_username').format(self.host, self.domain_id, page_size, username)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def get_user_groups(self, page_size=20) -> dict:
        """
        Method to retrieve all user groups
        :param page_size: Number of results, defaulted to 20
        :return: JSON response
        """
        endpoint = self.parser.get('REST', 'get_user_groups').format(self.host, self.domain_id, page_size)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def get_users_in_user_group(self, user_group_id: str, page_size=20) -> dict:
        """
        Method to retrieve all user groups
        :param page_size: Number of results, defaulted to 20
        :param user_group_id: ID of user group to query
        :return: JSON response
        """
        endpoint = self.parser.get('REST', 'get_users_in_user_groups').format(self.host, self.domain_id, user_group_id, page_size)
        resp = self.__api_request('GET', endpoint)
        return resp.json()

    def add_user_to_user_group(self, user_group_id: str, user_id: str):
        """
        Method to add user to user group
        :param user_group_id: ID of user group to add user to
        :param user_id: ID of user to add to user group
        :return: Response object
        """
        endpoint = self.parser.get('REST', 'assign_to_user_group').format(self.host, self.domain_id, user_group_id, user_id)
        resp = self.__api_request('POST', endpoint)
        return resp

    def logout(self) -> list:
        """
        Method to logout of current session
        """
        self.fm_api_session.headers['Connection'] = 'Close'
        endpoint = self.parser.get('REST', 'logout_api_url').format(self.host)
        resp = self.__api_request('POST', endpoint)
        return resp

    def bulk_add_supp_route(self, f) -> int:
        """
        Bulk adding Supplemental Routes via formatted text file
        :param f: file stream
        :return: 0
        """
        csv_reader = csv.reader(f, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                print("Starting Bulk Supplemental Route Import...")
                line_count += 1
            else:
                line_count += 1
                upload = self.add_supp_route(row[0], build_route_json(row))
                print("Line " + str(line_count) + ":", upload[0], upload[1])
        print(f'Processed {line_count} lines.')
        return 0

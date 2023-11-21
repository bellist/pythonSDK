import requests
import authenticate_user
from security_manager_apis.get_properties_data import get_properties_data


class OrchestrationApis:
    """ Adding code for calling orchestration APIs """

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool, domain_id: str, suppress_ssl_warning=False):
        """ User needs to pass host,username,password,and verify_ssl as parameters while
        creating instance of this class and internally Authentication class instance
        will be created which will set authentication token in the header to get firemon API access """
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

    def rulerec_api(self, params: dict, req_json: dict) -> dict:
        """ Calling orchestration rulerec api by passing json data as request body, headers, params and domainId 
            which returns you list of rule recommendations for given input as response"""
        rulerec_url = self.parser.get('REST', 'rulerec_api_url').format(self.host, self.domain_id)
        resp = self.__api_request('POST', rulerec_url, req_json, params)
        return resp.json()

    def pca_api(self, device_id: str, change_json: list) -> dict:
        """ Calling orchestration pca api by passing json data as request body, headers, deviceId and domainId 
            which returns you pre-change assessments for the given device """
        control_list = 'controlType=RULE_SEARCH&controlType=ALLOWED_SERVICES&controlType=SERVICE_RISK_ANALYSIS&controlType=DEVICE_ACCESS_ANALYSIS&controlType=NETWORK_ACCESS_ANALYSIS'
        pca_url = self.parser.get('REST', 'pca_api_url').format(self.host, self.domain_id, device_id, control_list)
        resp = self.__api_request('POST', pca_url, change_json)
        return resp.json()

    def logout(self) -> list:
        """
        Method to logout of current session
        """
        self.fm_api_session.headers['Connection'] = 'Close'
        endpoint = self.parser.get('REST', 'logout_api_url').format(self.host)
        resp = self.__api_request('POST', endpoint)
        return resp

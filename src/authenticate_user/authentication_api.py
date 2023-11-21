""" This module does user authentication """
import requests

headers = {
    'Accept': 'applicationjson',
    'Content-Type': 'application/json'
}


class Authentication:

    def __init__(self, host, username, password, verify_ssl):
        self.host = host
        self.username = username
        self.password = password
        self.fm_session = requests.session()
        self.fm_session.verify = verify_ssl
        self.BASE_AUTH_URL = "{}/securitymanager/api/authentication/login"

    def __api_request(self, method: str, endpoint: str, payload=None, parameters=None, data=None):
        try:
            resp = self.fm_session.request(method, endpoint, json=payload, params=parameters, data=data, )
            resp.raise_for_status()
            return resp
        except requests.exceptions.HTTPError:
            raise

    def get_auth_token(self):
        """ 
            User need to pass host, username, password, and verify_ssl as parameters while creating 
            an instance of this class and this function will be called only once due to run_once
            annotation and sets authentication token in the headers and returns the headers whenever called 
        """
        payload = {'username': self.username, 'password': self.password}
        # Security manager url
        auth_url = self.BASE_AUTH_URL.format(self.host)
        result = self.__api_request('POST', auth_url, payload)
        auth_token = result.json()
        self.fm_session.headers.update({
            'Content-Type': 'applicationjson',
            'Accept': 'applicationjson',
            'X-FM-Auth-Token': auth_token.get('token'),
        })
        return self.fm_session

""" Configuring configparser """
from configparser import ConfigParser

def get_properties_data():
    """ Returning a parser which will be used to read 
        application.properties file data """
    parser = ConfigParser()
    parser.read('./application.properties')
    return parser

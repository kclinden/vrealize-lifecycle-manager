import requests
import json
import pprint
from prettytable import PrettyTable
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # Disable SSL warning


def lcm_auth(lcmfqdn, user, password):   
    #Builds an authentication token for the user. Takes the input of the LCM server, user and password.   
    url = "https://{}/lcm/api/v1/login".format(lcmfqdn)
    payload = '{{"username":"{}","password":"{}"}}'.format(user, password)
    headers = {
        'accept': "application/json",
        'content-type': "application/json"
        }
    response = requests.request("POST", url, data=payload, headers=headers, verify=False)
    if response.status_code == 200:
        token = response.json()['token'] 
        return token
    else:
        raise Exception("Did not get status of 200 from server!")
    
def get_content_items_asTable(lcmfqdn, user, password):
    #Builds a table using PrettyTable to return LCM Content
    auth = lcm_auth(lcmfqdn, user, password)
    lcmheaders = {
        'accept': "application/json",
        'content-type': "application/json",
        'xenon-auth-cookie' : auth
        }
    url = "https://{}/cms/api/v1/content?expands=true".format(lcmfqdn)
    response = requests.request("GET", url, headers=lcmheaders, verify=False) #Invoke request to get all Contents
    return response
    #lcmtable = PrettyTable(["Name", "Package Type", "Unique ID", "Path"])
    '''
    for i in response.sortedDocuments:
        name = i['name']
        packageType = i['packageType']
        uniqueId = i['uniqueId']
        path = i['id']
     '''  
        

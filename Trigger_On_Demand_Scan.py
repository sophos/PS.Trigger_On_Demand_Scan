# Copyright 2019-2020 Sophos Limited
#
# Licensed under the GNU General Public License v3.0(the "License"); you may
# not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
# https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Trigger_On_Demand_Scan.py
# Triggers an On Demand scan for Windows workstations in a single Sophos Central console
#
# Check Log "C:\ProgramData\Sophos\Endpoint Defense\Logs\SophosScanCoordinator.log"
#
# By: Michael Curtis and Robert Prechtel
# Date: 29/6/2020
# Version 2025.7
# README: This script is an unsupported solution provided by
# Sophos Professional Services

import requests
import csv
import configparser
import json
# Import getpass for Client Secret
import getpass
# Import datetime modules
from datetime import date
from datetime import datetime
#Import OS to allow to check which OS the script is being run on
import os
# Get todays date and time
today = date.today()
now = datetime.now()
timestamp = str(now.strftime("%d%m%Y_%H-%M-%S"))
# This list will hold all the computers
list_of_machines_in_central = []
# Allows colour to work in Microsoft PowerShell
os.system("")

# Class to add colours to the console output
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Get Access Token - JWT in the documentation
def get_bearer_token(client, secret, url):
    d = {
                'grant_type': 'client_credentials',
                'client_id': client,
                'client_secret': secret,
                'scope': 'token'
            }
    request_token = requests.post(url, auth=(client, secret), data=d)
    json_token = request_token.json()
    #headers is used to get data from Central
    headers = {'Authorization': f"Bearer {json_token['access_token']}"}
    #post headers is used to post to Central
    post_headers = {'Authorization': f"Bearer {json_token['access_token']}",
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }
    return headers, post_headers

def get_whoami():
    # We now have our JWT Access Token. We now need to find out if we are a Partner or Organization
    # Partner = MSP
    # Organization = Sophos Central Enterprise Dashboard
    # The whoami URL
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    request_whoami = requests.get(whoami_url, headers=headers)
    whoami = request_whoami.json()
    # MSP or Sophos Central Enterprise Dashboard
    # We don't use this variable in this script. It returns the organization type
    # Oraganization_Type = whoami["idType"]
    organization_id = whoami["id"]
    # Get the tennant Region
    region_url = whoami.get('apiHosts', {}).get("dataRegion", None)
    return organization_id, region_url

def get_all_computers(tenant_token, url):
    # Get all Computers from sub estates
    pagesize = 500
    #url = (f"{url}{'/endpoints?pageSize=500&view=full'}")
    # computers_url = (f"{url}{'/endpoints?pageSize=500&view=full'}")
    url = f"{url}{'/endpoints?pageSize='}{pagesize}{'&sort=id:desc'}{'&view=full'}"
    computers_url = url
    # Loop while the page_count is not equal to 0. We have more computers to query
    page_count = 1
    while page_count != 0:
        # Tenant to be searched
        tenant_id = tenant_token
        #Add X-Tenant-ID to the headers dictionary
        headers['X-Tenant-ID'] = tenant_id
        #Add X-Tenant-ID to the post_headers dictionary
        post_headers['X-Tenant-ID'] = tenant_id
        # Request all Computers
        request_computers = requests.get(computers_url, headers=headers)
        # Convert to JSON
        computers_json = request_computers.json()
        # Set the keys you want in the list
        #computer_keys = ('id', 'hostname', 'lastSeenAt', 'Sub Estate', 'type')
        #Add the computers to the computers list
        for all_computers in computers_json["items"]:
            if all_computers['type'] == 'computer' and all_computers['os']['platform'] == 'windows':
                # endpoint_id, native_machine_id = make_valid_client_id(all_computers['type'], all_computers['id'])
                result_code = trigger_scan(all_computers['id'], post_headers)
                if result_code.status_code == 201:
                    print(f"{bcolors.OKGREEN}{'Scanning set on machine: '}{all_computers['hostname']}{'. Machine ID: '}{all_computers['id']}{bcolors.ENDC}")
                else:
                    print(f"{bcolors.FAIL}{'Scanning failed to be set on machine: '}{all_computers['hostname']}{'. Machine ID: '}{all_computers['id']}{bcolors.ENDC}")
        # This line allows you to debug on a certain computer. Add computer name
            if 'mc-nuc-dciiii' == all_computers['id']:
                print('Add breakpoint here')
        # Check to see if you have more than 500 machines by checking if nextKey exists
        # We need to check if we need to page through lots of computers
        if 'nextKey' in computers_json['pages']:
            next_page = computers_json['pages']['nextKey']
            # Change URL to get the next page of computers
            # Example https://api-us01.central.sophos.com/endpoint/v1/endpoints?pageFromKey=<next-key>
            computers_url = f"{url}{'&pageFromKey='}{next_page}"
        else:
            # If we don't get another nextKey set page_count to 0 to stop looping
            page_count = 0

def trigger_scan(native_machine_id, post_header):
    full_endpoint_url = f"{tenant_endpoint_url}{'/'}{'endpoints/'}{native_machine_id}{'/'}{'scans'}"
    # It seems you have to send blank data to the API
    on_demand_status = {}
    result = requests.post(full_endpoint_url, data=json.dumps(on_demand_status), headers=post_header)
    return result

def read_config():
    config = configparser.ConfigParser()
    config.read('Trigger_On_Demand_Scan.config')
    config.sections()
    client_id = config['DEFAULT']['ClientID']
    client_secret = config['DEFAULT']['ClientSecret']
    if client_secret == '':
        client_secret = getpass.getpass(prompt='Enter Client Secret: ', stream=None)
    # ReportName = config['REPORT']['ReportName']
    # ReportFilePath = config['REPORT']['ReportFilePath']
    return(client_id,client_secret)

clientID, clientSecret = read_config()
# full_report_path = f"{report_file_path}{report_name}{timestamp}{'.csv'}"

token_url = 'https://id.sophos.com/api/v2/oauth2/token'
headers, post_headers = get_bearer_token(clientID, clientSecret, token_url)
# Get the tenantID
tenant_id, tenant_url = get_whoami()
tenant_endpoint_url = f"{tenant_url}{'/endpoint/v1'}"
get_all_computers(tenant_id, tenant_endpoint_url)

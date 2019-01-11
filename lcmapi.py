#!/bin/env python
import sys, os
import getopt
import requests
import getpass
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
        raise Exception("Failed while requesting authentication token!")

def get_content_items_asTable(lcmfqdn, token):
    #Builds a table using PrettyTable to return LCM Content
    lcmheaders = {
        'accept': "application/json",
        'content-type': "application/json",
        'x-xenon-auth-token' : token
        }
    url = "https://{}/cms/api/v1/content?expands=true".format(lcmfqdn)
    response = requests.request("GET", url, headers=lcmheaders, verify=False).json() #Invoke request to get all Contents

    # Initialize a pretty table
    lcmtable = PrettyTable(["Name", "Package Type", "Path"])
    # Since we're already looping over all items, lets build a useful dictionary
    content_map = {}
    for docs in response['sortedDocuments']:
        name = docs['name']
        packageType = docs['packageType']
        path = docs['id']
        lcmtable.add_row((name, packageType, path))
        content_map[name] = path
    return content_map, lcmtable

def delete_content_item(lcmfqdn, path, token):
    # Set common headers for request
    lcmheaders = {
        'accept': "application/json",
        'content-type': "application/json",
        'x-xenon-auth-token' : token
        }
    url = "https://{}{}".format(lcmfqdn, path)
    response = requests.request("DELETE", url, headers=lcmheaders, verify=False).json() #Invoke request to delete item(s)
    # Pretty print the JSON response from the delete request
    print(json.dumps(response, indent=4))

def usage():
    # Print the usage statement for the program
    print("\nUsage:")
    print("  " + os.path.basename(sys.argv[0]) + " -f <vlcm_fqdn> -u <username> -p <password> [--all|--name <content_name>|--list]")
    print("    {0:8} The FQDN of the vLCM Server. REQUIRED.").format('-f:')
    print("    {0:8} The user to use for API authentication. REQUIRED.").format('-u:')
    print("    {0:8} The password for the API user. REQUIRED.").format('-p:')
    print("    {0:8} If this option is specified all content items will be deleted.\n" \
          "{1:12} This option is mutually exclusive with --name and --list.").format('--all:', '')
    print("    {0:8} If this option is specified the named content will be deleted.\n" \
          "{1:12} The 'content_name' can be determined from the output of --list.\n" \
          "{1:12} This option can be specified multiple times to specify multiple content items\n" \
          "{1:12} to delete. This option is mutually exclusive with --all and --list.").format('--name:', '')
    print("    {0:8} If this option is specified all content items will be listed in a table.\n" \
          "{1:12} This is mutually exclusive with --name and --all.").format('--list:', '')

# Allow us to be run directly or utilized as a library of functions
if __name__ == "__main__":

    # Parse commandline options in the standard way
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "u:p:f:", ["name=", "all", "list"])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    # Initialize some datastructures for input validation
    reqs = {'-p': None, '-u': None, '-f': None}
    exclusives = {}
    names = []

    for opt, val in opts:
        # Set '-p': <password> in the required options dictionary
        if opt == '-p':
            reqs['-p'] = val
        # Set '-u': <username> in the required options dictionary
        elif opt == '-u':
            reqs['-u'] = val
        # Set '-f': <fqdn> in the required options dictionary
        elif opt == '-f':
            reqs['-f'] = val
        # Add any name values to the list of names
        elif opt == '--name':
            names.append(val)
            # Indicate that we found the --name option
            exclusives['--name'] = True
        elif opt == '--all':
            # Indicate that we found the --all option
            exclusives['--all'] = True
        elif opt == '--list':
            # Indicate that we found the --list option
            exclusives['--list'] = True

    # Here we enforce that only one of --name, --all or --list was provided
    if len(exclusives) > 1:
        l = ', '.join(exclusives.keys())
        print("More than one mutually exclusive options provided: " + l)
        usage()
        sys.exit(3)
    # Here we require that at least one of --name, --all or --list was provided
    elif len(exclusives) < 1:
        print("No operation provided.")
        usage()
        sys.exit(3)

    # Here we ensure that ALL of -p, -u and -f were provided
    for item in ['-u','-f','-p']:
        if reqs[item] == None:
            if item == '-p':
                reqs['-p'] = getpass.getpass("Enter password for {}: ".format(reqs['-u']))
            else:
                print("REQUIRED parameter \'{}\' not provided.".format(item))
                usage()
                sys.exit(4)

    # We will retrieve the token initially before any other operations
    token = lcm_auth(reqs['-f'], reqs['-u'], reqs['-p'])
    print("vLCM FQDN: " + reqs['-f'])
    print("vLCM Token: " + token)

    # If we were requested to list retrieve the pretty table and print
    if exclusives.has_key('--list'):
        cm, tab = get_content_items_asTable(reqs['-f'], token)
        print(tab)
    # If we were passed content names, we loop over them
    # dereference the name against our content map and delete
    elif exclusives.has_key('--name'):
        cm, tab = get_content_items_asTable(reqs['-f'], token)
        for name in names:
            # If the user provided a name that doesn't exist we'll
            # handle it elegantly instead of failing.
            try:
                path = cm[name]
            except KeyError as e:
                print("Content name ({}) not found.".format(name))
                continue
            print(name + ': ' + cm[name])
            delete_content_item(reqs['-f'], cm[name], token)
    # If we were requested to delete all content items we
    # loop over the content map and delete each item
    elif exclusives.has_key('--all'):
        cm, tab = get_content_items_asTable(reqs['-f'], token)
        for name, path in cm.iteritems():
            print(name + ': ' + path)
            delete_content_item(reqs['-f'], path, token)

import azure.cosmos.cosmos_client as cosmos_client
import io
import json
import os
import requests
import time

from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from pathlib import Path

####################
# GLOBAL VARIABLES #
####################



##########################################################################
#
# Function name: main
# Input: None.
# Output: TBD
#
# Purpose: Connect to COSMOS DB and retrieve list of malicious URLs for
#          dissemination.
#
##########################################################################
def main():

    print ("***** Retrieve state information for each URL submitted to Netcraft *****")

    uuids = get_netcraft_uuids_from_cosmos()
    netcraft_characterization_results = check_URLs_state_netcraft_by_UUID(uuids)
    sort_netcraft_results(netcraft_characterization_results)
    
##########################################################################
#
# Function name: sort_netcraft_results
# Input: dictionary of netcraft results returned by API call.
# Output: n/a
#
# Purpose: To sort and view the aggregated results returned by netcraft
#          per classification bin.
#
#
##########################################################################
def sort_netcraft_results(netcraft_characterization_results):
    print ("***** Sort Netcraft Characterization Results *****\n")

    print ("***** Malicious URLs Returned *****\n")
    for url, state in sorted(netcraft_characterization_results.items()):
        print (url, state)

    # keys by value:
    #      - processing
    #      - no threats
    #      - unavailable
    #      - phishing
    #      - already blocked
    #      - suspicious
    #      - malware
    #      - rejected (was already submitted)

    print ("\n***** PHISHING *****")
    phishing_results = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "phishing"]
    print(len(phishing_results))
    print (phishing_results)

    print ("\n***** ALREADY BLOCKED *****")
    already_blocked = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "already blocked"]
    print(len(already_blocked))
    print (already_blocked)

    print ("\n***** NO THREATS *****")
    no_threats = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "no threats"]
    print(len(no_threats))
    print (no_threats)
    
    print ("\n***** SUSPICIOUS *****")
    suspicious_results = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "suspicious"]
    print(len(suspicious_results))
    print (suspicious_results)

    print ("\n***** MALWARE *****")
    malware_results = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "malware"]
    print(len(malware_results))
    print (malware_results)

    print ("\n***** PROCESSING *****")
    processing = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "processing"]
    print(len(processing))
    print (processing)

    print ("\n***** UNAVAILABLE *****")
    unavailable = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "unavailable"]
    print(len(unavailable))
    print (unavailable)

    print ("\n***** REJECTED *****")
    rejected = [url for url, status in netcraft_characterization_results.items() if status['characterization'] == "rejected"]
    print(len(rejected))
    print (rejected)
    
##########################################################################
#
# Function name: get_NETCRAFT_uuids_from_Cosmos
# Input:
# Output:
#
# Purpose: Connect to the COSMOS DB.
#
##########################################################################
def get_netcraft_uuids_from_cosmos():

    print ("\n***** Connect to COSMOS DB *****\n")
    uri          = os.environ.get('ACCOUNT_URI')
    key          = os.environ.get('ACCOUNT_KEY')
    database_id  = os.environ.get('DATABASE_ID')
    container_id = os.environ.get('CONTAINER_ID')

    client = cosmos_client.CosmosClient(uri, {'masterKey': key})
    container_link = "dbs/" + database_id + "/colls/" + container_id
    print ("Container link: " + container_link)


    #date_str = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    current_date = datetime.now()
    date_yesterday = current_date - timedelta(days=1)

    #print('Today: ' + current_date.strftime('%Y-%m-%d %H:%M:%S'))
    #print('Yesterday: ' + date_yesterday.strftime('%Y-%m-%d %H:%M:%S'))

    print ("Query db for UUIDs since yesterday\n")

    yesterday  = int((datetime.utcnow() - relativedelta(days=1)).timestamp())

    print(str(yesterday))

    query = 'SELECT DISTINCT VALUE c.id FROM c WHERE c._ts > {}'.format(str(yesterday))
    uuid_query_results = set(client.QueryItems(container_link,
                                       query,
                                       {"enableCrossPartitionQuery": True}))

    print (uuid_query_results)

    return uuid_query_results
    
##########################################################################
#
# Function name: check_URLs_state_netcraft_bulk
# Input: uuid returned from Netcraft submission,
#
# Output:
#
# Purpose: to check the characterization of each URL submitted to
#          Netcraft.
#          Possible results:
#          - processing
#          - no threats
#          - unavailable
#          - phishing
#          - already blocked
#          - suspicious
#          - malware
#          - rejected (was already submitted)
#
##########################################################################
def check_URLs_state_netcraft_by_UUID(uuid_list):

    print("\n***** Query Netcraft for URL classification by UUID *****\n")

    URL_characterization_results = {}

    for uuid in uuid_list:
        print("\n***** " + uuid + " *****")
        # submit GET request to Netcraft for each UUID identified above
        # The below link is for development.  Once deployed, use:
        netcraftSubmissionCheck_url = "https://report.netcraft.com/api/v2/submission/" + str(uuid) + "/urls"
        #netcraftSubmissionCheck_url = "https://report.netcraft.com/api/v2/test/submission/" + uuid_str + "/urls"

        print ("Netcraft API call: " + netcraftSubmissionCheck_url)

        # Check URLs with netcraft service
        headers = {'Content-type': 'application/json'}
        request_data = {};

        # Check URLs with netcraft service
        r_get = requests.get(netcraftSubmissionCheck_url, json=request_data, headers=headers)

        print("Netcraft submission check response status code (" + str(uuid) + "): " + str(r_get.status_code))
        #print(r_get.json())
        
        if r_get.status_code == 200:
            if r_get.json() == {}:
                print("No results available.")

            else:
                print("Results for uuid:", str(uuid), " available.")
                # Get results
                for entry in r_get.json()['urls']:
#                    print(entry)
                    url = entry['url']
                    url_state = entry['url_state']

                    URL_characterization_results[url]={'characterization':url_state}

    return URL_characterization_results

if __name__ == "__main__":
    main()

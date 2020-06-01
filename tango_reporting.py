import io
import json
import os
import requests
import time

from azure.cosmos import CosmosClient
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

    netcraft_characterizatin_results_json = {}
    uuids_list = []

    uuids_list = get_netcraft_uuids_from_cosmos()

    print ("**** UUID List ****")
    for uuid in uuids_list:
        print (uuid)   
 
    if len(uuids_list) != 0:
        netcraft_characterization_results_json = check_URLs_state_netcraft_by_UUID(uuids_list)
    
    sort_netcraft_results(netcraft_characterization_results_json) 

##########################################################################
#
# Function name: sort_netcraft_results
# Input: dictionary of netcraft results returned by API call. 
# Output: dictionary to be saved in Cosmos
#
# Purpose: To sort and view the aggregated results returned by netcraft
#          per classification bin.
#          
#
##########################################################################
def sort_netcraft_results(netcraft_characterization_results):
    print ("***** Sort Netcraft Characterization Results *****\n")

    # keys by value: 
    #      - processing
    #      - no threats
    #      - unavailable
    #      - phishing
    #      - already blocked
    #      - suspicious
    #      - malware
    #      - rejected (was already submitted)

    phishing_results   = []
    already_blocked    = []
    no_threats         = []
    suspicious_results = []
    malware_results    = []
    processing         = []
    unavailable        = []
    rejected           = []

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

    print ("\n***** Add UUID to the COSMOS DB *****\n")
    uri          = os.environ.get('ACCOUNT_URI')
    key          = os.environ.get('ACCOUNT_KEY')
    database_id  = os.environ.get('DATABASE_ID')
    container_id = os.environ.get('RESULTS_CONTAINER_ID')

    client = CosmosClient(uri, {'masterKey': key})
    print (client)

    database = client.get_database_client(database_id)
    container = database.get_container_client(container_id)

    # Get date
    date_str = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    id_date  = int((datetime.utcnow()).timestamp())
    id_date_str = str(id_date)

    all_phishing_results_str   = ' '.join(map(str, phishing_results))
    all_already_blocked_str    = ' '.join(map(str, already_blocked))
    all_no_threats_str         = ' '.join(map(str, no_threats))
    all_suspicious_results_str = ' '.join(map(str, suspicious_results))
    all_malware_results_str    = ' '.join(map(str, malware_results))
    all_processing_str         = ' '.join(map(str, processing))
    all_unavailable_str        = ' '.join(map(str, unavailable))
    all_rejected_str           = ' '.join(map(str, rejected))

    print ("**** Write new record to Cosmos DB ****\n")

    print ("id: " + id_date_str)
    print ("date_time: " + id_date_str)
    print ("date: " + date_str)
    print ("n_phishig: " + str(len(phishing_results)))
    print ("phishing: " + all_phishing_results_str)
    print ("n_blocked: " + str(len(already_blocked)))
    print ("already_blocked: " + all_already_blocked_str)
    print ("n_nothreat: " + str(len(no_threats)))
    print ("nothreat: " + all_no_threats_str)
    print ("n_suspicious: " + str(len(suspicious_results)))
    print ("suspicious: " + all_suspicious_results_str)
    print ("n_malware: " + str(len(malware_results)))
    print ("malware: " + all_malware_results_str)
    print ("n_processing: " + str(len(processing)))
    print ("processing: " + all_processing_str)
    print ("n_unavailable: " + str(len(unavailable)))
    print ("unavailable: " + all_unavailable_str)
    print ("n_rejected: " + str(len(rejected)))
    print ("rejected: " + all_rejected_str)

    container.upsert_item( { 'id': id_date_str,
                             'date_time': id_date_str,
                             'date': date_str,
                             'n_phishing': str(len(phishing_results)),
                             'phishing': all_phishing_results_str,
                             'n_blocked': str(len(already_blocked)),
                             'already_blocked': all_already_blocked_str,
                             'n_nothreat': str(len(no_threats)),
                             'nothreat': all_no_threats_str,
                             'n_suspicious': str(len(suspicious_results)),
                             'suspicious': all_suspicious_results_str,
                             'n_malware': str(len(malware_results)),
                             'malware': all_malware_results_str,
                             'n_processing': str(len(processing)),
                             'processing': all_processing_str,
                             'n_unavailable': str(len(unavailable)),
                             'unavailable': all_unavailable_str,
                             'n_rejected': str(len(rejected)),
                             'rejected': all_rejected_str })



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
    container_id = os.environ.get('UUID_CONTAINER_ID')

    client = CosmosClient(uri, {'masterKey': key})
    print (client)

    database = client.get_database_client(database_id)
    container = database.get_container_client(container_id)

    client = CosmosClient(uri, {'masterKey': key})

    date_str = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    current_date = datetime.now()
    date_yesterday = current_date - timedelta(days=1)

    #print('Today: ' + current_date.strftime('%Y-%m-%d %H:%M:%S'))
    #print('Yesterday: ' + date_yesterday.strftime('%Y-%m-%d %H:%M:%S'))

    print ("Query db for UUIDs since yesterday\n")

    yesterday  = int((datetime.utcnow() - relativedelta(days=1)).timestamp())

    #print(str(yesterday))

    query = 'SELECT DISTINCT VALUE c.id FROM c WHERE c._ts > {}'.format(str(yesterday))
    uuid_query_results = list(container.query_items(query, enable_cross_partition_query = True))

    print (uuid_query_results)

    #for result in uuid_query_results:
    #    print (json.dumps(result, indent=True))

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
        #uuid = json.dumps(result, indent=True).strip('\"')  

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

    print ("**** URL Characterization Results from Netcraft ****")
    for k,v in URL_characterization_results.items():
        print (k,v)

    return URL_characterization_results



if __name__ == "__main__":
    main()


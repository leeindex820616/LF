from datetime import datetime, timedelta
import pymongo
from tqdm import tqdm
from datetime import datetime
import requests
import json
from json import loads
import linecache
import time
import getpass
import socket
import pandas as pd
pd.set_option('display.max_rows', 800)
pd.set_option('display.max_columns', 800)

def Selection_Menu():
    print('--'*20)
    print('UltraDNS API Script..')
    print('--'*20)
    print("Process Menu\n")
    print("[1] Process for Check DNS Records for cdn1\n")
    print("[2] Process for Flush China Only for cdn1\n")
    print("[3] Process for Check DNS Records for cdn4\n")
    print("[4] Process for Flush China Only for cdn4\n")
    #print("[5] Process for Check China Only for test domains\n")
    #print("[6] Process for Flush China Only for test domains\n")

    domainlist = ""
    if len(Ultradns_login) > 0:
        while True:
            Selection_input = input("Selection (leave blank to quit): ")
            if Selection_input == "1":
                db = myclient["china_https"]
                Collection = db["domains_https"]
                china_https_domainlist = []
                for doc in Collection.find({}, {'_id': False}):
                    china_https_domainlist += doc['Domain'].split('\n')

                domainlist = china_https_domainlist
                CheckDNSrecords(domainlist)
                break
            elif Selection_input == "2":
                db = myclient["china_https"]
                Collection = db["domains_https"]
                china_https_domainlist = []
                for doc in Collection.find({}, {'_id': False}):
                    china_https_domainlist += doc['Domain'].split('\n')

                domainlist = china_https_domainlist
                FlushChinaOnly(domainlist)
                CheckDNSrecords(domainlist)
                break
            elif Selection_input == "3":
                db = myclient["china_non_https"]
                Collection = db["domains_no_https"]
                china_non_https_domainlist = []
                for doc in Collection.find({}, {'_id': False}):
                    china_non_https_domainlist += doc['Domain'].split('\n')

                domainlist = china_non_https_domainlist
                CheckDNSrecords(domainlist)
                break
            elif Selection_input == "4":
                db = myclient["china_non_https"]
                Collection = db["domains_no_https"]
                china_non_https_domainlist = []
                for doc in Collection.find({}, {'_id': False}):
                    china_non_https_domainlist += doc['Domain'].split('\n')

                domainlist = china_non_https_domainlist
                FlushChinaOnly(domainlist)
                CheckDNSrecords(domainlist)
                break
            #elif Selection_input == "5":
            #    db = myclient["test_domains"]
            #    Collection = db["test_domains"]
            #    china_https_domainlist = []
            #    for doc in Collection.find({}, {'_id': False}):
            #        china_https_domainlist += doc['Domain'].split('\n')
#
            #    domainlist = china_https_domainlist
            #    CheckDNSrecords(domainlist)
            #    break                
            #elif Selection_input == "6":
            #    db = myclient["test_domains"]
            #    Collection = db["test_domains"]
            #    china_non_https_domainlist = []
            #    for doc in Collection.find({}, {'_id': False}):
            #        china_non_https_domainlist += doc['Domain'].split('\n')
#
            #    domainlist = china_non_https_domainlist
            #    FlushChinaOnly(domainlist)
            #    break                
            else:
                print("invalid Selection, Press any to exit...:")
                exit()

def CheckDNSrecords(domainlist):
    output_dict = []
    for domain in tqdm(domainlist, desc='listing..records..'):
        try:
            response_www = requests.get(
                'https://api.ultradns.com/zones/' + domain + '/rrsets/A/www.' + domain, headers=headers)
            response_www.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print("requests exception found: ", err)
        else:
            DNSJSON_www = response_www.json()

            #print(json.dumps(DNSJSON_www['rrSets'][0], indent=4, sort_keys=True))
            dns_record_data = DNSJSON_www['rrSets'][0]['rdata']

            # https://stackoverflow.com/questions/4843158/how-to-check-if-a-string-is-a-substring-of-items-in-a-list-of-strings
            # to check if there is china only cdn record, if yes, starting get root domain dns data.
            if any("cdn" in s for s in dns_record_data):
                for i in range(len(DNSJSON_www['rrSets'][0]['profile']['rdataInfo'])):
                    # if str(DNSJSON_www['rrSets'][0]['profile']['rdataInfo'][i]['geoInfo']['codes']).find("\'CN\'") != -1:
                    if str(DNSJSON_www['rrSets'][0]['profile']['rdataInfo'][i]['geoInfo']).find("\'CN\'") != -1:
                        www_CN_sequence = i

                try:
                    response = requests.get(
                        'https://api.ultradns.com/zones/' + domain + '/rrsets/A/' + domain, headers=headers)
                    response.raise_for_status()
                except requests.exceptions.HTTPError as err:
                    print("\n" + "requests exception found: ", err)
                    '''
                if response.status_code == 400:
                    print("error code:", response.status_code, err)
                if response.status_code == 401:
                    print("Unauthorized, token invalid to "+domain)
                if response.status_code == 404:
                    print("API No found "+domain)
                if response.status_code == 403:
                    print("Forbidden, API incorrect "+domain)
                if response.status_code == 200:
                    pass
                    '''
                else:
                    DNSJSON = response.json()

                    #print(json.dumps(DNSJSON['rrSets'][0], indent=4, sort_keys=True))
                    for i in range(len(DNSJSON['rrSets'][0]['profile']['rdataInfo'])):
                        # if '\'CN\'' in str(DNSJSON['rrSets'][0]['profile']['rdataInfo'][i]['geoInfo']['codes']):
                        if str(DNSJSON['rrSets'][0]['profile']['rdataInfo'][i]['geoInfo']).find("\'CN\'") != -1:
                            CN_sequence = i
                            domain_str = domain
                            CN_IP_str = DNSJSON['rrSets'][0]['rdata'][CN_sequence]
                            CN_CNAME_str = dns_record_data[www_CN_sequence]
                            #output_dict[domain_str] = domain_str, CN_IP_str, CN_CNAME_str
                            output_dict += [[domain_str,
                                             CN_IP_str, CN_CNAME_str]]

                    for i in range(len(DNSJSON['rrSets'][0]['profile']['rdataInfo'])):
                        if str(DNSJSON['rrSets'][0]['profile']['rdataInfo'][i]['geoInfo']).find("\'CN\'") == 0:
                            print("domain: " + domain + " CN IP: N/A")
            else:
                print("\n" + "domain: " + domain + " no matches cdn domains")

    # print(output_dict)
    df = pd.DataFrame(output_dict, columns=['domain', 'CN IP', 'CN CNAME'])
    print(df)

    Selection_Menu()

def FlushChinaOnly(domainlist):
    db = myclient["ultradnstest"]
    Collection = db["data"]
    cdn1IP = 'cdn1.dwdns3.services.'  # non-https
    cdn2IP = 'cdn2.dwdns3.services.'  # non-https
    cdn3IP = 'cdn3.dwdns3.services.'  # non-https, default
    cdn5IP = 'cdn5.dwdns3.services.'  # non-https
    cdn6IP = 'cdn6.dwdns3.services.'  # non-https
    BackupFileName = 'UltrDNS-Backup-Records' + current_time
    BackupPatchName = 'UltrDNS-Backup-PatchJson' + current_time
    # for china only
    # request record data of domain
    # for domain in tqdm((domainlist), desc='reflush records'):
    for domain in domainlist:
        try:
            response_www = requests.get(
                'https://api.ultradns.com/zones/' + domain + '/rrsets/A/www.' + domain, headers=headers)
            response_www.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print("requests exception found: ", err)
        else:
            DNSJSON_www = response_www.json()
            json_decoded_www = DNSJSON_www
            # to follow mongodb's GMT+0 timestamp.
            json_decoded_www['timestamp'] = datetime.now() - timedelta(hours=8)
            json_decoded_www['user'] = username
            x = Collection.insert_one(json_decoded_www)
            DNSJSON_www = response_www.json()
            #print(json.dumps(DNSJSON_www['rrSets'][0], indent=4, sort_keys=True))
            dns_record_data = DNSJSON_www['rrSets'][0]['rdata']

            if any("cdn" in s for s in dns_record_data):
                for i in range(len(DNSJSON_www['rrSets'][0]['profile']['rdataInfo'])):
                    # if str(DNSJSON_www['rrSets'][0]['profile']['rdataInfo'][i]['geoInfo']['codes']).find("\'CN\'") != -1:
                    if str(DNSJSON_www['rrSets'][0]['profile']['rdataInfo'][i]['geoInfo']).find("\'CN\'") != -1:
                        www_CN_sequence = i
                        # print(dns_record_data[www_CN_sequence])
                cdn_value = ""

                if(str(dns_record_data[www_CN_sequence]) == "cdn1.dwdns2.services."):
                    cdn_value = "cdn1"
                if(str(dns_record_data[www_CN_sequence]) == "cdn2.dwdns3.services."):
                    cdn_value = "cdn2"    
                if(str(dns_record_data[www_CN_sequence]) == "cdn3.dwdns3.services."):
                    cdn_value = "cdn3"
                if(str(dns_record_data[www_CN_sequence]) == "cdn5.dwdns3.services."):
                    cdn_value = "cdn5"
                if(str(dns_record_data[www_CN_sequence]) == "cdn6.dwdns3.services."):
                    cdn_value = "cdn6"    

                try:
                    response = requests.get(
                        'https://api.ultradns.com/zones/' + domain + '/rrsets/A/www.' + domain, headers=headers)
                    response.raise_for_status()
                except requests.exceptions.HTTPError as err:
                    print("\n" + "requests exception found: ", err)
                else:
                    DNSJSON = response.json()
                    json_decoded = DNSJSON
                    json_decoded['timestamp'] = datetime.now() - \
                        timedelta(hours=8)
                    json_decoded['user'] = username
                    x = Collection.insert_one(json_decoded)
                    DNSJSON = response.json()
                    with open(BackupFileName + ".txt", 'a') as myfile:
                        myfile.write(str(DNSJSON))
                        myfile.write("\n")
                        myfile.close

                    for i in range(len(DNSJSON['rrSets'][0]['profile']['rdataInfo'])):
                        # if '\'CN\'' in str(DNSJSON['rrSets'][0]['profile']['rdataInfo'][i]['geoInfo']['codes']):
                        if str(DNSJSON_www['rrSets'][0]['profile']['rdataInfo'][i]['geoInfo']).find("\'CN\'") != -1:
                            www_CN_sequence = i
                            for index,domain1 in enumerate(DNSJSON_www['rrSets'][0]['rdata']):                 
                                if domain1 == "cdn1.dwdns2.services.":
                                    DNSJSON_www['rrSets'][0]['rdata'][index] = cdn3IP
                                if domain1 == "cdn2.dwdns2.services.":
                                    DNSJSON_www['rrSets'][0]['rdata'][index] = cdn3IP
                                if domain1 == "cdn3.dwdns2.services.":
                                    DNSJSON_www['rrSets'][0]['rdata'][index] = cdn3IP    
                                if domain1 == "cdn4.dwdns2.services.":
                                    DNSJSON_www['rrSets'][0]['rdata'][index] = cdn3IP
                                if domain1 == "cdn5.dwdns2.services.":
                                    DNSJSON_www['rrSets'][0]['rdata'][index] = cdn3IP    

                                    
                            #print(json.dumps(patch_jsonbody,indent=4, sort_keys=True))

                           # with open(BackupPatchName + ".txt", 'a') as patchfile:
                            #    patchfile.write(str(patch_jsonbody))
                            #    patchfile.write("\n")
                             #   patchfile.close
                                
                            try:
                                print(DNSJSON_www)
                                response_put = requests.put(
                                    'https://api.ultradns.com/zones/' + domain + '/rrsets/A/www.' + domain, headers=headers, json=DNSJSON_www['rrSets'][0])
                                response_put.raise_for_status()
                            except requests.exceptions.HTTPError as err:
                                print("requests exception found: ", err)
                            else:
                                if response.status_code == 200:
                                    print(
                                        "\nDomain: " + domain + " successfully updated China only CNAME records\n")
                                else:
                                    print(
                                        "\nDomain: " + domain + " failed to change China only CNAME records\n")

                    for i in range(len(DNSJSON['rrSets'][0]['profile']['rdataInfo'])):
                        if str(DNSJSON['rrSets'][0]['profile']['rdataInfo'][i]['geoInfo']).find("\'CN\'") == 0:
                            print("domain: " + domain + " CN IP: N/A")
            else:
                print("\n" + "domain: " + domain +
                      " no matches cdn domains, skip")
    CheckDNSrecords(domainlist)
    Selection_Menu()

# https://gist.github.com/wadewegner/7557434
Ultradns_login = ""
# account
username = input("Please input Ultradns Username: ")
# password
#password = getpass.getpass("Please input Ultradns Password: ")

body = {
    'grant_type': 'password',
    'username': username,
    'password': getpass.getpass("Please input Ultradns Password: ")
}

time.sleep(1)

try:
    response = requests.post(
        'https://api.ultradns.com/v2/authorization/token', headers={"Content-Type": "application/x-www-form-urlencoded"}, data=body)
    response.raise_for_status()
except requests.HTTPError as exception:
    # if response.status_code == 401:
    #    print("Unauthorized, wrong username or password")
    if response.status_code == 200:
        pass
    else:
        print(exception)
        text = input("\n" + "Login failed, Press any to exit...:")
        exit()
else:
    print("login okay.")
    Ultradns_login = "12345678"
    response_str = response.json()
    access_token = json.dumps(response_str['access_token'])
# -------------------------------------------------------------------------------------
now = datetime.now()
current_time = now.strftime("%Y-%m-%d %H%M%S")

apikey = access_token.replace('"', '')


time.sleep(1)

headers = {"Content-type": "application/json",
           "Authorization": "Bearer " + apikey
           }

'''
# test portal ultradns API
try:
    response_testportal = requests.post(
        'https://test-api.ultradns.com/v2/authorization/token', headers={"Content-Type": "application/x-www-form-urlencoded"}, data=body)
    response_testportal.raise_for_status()
except requests.HTTPError as exception:
    # if response_testportal.status_code == 401:
    #    print("Unauthorized, wrong username or password")
    if response_testportal.status_code == 200:
        pass
    else:
        print(exception)
        text = input("\n" + "Login failed, Press any to exit...:")
        exit()
else:
    print("login okay.")
    response_str = response_testportal.json()
    access_token_testportal = json.dumps(response_str['access_token'])
    apikey_testportal = access_token_testportal.replace('"', '')
headers_testportal = {"Content-type": "application/json",
           "Authorization": "Bearer " + apikey_testportal
           }
           
try:
    response_377fn = requests.get(
        'https://test-api.ultradns.com/zones/377fn.com/rrsets/', headers=headers_testportal)
    response_377fn.raise_for_status()
except requests.exceptions.HTTPError as err:
    print("requests exception found: ", err)
else:
    DNSJSON_377fn = response_377fn.json()
'''

# mongodb connection
myclient = pymongo.MongoClient('172.20.102.240:27017', username='noc_user',
                               password=getpass.getpass("Please input noc_user MongoDB Password: "))

Selection_Menu()

text = input("\n" + "Press any to exit...:")
exit()
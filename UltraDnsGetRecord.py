import requests
import json
import time
import getpass
from datetime import datetime

# Account
username = input("Please input Ultradns username: ")

# Password
password = getpass.getpass("Please input Ultradns password: ")

# Body for authentication request
body = {
    'grant_type': 'password',
    'username': username,
    'password': password
}

try:
    # Make the authentication request
    response = requests.post(
        'https://api.ultradns.com/v2/authorization/token', headers={"Content-Type": "application/x-www-form-urlencoded"}, data=body)
    response.raise_for_status()
except requests.HTTPError as exception:
    # If the response status code is not 200, raise an exception and display the error message
    if response.status_code != 200:
        print(exception)
        text = input("\n" + "Login failed, Press any key to exit...:")
        exit()
else:
    print("Login okay.")
    response_str = response.json()
    access_token = json.dumps(response_str['access_token'])



# Remove the quotes from the access token string
apikey = access_token.replace('"', '')

# Set the headers for API requests
headers = {"Content-type": "application/json",
           "Authorization": "Bearer " + apikey
           }

domain_input=[]
print('Paste the domain list(:q for quit):')
while 1:
    input_buffer=input('').strip()
    if input_buffer == '':
        continue
    elif input_buffer == ':q':
        break
    domain_input.append(input_buffer)
for domain in domain_input:
    domain=domain.strip()
    try:
        response = requests.get('https://api.ultradns.com/zones/' + domain + '/rrsets/ANY/', headers=headers)
        response.raise_for_status()
    except requests.HTTPError as exception:
        print(exception)
    else:
        records = response.json()
        with open('records' + domain+ '.json', 'w') as f:
            json.dump(records, f, indent=4)
#        print(records)
input("Press enter to exit...")
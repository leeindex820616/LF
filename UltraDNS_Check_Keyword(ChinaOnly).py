import requests
import getpass
import json
import datetime

now = datetime.datetime.now()
timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
timestamp2 = now.strftime("%Y-%m-%d")
filename = "zones_" + timestamp + ".txt"

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
refreshkey = None

def Ultra_login_refresh():
    global refreshkey, body_refresh, headers
    if refreshkey is None:
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
            refresh_token = json.dumps(response_str['refresh_token'])

        # Remove the quotes from the access token string
        apikey = access_token.replace('"', '')
        refreshkey = refresh_token.replace('"', '')
        # Set the headers for API requests
        headers = {"Content-type": "application/json",
                   "Authorization": "Bearer " + apikey
                   }

        body_refresh = {
            'grant_type': 'refresh_token',
            'refresh_token': refreshkey
        }
    
        return headers, body_refresh
    else:
        response = requests.post(
            'https://api.ultradns.com/v2/authorization/token', headers={"Content-Type": "application/x-www-form-urlencoded"}, data=body_refresh)
        response.raise_for_status()
        response_str = response.json()
        access_token = json.dumps(response_str['access_token'])
        refresh_token = json.dumps(response_str['refresh_token'])
        apikey = access_token.replace('"', '')
        refreshkey = refresh_token.replace('"', '')
        headers = {"Content-type": "application/json",
            "Authorization": "Bearer " + apikey
            }

        body_refresh = {
            'grant_type': 'refresh_token',
            'refresh_token': refreshkey
        }
        return headers, body_refresh
Ultra_login_refresh()

# Call Ultra_login_refresh and store the returned headers in a variable
headers, body_refresh = Ultra_login_refresh()

# The URL to retrieve the zones
url = "https://api.ultradns.com/v3/zones?limit=1000"
keyword_input = input("Enter the keyword to search for in DNS records: ")
while True:
    # Make the API request
    response = requests.get(url, headers=headers)
    data = response.json()
    zones = data.get('zones', [])
    for zone in zones:
        name = zone.get("properties", {}).get("name", "")
        print(name)
        with open(filename, "a") as f:
            f.write(name + "\n")
    cursor_info = data.get('cursorInfo', {})
    next_cursor = cursor_info.get('next')
    if not next_cursor:

        with open(filename, "r") as c:
            for domain in c:
                domain = domain.strip()
                try:
                    response = requests.get(
                        'https://api.ultradns.com/zones/' + domain + '/rrsets/ANY/', headers=headers)
                    response.raise_for_status()
                except requests.HTTPError as exception:
                    print(exception)
                    if exception.response.status_code == 401:
                        Ultra_login_refresh()
                        continue

                else:
                    records = response.json()
                    filtered_rrsets = [
                        rrset for rrset in records['rrSets'] if keyword_input in rrset['rdata'][0]]
                    owner_names = [rrset['ownerName']
                                   for rrset in filtered_rrsets]
                    print(owner_names)
                    with open("ownerNames_keyword_" + keyword_input + "_" + timestamp2 + ".txt", "a") as f:
                        for owner_name in owner_names:
                            f.write(owner_name + "\n")
        break

    # There is a next cursor, so continue to retrieve results
    else:
        url = "https://api.ultradns.com/v3/zones?limit=1000&cursor={}".format(
            next_cursor)

input("Press enter to exit...")

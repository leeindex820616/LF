import requests
import getpass
import json
import datetime
now = datetime.datetime.now()
timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
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


# The URL to retrieve the zones
url = "https://api.ultradns.com/v3/zones?limit=1000"

while True:
    # Make the API request
#    cursor = None
#    params = {'limit':limit,'cursor':cursor}
    response = requests.get(url, headers=headers)
    data = response.json()
    zones = data.get('zones', [])
    cursor_info = data.get('cursorInfo', {})
    for zone in zones:
        name = zone.get("properties", {}).get("name", "")
        print(name)
        with open(filename, "a") as f:
            f.write(name + "\n")
 #   if data:
 #       for result in data:
 #           result = json.loads(response.text)
 #           zones = result.get('zones', [])
 #           cursorinfo = result.get('cursorinfo', [])
 #           for zone in zones:
 #               properties = zone.get('properties', {})
 #               name = properties.get('name', '')
 #               print(name)
 #
 #               with open("zones.txt", "a") as f:
 #                   f.write(name + "\n")
  #  cursor_info = result.get('cursorInfo', {})
    next_cursor = cursor_info.get('next')
    if not next_cursor:
        break
        # There is a next cursor, so continue to retrieve results               
    else:
        url = "https://api.ultradns.com/v1/zones?limit=1000&cursor={}".format(next_cursor)
        # No more results to retrieve, so exit the loop
        #    for cursor in cursorinfo:
         #       cursors = cursor.get('next', '')
          #      print(cursor)
    # Check if there are more results
           #     if cursor is None:
            #        break

    # Set the cursor for the next API call
            #    cursor = cursors  
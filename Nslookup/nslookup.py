import subprocess
from datetime import datetime

today = datetime.today()
date_string = today.strftime('%Y-%m-%d-%H-%M-%S')
output_filename = f"{date_string}.txt"

with open('domains.txt', 'r') as f, open(output_filename, 'w') as output_file:
    for line in f:
        domain = line.strip()
        try:
            command = f"nslookup {domain}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            output_file.write(result.stdout)
            print(result.stdout)

        except subprocess.CalledProcessError as e:
            print(f"Command '{command}' returned non-zero exit status {e.returncode}: {e.stderr}")

input("Press enter to exit...")

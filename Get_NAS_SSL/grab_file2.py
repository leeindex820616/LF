import os
import shutil
from datetime import datetime

# specify the path to the text file containing the file names to search for
filename_txt = "domain_list.txt"
filename_txt2 = "domain_list_temp.txt"
# specify the path to the NAS folder to search for files in
nas_path = r"\\192.168.73.8\infra\SSL_Certificate_Files\SSLCert"

# specify the destination folder to copy files to
today = datetime.today()
date_string = today.strftime('%Y-%m-%d-%H-%M')
folder_name = f"{date_string}"
os.makedirs(folder_name)
destination_folder = folder_name

with open(filename_txt, "r") as f1, open(filename_txt2, "w") as f2:
    for line in f1:
        # Remove spaces from line
        line = line.replace(" ", "")
        # Write updated line to output file
        f2.write(line)
# read the list of file names from the text file
with open(filename_txt2, "r") as f:
    filenames = f.read().splitlines()

# iterate over the list of file names
for filename in filenames:
    # search for files in the NAS folder that contain the current file name
    matching_files = []
    for root, dirs, files in os.walk(nas_path):
        if "OLD" in dirs:
            dirs.remove("OLD")
        for file in files:
            if filename in file:
                matching_files.append(os.path.join(root, file))
    
    # if matching files were found, copy the latest one to the destination folder
    if matching_files:
        latest_file = max(matching_files, key=os.path.getctime)
        src_path = os.path.join(nas_path, latest_file)
        dst_path = os.path.join(destination_folder, latest_file)
        shutil.copy2(latest_file, destination_folder)
        print("Copied file:", latest_file)
    else:
        print("No file found for:", line)    

os.remove(filename_txt2)
# Keep the console open
input("Press enter to exit...")

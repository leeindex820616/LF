import os
import sys
import subprocess
import zipfile
from xml.dom import minidom
import tkinter as tk
from tkinter import messagebox


def unzip_apk(apk_file, output_dir):
    with zipfile.ZipFile(apk_file, 'r') as zip_ref:
        zip_ref.extractall(output_dir)

def compile_manifest(manifest_file):
    process = subprocess.Popen(['java', '-jar', 'AXMLPrinter2.jar', manifest_file], stdout=subprocess.PIPE)
    output, _ = process.communicate()
    return output

def check_package_name(manifest_xml):
    xml_doc = minidom.parseString(manifest_xml)
    meta_data_nodes = xml_doc.getElementsByTagName('meta-data')
    for meta_data_node in meta_data_nodes:
        if meta_data_node.getAttribute('android:name'):
            application_id = meta_data_node.getAttribute('android:value')
            #return "F1M1P5" in package_name
            return application_id
        return False

def check_bundle_name(bundle_content):
    index_ios = bundle_content.find('window.CodePushAppNameIOS="')
    if index_ios != -1:
        start_index_ios = index_ios + len('window.CodePushAppNameIOS="')
        end_index_ios = bundle_content.find('"', start_index_ios)
        code_push_app_name_ios = bundle_content[start_index_ios:end_index_ios]
        #print("CodePushAppNameIOS:", code_push_app_name_ios)
        return code_push_app_name_ios
    else:
        return False


def show_popup(message):
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    messagebox.showinfo("Result", message)
    root.destroy()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py path_to_app_file.apk(or ipa)")
        sys.exit(200)

    apk_file_path = sys.argv[1]
    if not os.path.exists(apk_file_path):
        print("Error: The specified file does not exist.")
        sys.exit(201)

    output_directory = "output_folder"

    # Unzip the APK file
    unzip_apk(apk_file_path, output_directory)
    apk_filename = os.path.basename(apk_file_path)
    contains_package_name =""
    if apk_file_path.startswith('zl_'):
        #show_popup("Specific package, will upload directly")
    
    else:
        if apk_file_path.endswith(".apk") :
            # Compile AndroidManifest.xml using AXMLPrinter
            manifest_file_path = os.path.join(output_directory, 'AndroidManifest.xml')
            compiled_manifest = compile_manifest(manifest_file_path)

            # Check if package name contains "F1M5"
            contains_package_name = check_package_name(compiled_manifest)


            if "com.f1m1.live" in contains_package_name.lower() and apk_filename.startswith('a45Qrj9ppJ'):
                #show_popup("Package name match filename, Will upload to F1M1P5")
                sys.exit(101)
            elif "com.f1m2.live" in contains_package_name.lower() and apk_filename.startswith('KEFv6MFNeKM'):
                #show_popup("Package name match filename, Will upload to F1M2")
                sys.exit(102)      
            elif "com.f1m2p5.live" in contains_package_name.lower() and apk_filename.startswith('SxwxRyvDF5'):
                #show_popup("Package name match filename, Will upload to F1M2")
                sys.exit(102)               
            elif "com.f1m3.live" in contains_package_name.lower() and apk_filename.startswith('uzyfRFCygDM3'):
                #show_popup("Package name match filename, Will upload to F1M3")
                sys.exit(103)
            elif "com.p1m1.live" in contains_package_name.lower() and apk_filename.startswith('0DvPq2K2OK'):
                #show_popup("Package name does not contain F1M2")
                #show_popup("Package name match filename, Will upload to P1M1")
                sys.exit(104)    
            elif "com.j1m1.live" in contains_package_name.lower() and apk_filename.startswith('rkJpyUhYyG'):
                #show_popup("Package name match filename, Will upload to J1M1")
                sys.exit(105)
            elif "com.j1m2.live" in contains_package_name.lower() and apk_filename.startswith('VcwtFXbzg5'):
                #show_popup("Package name match filename, Will upload to J1M2")
                sys.exit(106)
            elif "com.j1m3.live" in contains_package_name.lower() and apk_filename.startswith('77kDTutEbc'):
                #show_popup("Package name match filename, Will upload to J1M3")
                sys.exit(107)                          
            else :
                #show_popup("applicationID not match filename, Kindly assist to double check. " + "\nApplicationId: " + contains_package_name)
                sys.exit(202)

        elif apk_file_path.endswith(".ipa") :
            output_directory_IOS = output_directory + "/Payload/FedevProject.app"
            manifest_file_path = os.path.join(output_directory_IOS, 'main.jsbundle')    
            with open(manifest_file_path, 'r') as file:
                bundle_content = file.read()
            code_push_app_name = check_bundle_name(bundle_content)    
            #print(code_push_app_name)
            if "f1m1-p5-ios" in code_push_app_name.lower() and apk_filename.startswith('a45Qrj9ppJ'):
                #show_popup("Package name match filename, Will upload to F1M1P5")
                sys.exit(101)
            elif "f1m2-live-ios" in code_push_app_name.lower() and apk_filename.startswith('KEFv6MFNeKM'):
                #show_popup("Package name match filename, Will upload to F1M2")
                sys.exit(102)    
            elif "f1m2-live-ios" in code_push_app_name.lower() and apk_filename.startswith('SxwxRyvDF5'):
                #show_popup("Package name match filename, Will upload to F1M2")
                sys.exit(102)               
            elif "f1m3-vn-live-ios" in code_push_app_name.lower() and apk_filename.startswith('uzyfRFCygDM3'):
                #show_popup("Package name match filename, Will upload to F1M3")
                sys.exit(103)
            elif "f1m3-vn-live-ios" in code_push_app_name.lower() and apk_filename.startswith('g2Dsv6hNIq'):
                #show_popup("Package name match filename, Will upload to F1M3")
                sys.exit(103)    
            elif "p1m1-cn-live-ios" in code_push_app_name.lower() and apk_filename.startswith('0DvPq2K2OK'):
                #show_popup("Package name does not contain F1M2")
                #show_popup("Package name match filename, Will upload to P1M1")
                sys.exit(104)    
            elif "jbo-cn-live-ios" in code_push_app_name.lower() and apk_filename.startswith('rkJpyUhYyG'):
                #show_popup("Package name match filename, Will upload to J1M1")
                sys.exit(105)
            elif "jbo-th-live-ios" in code_push_app_name.lower() and apk_filename.startswith('VcwtFXbzg5'):
                #show_popup("Package name match filename, Will upload to J1M2")
                sys.exit(106)
            elif "jbo-vn-live-ios" in code_push_app_name.lower() and apk_filename.startswith('77kDTutEbc'):
                #show_popup("Package name match filename, Will upload to J1M3")
                sys.exit(107)                          
            else :
                #show_popup("applicationID not match filename, Kindly assist to double check. " + "\nApplicationId: " + code_push_app_name)
                sys.exit(202)

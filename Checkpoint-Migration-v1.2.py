import json, re, os, copy
from ipaddress import ip_address, ip_network, summarize_address_range

#######################################################################################################
####################FUNCTION TO SANITZE NAMES - JUST THE WAY OCI FIREWALL LIKES########################
#######################################################################################################

def sanitize_name(name):
    # Trim the name to 28 characters
    name = name[:28]
    # Remove spaces in the name
    name = name.replace(' ', '')
    # Add the "IP_" prefix if the name starts with a number
    if name[0].isdigit():
        name = "IP_" + name
    # Replace "." with "_" and "/" with "-"
    name = name.replace(".", "_").replace("/", "-")
    # Check if the name ends with a special character
    special_char_pattern = r'[^a-zA-Z0-9]'
    if re.search(special_char_pattern, name[-1]):
        name = name[:-1]
    return name

#######################################################################################################
#######CODE TO EXTRACT REQUIRED FIELD DATA FROM CHECKPOINT JSON - FOR IP & APPLICATION LIST############
#######################################################################################################
with open('Standard_objects.json', 'r') as file:
 data = json.load(file)
 name = []
for x in data:
    if  x["type"] == "host" or x["type"] == "checkpoint-host" or x["type"] == "CpmiClusterMember":
        name.append({"name":sanitize_name(x["name"]),"ipv4-address": x["ipv4-address"],"type":"host","uid":x["uid"]})
    elif x["type"] == "network":
        name.append({"name":sanitize_name(x["name"]),"Network-address": x["subnet4"], "Subnet-Mask": x["mask-length4"],"type":"network","uid":x["uid"]})
    elif x["type"] == "address-range":
        name.append({"name":sanitize_name(x["name"]),"First-IP": x["ipv4-address-first"], "Last-IP": x["ipv4-address-last"],"type":"address-range","uid":x["uid"]})
    elif x["type"] == "group":
        name.append({"name":sanitize_name(x["name"]),"ips": x["members"],"type":"group","uid":x["uid"]})
    elif x["type"] == "service-tcp":
        name.append({"name":sanitize_name(x["name"]),"port": x["port"],"type":"service-tcp","uid":x["uid"]})
    elif x["type"] == "service-udp":
        name.append({"name":sanitize_name(x["name"]),"port": x["port"],"type":"service-udp","uid":x["uid"]})
    elif x["type"] == "service-group":
        name.append({"name":sanitize_name(x["name"]),"members": x["members"],"type":"service-group","uid":x["uid"]})
    elif x["type"] == "service-icmp":
        name.append({"name": sanitize_name(x["name"]), "icmp-type": x["icmp-type"], "type": "service-icmp", "uid": x["uid"]})


# Save the modified data back to the file
with open('iplists.json', 'w') as f:
    json.dump(name, f)

#######################################################################################################
###########CONVERT RANGE OF IP ADDRESS - TO SUBNETS IN THE IPLIIST#####################################
#######################################################################################################
# Open the json file and read the data
with open('iplists.json') as f:
    data = json.load(f)

# Iterate through the list of dictionaries
for d in data:
    # Check if the current dictionary contains the "First-IP" and "Last-IP" fields
    if 'First-IP' in d and 'Last-IP' in d:
        # Extract the start and end IP addresses
        start_ip = d['First-IP']
        end_ip = d['Last-IP']

        # Convert the start and end IP addresses to ip_address objects
        start_address = ip_address(start_ip)
        end_address = ip_address(end_ip)

        # Calculate a list of IP network objects that cover the range of IP addresses
        ip_network_objects = list(summarize_address_range(start_address, end_address))

        # Convert the IP network objects to strings and add them to the dictionary
        d['ips'] = [str(network) for network in ip_network_objects]

# Save the modified data back to the file
with open('Modified_iplists.json', 'w') as f:
    json.dump(data, f)

#######################################################################################################
###############MAP THE UIDs OF NESTED GROUP  AND UPDATE IN IPLIST######################################
####################################################################################################### 
# Load the source JSON file
with open('Standard_objects.json', 'r') as f:
    source = json.load(f)

# Create a dictionary to map "uid" values to "member" values
uid_to_member_map = {}

# Iterate through each element in the source data
for element in source:
    # Check if the element has an "members" field
    if "members" in element:
        # Add the "uid" and "members" values to the map
        uid_to_member_map[element["uid"]] = element["members"]

# Load the target JSON file
with open('Modified_iplists.json', 'r') as f:
    target = json.load(f)

# Iterate through each element in the target data
for element in target:
    # If the element is a group
    if element["type"] == "group":
        # Replace the "uid" values in the "ips" field with the corresponding "members" values from the map
        new_ips = []
        for uid in element["ips"]:
            member = uid_to_member_map.get(uid, uid)
            if isinstance(member, list):
                new_ips.extend(member)
            else:
                new_ips.append(member)
        element["ips"] = new_ips

# Write the modified data to the target JSON file
with open('Modified_iplist.json', 'w') as f:
    json.dump(target, f)
#######################################################################################################
###############MAP THE UIDs TO IPV4-ADDRESS , SUBNET4/MASK-LENGTH VALUES AND UPDATE IN IPLIST##########
####################################################################################################### 
# Load the source JSON file
with open('Standard_objects.json', 'r') as f:
    source = json.load(f)

# Create a dictionary to map "uid" values to "ipv4-address" values
uid_to_ip_map = {}

# Create a dictionary to map "uid" values to "subnet4" and "mask-length4" values
uid_to_subnet_mask_map = {}

# Iterate through each element in the source data
for element in source:
    # Check if the element has an "ipv4-address" field
    if "ipv4-address" in element:
        # Add the "uid" and "ipv4-address" values to the map
        uid_to_ip_map[element["uid"]] = element["ipv4-address"]

    # Check if the element has a "subnet4" and "mask-length4" field
    if "subnet4" in element and "mask-length4" in element:
        # Concatenate the "subnet4" and "mask-length4" values
        subnet_mask = f"{element['subnet4']}/{element['mask-length4']}"
        # Add the "uid" and concatenated "subnet4" and "mask-length4" values to the map
        uid_to_subnet_mask_map[element["uid"]] = subnet_mask

# Load the target JSON file
with open('Modified_iplist.json', 'r') as f:
    target = json.load(f)

# Open the text file to write removed uids
with open('removed_uids.txt', 'a') as f:
    # Iterate through each element in the target data
    for element in target:
        # If the element is a group
        if element["type"] == "group":
            new_ips = []
            for uid in element["ips"]:
                if uid in uid_to_ip_map or uid in uid_to_subnet_mask_map:
                    new_ips.append(uid_to_ip_map.get(uid, uid_to_subnet_mask_map.get(uid)))
                else:
                    f.write(uid + '\n')
            element["ips"] = new_ips
# Write the modified data to the target JSON file
with open('Modified_iplists.json', 'w') as f:
    json.dump(target, f)
#######################################################################################################
#########CONVERT THE IPLIST TO OCI FIREWALL : IP_ADDRESS_LISTS JSON FORMAT#############################
#######################################################################################################

# Load the source JSON data
with open('Modified_iplists.json', 'r') as f:
    source_data = json.load(f)

def convert_format(source_json):
    target_json = {}
    for obj in source_json:
        if obj['type'] == 'address-range':
            target_json[obj['name']] = obj['ips']
        elif obj['type'] == 'network':
            target_json[obj['name']] = [f"{obj['Network-address']}/{obj['Subnet-Mask']}"]
        elif obj["type"] == "host":
            target_json[obj['name']] = [obj["ipv4-address"]]
        elif obj['type'] == 'group':
            target_json[obj['name']] = obj['ips']
    return target_json

# Read the source JSON file
with open('Modified_iplists.json', 'r') as f:
    source_json = json.load(f)

# Convert the source JSON to the target JSON format
converted_json = convert_format(source_json)

# Write the converted JSON to a file
with open('IP-Address-List.json', 'w') as f:
    json.dump(converted_json, f, indent=2)
print("Checkpoint IP Address objects to OCI IP-Address-List Conversion - Done!")
#######################################################################################################
########IPLIST DATA IS USED AS INPUT , TO CREATE OCI FIREWALL : APPLICATION_LIST JSON##################
#######################################################################################################

# Load the source JSON data
with open('Modified_iplists.json', 'r') as f:
    source_data = json.load(f)

# Initialize the destination data structure
destination_data = {}

# Iterate through the list of source data
for item in source_data:
    # Check if the item is a "service-tcp" or "service-udp"
    if item["type"] in ["service-tcp", "service-udp"]:
        name = item['name']
        type = item['type'].upper()
        port = item['port']

        # Convert the 'type' value
        if type == 'SERVICE-TCP':
            type = 'TCP'
        elif type == 'SERVICE-UDP':
            type = 'UDP'

        # Check if the port value is a range
        if '-' in port:
            # Split the range into minimum and maximum values
            minimum, maximum = port.split('-')
            minimum = int(minimum)
            maximum = int(maximum)
        else:
            # Set the minimum and maximum values to the same value
            minimum = int(port)
            maximum = int(port)

        # Add the data for this item to the destination data structure
        if name not in destination_data:
            destination_data[name] = []
        destination_data[name].append({
            'maximum-port': maximum,
            'minimum-port': minimum,
            'type': type})

    # Check if the item is a "service-icmp"
    elif item["type"] in ["service-icmp"]:
        name = item['name']
        type = item['type'].upper()
        icmp = item['icmp-type']

        # Convert the 'type' value
        if type == 'SERVICE-ICMP':
            type = 'ICMP'
        
        if name not in destination_data:
            destination_data[name] = []
        destination_data[name].append({
            "icmp-code": None,
            'icmp-type': icmp,
            'type': type
        })
        
    # Check if the item is a "service-group"
    elif item["type"] == "service-group":
        group_name = item['name']
        members = item['members']
        for member in members:
            # Find the member item in the source data
            for member_item in source_data:
                if member_item["uid"] != member:
                    continue
                # Check if the item is a "Service-TCP" or "Service-UDP"
                if member_item["type"] in ["service-tcp", "service-udp"]:
                    name = member_item['name']
                    type = member_item['type'].upper()
                    port = member_item['port']

                    # Convert the 'type' value
                    if type == 'SERVICE-TCP':
                        type = 'TCP'
                    elif type == 'SERVICE-UDP':
                        type = 'UDP'

                    # Check if the port value is a range
                    if '-' in port:
                        # Split the range into minimum and maximum values
                        minimum, maximum = port.split('-')
                        minimum = int(minimum)
                        maximum = int(maximum)
                    else:
                        # Set the minimum and maximum values to the same value
                        minimum = int(port)
                        maximum = int(port)

                    # Add the data for this item to the destination data structure
                    if group_name not in destination_data:
                        destination_data[group_name] = []
                    destination_data[group_name].append({
                        'maximum-port': maximum,
                        'minimum-port': minimum,
                        'type': type
                    })
                # Check if the item is a "service-icmp"
                elif member_item["type"] in ["service-icmp"]:
                    name = member_item['name']
                    type = member_item['type'].upper()
                    icmp = member_item['icmp-type']

                    # Convert the 'type' value
                    if type == 'SERVICE-ICMP':
                        type = 'ICMP'
        
                    if group_name not in destination_data:
                        destination_data[group_name] = []
                    destination_data[group_name].append({
                        "icmp-code": None,
                        'icmp-type': icmp,
                        'type': type
                    })
# Save the destination JSON data with correct spacing
with open('application-list.json', 'w') as f:
    json.dump(destination_data, f, indent=2)
print("Checkpoint Service objects to OCI Application-List Conversion - Done!")
#######################################################################################################
########################### BELOW CODE IS FOR ACCESS RULE CREATION#####################################
#######################################################################################################

#######################################################################################################
########### STRIP REQUIRED DETAILS FROM , NETWORK-MANAGEMENT SERVER FILE CREATE SECURITY-RULES JSON####
#######################################################################################################
with open('Network-Management server.json', 'r') as file:
 data = json.load(file)

 name = []
for x in data:
    if x["type"] == "access-rule":
        name.append({"action":x["action"],"destination": x["destination"],"source":x["source"],"service":x["service"],"enabled":x["enabled"]})
        # Save the modified data back to the file

with open('Securityruleitems.json', 'w') as f:
    json.dump(name, f)

#######################################################################################################
########### UID OF SRC , DST , ACTION ARE REPLACED BY ITS SANTIZED NAMES AS A INTERMEDIATE JSON FILE###
#######################################################################################################

# Load the Standard_objects.json file and create a dictionary mapping uid to name
with open('Standard_objects.json', 'r') as f:
    objects = json.load(f)
uid_to_name = {o['uid']: sanitize_name(o['name']) for o in objects}

# Load the securityruleitems.json file and replace the uid values with the corresponding name values
with open('securityruleitems.json', 'r') as f:
    security_rules = json.load(f)
for rule in security_rules:
    if isinstance(rule['source'], list):
        rule['source'] = [uid_to_name[uid] for uid in rule['source']]
    else:
        rule['source'] = uid_to_name[rule['source']]
    if isinstance(rule['destination'], list):
        rule['destination'] = [uid_to_name[uid] for uid in rule['destination']]
    else:
        rule['destination'] = uid_to_name[rule['destination']]
    if isinstance(rule['action'], list):
        rule['action'] = [uid_to_name[uid] for uid in rule['action']]
    else:
        rule['action'] = uid_to_name[rule['action']]
    if isinstance(rule['service'], list):
        rule['service'] = [uid_to_name[uid] for uid in rule['service']]
    else:
        rule['service'] = uid_to_name[rule['service']]

# Save the modified security rules to a new file
with open('modified_security_rules_a.json', 'w') as f:
    json.dump(security_rules, f)

#######################################################################################################
####### INTERMEDIATE JSON FILE ACTION IS CONVERTED TO OCI FIREWALL -SECURITY-RULES JSON FILE###########
#######################################################################################################

# Load the JSON file
with open('modified_security_rules_a.json', 'r') as f:
    data = json.load(f)

# Iterate over the items in the data list
for item in data:
    # Convert the value of the "action" field
    if item['action'] == 'Accept':
        item['action'] = 'ALLOW'
    elif item['action'] == 'Drop':
        item['action'] = 'DROP'

# Save the transformed data to a new JSON file
with open('modified_security_rules.json', 'w') as f:
    json.dump(data, f, indent=2)
#######################################################################################################
######MODIFIED SECURITY RULES IS CONVERTED TO OCI FIREWALL JSON FORMAT#################################
#######################################################################################################

# Load the JSON file
with open('modified_security_rules.json', 'r') as f:
    data = json.load(f)

# Create a new list to store the transformed data
transformed_data = []

# Initialize a counter variable to keep track of the index
counter = 1

# Iterate over the items in the data list
for item in data:
    # Create a new dictionary for the transformed data
    transformed_item = {}

    # Set the "action" field based on the "action" field in the original data
    
    transformed_item['action'] = item['action']

    # Create a new dictionary for the "condition" field
    condition = {}

    # Set the "applications" field based on the "service" field in the original data
    if item['service'][0] == "Any":
       condition['applications'] = []
    else:
       condition['applications'] = item['service']

    # Set the "destinations" field based on the "destination" field in the original data
    if item['destination'][0] == "Any":
        condition['destinations'] = []
    else:
        condition['destinations'] = item['destination']

    # Set the "sources" field based on the "source" field in the original data
    if item['source'][0] == "Any":
        condition['sources'] = []
    else:
        condition['sources'] = item['source']

    # Set the "urls" field to an empty list
    condition['urls'] = []

    # Add the "condition" dictionary to the transformed item
    transformed_item['condition'] = condition

    # Set the "inspection" field to null
    transformed_item['inspection'] = None

    # Set the "name" field to "rule-number-X", where X is the index of the item in the list
    transformed_item['name'] = "rule-number-{}".format(counter)

    # Increment the counter variable
    counter += 1

    # Add the transformed item to the list, unless it is disabled
    if item['enabled']:
        transformed_data.append(transformed_item)

# Save the transformed data to a new JSON file
with open('security_rules.json', 'w') as f:
    json.dump(transformed_data, f, indent=2)

######################################################################################################
###############REMOVE OBJECTS THAT ARE NOT MATCHING IN IPADDRESS & APPLICATION LISTS##################
######################################################################################################
with open("iplists.json") as file:
    data = json.load(file)

with open("security_rules.json") as file:
    B = json.load(file)

# Extracting the 'name' field from each object in the list
name_list = [obj["name"] for obj in data]

removed_sources = []
new_B = copy.deepcopy(B)

for obj in new_B:
    assert 'condition' in obj, f'condition key not found in object {obj}'
    for key in ['sources','destinations','applications']:
        if key in obj['condition']:
            valid_elements = [ element for element in obj["condition"][key] if element in name_list]
            invalid_elements = [ element for element in obj["condition"][key] if element not in name_list]
            removed_sources.extend(invalid_elements)
            obj["condition"][key] = valid_elements
# Dumping the modified B object to a new json file
with open('modified.b.json', 'w') as file:
    json.dump(new_B, file, indent=2)

# Open a log file in write mode
with open("removed_objects_log.txt", "w") as log_file:
        # Print the removed objects to the log file
    print("Removed Objects:", removed_sources, file=log_file)

#######################################################################################################
####################CREATE DUPLICATE RULES THAT HAS ICMP APPLICATIONS##################################
#######################################################################################################

try:
    with open("iplists.json") as file:
        data = json.load(file)
    with open("modified.b.json") as file:
        B = json.load(file)

except FileNotFoundError as e:
    print(f"File not found: {e}")
    exit(1)
except json.decoder.JSONDecodeError as e:
    print(f"Error decoding JSON file: {e}")
    exit(1)

# Extracting the list of 'names' that is icmp-application or has icmp in its name"
icmp_list = [obj["name"] for obj in data if "icmp" in obj["name"] or obj["type"] == "service-icmp"]
new_rules = []
for obj in B:
    assert 'condition' in obj, f'condition key not found in object {obj}'
    new_rule = copy.deepcopy(obj)
    icmp_applications = []
    non_icmp_applications = []
    if 'applications' in obj['condition']:
        for application in obj["condition"]["applications"]:
            if application in icmp_list:
                icmp_applications.append(application)
            else:
                non_icmp_applications.append(application)
        new_rule['condition']['applications'] = non_icmp_applications
        new_rules.append(new_rule)
        if icmp_applications:
            icmp_rule = copy.deepcopy(obj)
            icmp_rule['name'] = icmp_rule['name'] + "-icmp"
            icmp_rule['condition']['applications'] = icmp_applications
            new_rules.append(icmp_rule)

# Dumping the modified B object to a new json file
with open('security_rules_v2.json', 'w') as file:
    json.dump(new_rules, file, indent=2)



print("Checkpoint Network Security Rules to OCI Security-Rules Conversion - Done!")

# print the log

######################################################################################################
#############################CLEAN UP THE MESS########################################################
#####################################################################################################
#List of file names to delete
file_names = [ "iplists.json","modified.b.json","Modified_iplist.json", "Modified_iplists.json","modified_security_rules.json","modified_security_rules_a.json","Securityruleitems.json"]

#Delete all files in the list
for file in file_names:
    os.remove(file)
print("Cleanup - Done!")
#######################################################################################################
#################################FINAL STEP EXECUTION##################################################
import time
import subprocess

print("WOULD YOU LIKE TO GET THE FIREWALL RULES DEPLOYED")
print("Choose one of the below Options.")
print("Option 1 : Create a New Firewall Policy")
print("Option 2: Update an Existing Firewall policy")
print("Option 3: Exit")

option = int(input())

if option == 1:
    
    compartment_ocid = input("Enter compartment OCID: ")
    display_name = input("Enter display name: ")
    profile = input("Enter profile name: ")
    output = subprocess.run(["oci", "network-firewall", "network-firewall-policy", "create", "-c", compartment_ocid, "--display-name", display_name, "--profile", profile], capture_output=True)
    output_str = output.stdout.decode('utf-8')
    output_json = json.loads(output_str)
    network_policy_ocid = output_json.get("data", {}).get("id", "")
    print("Wait while your new firewall policy is getting created :")
    time.sleep(15)

    subprocess.run(["oci", "network-firewall", "network-firewall-policy", "update", "--network-firewall-policy-id", network_policy_ocid, "--ip-address-lists", "file://IP-Address-List.json", "--profile", profile, "--force"])
    print("Wait while your IP-Address-List is getting updated..")
    time.sleep(15)
    
    subprocess.run(["oci", "network-firewall", "network-firewall-policy", "update", "--network-firewall-policy-id", network_policy_ocid, "--application-lists", "file://application-list.json", "--profile", profile, "--force"])
    print("Wait while your Application-List is getting updated..")
    time.sleep(15)
    
    subprocess.run(["oci", "network-firewall", "network-firewall-policy", "update", "--network-firewall-policy-id", network_policy_ocid, "--security-rules", "file://security_rules_v2.json", "--profile", profile, "--force"])
    print("Wait while your Security-rules are getting updated..")


elif option == 2:
    network_policy_ocid = input("Enter Network Policy OCID: ")
    profile = input("Enter profile name: ")

    subprocess.run(["oci", "network-firewall", "network-firewall-policy", "update", "--network-firewall-policy-id", network_policy_ocid, "--ip-address-lists", "file://IP-Address-List.json", "--profile", profile, "--force"])
    print("Wait while your IP-Address-List is getting updated..")
    time.sleep(15)
    
    subprocess.run(["oci", "network-firewall", "network-firewall-policy", "update", "--network-firewall-policy-id", network_policy_ocid, "--application-lists", "file://application-list.json", "--profile", profile, "--force"])
    print("Wait while your Application-List is getting updated..")
    time.sleep(15)
    
    subprocess.run(["oci", "network-firewall", "network-firewall-policy", "update", "--network-firewall-policy-id", network_policy_ocid, "--security-rules", "file://security_rules_v2.json", "--profile", profile, "--force"])
    print("Wait while your Security-rules are getting updated..")
elif option == 3:
    exit()
else:
    print("Invalid option selected")

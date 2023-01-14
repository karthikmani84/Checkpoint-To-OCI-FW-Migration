[BRIEF-DESCRIPTION-OF-THE-TOOL]:

This scripts uses , Checkpoint firewall Web-Visualization tool output json files and converts them to OCI Network firewalls IP address , Application and Security Rules. Essentially a data converter tool.

The Web Visualization solution exports the configuration of the Security Management Server to a readableformat. The exported data is an independent snapshot of the database. You can see it in your browser. This lets security administrators or executives audit the Security Management Server configuration. To know more refer : [https://downloads.checkpoint.com/fileserver/SOURCE/direct/ID/12106/FILE/CP_WebVisualization_ReleaseNotes.pdf]

[INSTALLATION-INSTRUCTIONS]:
1. Python needs to be installed in your machine , to run this code. Refer to this link for installing python on your workstation. [https://realpython.com/installing-python/]

2. Download the Webvisualization tool , extract the files in a folder. Move the Script to the same path , were visualization tool files are extracted. Then Execute the Python script, from that path.

[USAGE-INSTRUCTIONS]:
1. If OCI CLI is installed in your machine , then the script lets you to even create a firewall policy & pushes the policy to your OCI tenancy [OCI Network Firewall]. refer this link , if you would like to get OCI CLI insalled. [https://docs.oracle.com/en-us/iaas/Content/API/Concepts/cliconcepts.htm]

2. If OCI CLI is not installed , then the JSON files can be copied to OCI Web CLI (Available in your OCI console), then execute OCI CLI commands for Network firewalls to create / update the firewall policies ,using the JSON files created by the script as input. Refer this link , if you would like to know the commands required to create / update - Network Firewall Policy. Refer:[https://docs.oracle.com/en-us/iaas/tools/oci-cli/3.14.0/oci_cli_docs/cmdref/network-firewall.html]


3. To covert the Checkpoint Firewall Policies - You can open the terminal or command prompt on your Mac or Windows computer and type "python3" followed by the name of the Python file you want to run. In our case, it will be  python3 Checkpoint-Migration-v1.py (run from the path were , checkpoint files are extracted.)

[EXAMPLE-OUTPUT]

********Execute the script with either the path , where the files are stored. Or Mention the path of file , while executing the script******************************************************

karthikmani@karthikmani-mac Demo % /usr/local/bin/python3 /Users/karthikmani/Desktop/Demo/Checkpoint-Migration-v1.py

******When the script gets excuted Successfully , expect to see below Output*********************

Checkpoint IP Address objects to OCI IP-Address-List Conversion - Done!
Checkpoint Service objects to OCI Application-List Conversion - Done!
Checkpoint Network Security Rules to OCI Security-Rules Conversion - Done!
Cleanup - Done!
WOULD YOU LIKE TO GET THE FIREWALL RULES DEPLOYED
Choose one of the below Options.
Option 1 : Create a New Firewall Policy
Option 2: Update an Existing Firewall policy
Option 3: Exit

***********Above lines means , the IP-Address-List , Applications-List , Security-Rules  Conversion is successfully completed. Followed by an option to either create a policy , or update the existing policy****************************************************************

[CODE-DESIGN-INFO]
1. Function to Sanitize Objects Names - Just the Way OCI Network firewall likes is created.
2. Webvisualization tools "standard_objects.json" file is used as input , to extract required fields. Name_Sanitize function is called , to sort the name formats while these data are extracted.
3. IP-Ranges objects in Checkpoint , are converted to Subnet ranges and added to a Modified_list that got created in previous step.
4. Nested Groups (if used) are converted to a single group , OCI firewall does not support creating - objects groups inside object groups. [Note: This code supports , one level of Nested group. If there are more , this portion of code must be run in loop].
5. Checkpoint JSON files refers - objects with 'UID' values , so UID of IP and Network_ranges are mapped.Then these data are appended to the file , created in step 3.
6. Then the IP-Address-lists OCI Network FIrewall - JSON format gets created using the file created in step 5.
7. Using file created in Step 5 - Application-List JSON also gets created.
8. Webvisualization tools "Network Managenment_Server.json" file is used as input and required data fields to builds Security Rules are extracted.
9. 'UID' and 'name' values are mapped , then (name_santize) function gets called again to convert the source , destination , action , servcies names. 
10. In the next two sections , the data is formatted to target OCI Network firewall JSON format.
11. OCI firewall currently , does not support allowing ICMP & TCP/UDP services in same rule. So another version of security rules ,thats splits such rules are created.

Some other info:
If a rule  , if marked as disabled will not be migrated to OCI firewall. As rule disable feature is not currently available, in OCI Network Firewall.

[KNOWN-ISSUES]
1. This tool uses JSON files , from the checkpoint visualization tool as input. If their JSON format  changes , that means some part of this code needs to change.
2. This version of code , foucses only on Firewall access rules , and threat prevention rules are not exported as part of this code.
3. You may also want to review, the features used in Checkpoint & OCI Network Firewall. The native firewall of OCI is pretty lean. [It is not expected to behave - as NAT , VPN , Proxy or a Routing device]. Such capabilites , when you choose to use OCI Network Firewall, will be migrated to other native services. So those blades / rules will not be part of this migration.
4. When it comes to "Nested-groups" - where an object-group is called inside an object-group , this code , will take care of one level of such madness. If you have multiple levels of Nested-groups, then please fix it before using this tool. Else refer code-design section : the code that sorts nested group ,must be run in a loop , as many times as required. Which is not tested yet!
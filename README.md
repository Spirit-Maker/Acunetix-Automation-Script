# Acunetix-Automation-Script
Acunetix web scannner script written in python3. Utilizes API and automates the management of URLs, groups, and scans. Very useful in cases with bulk of target URLs/ domains/ subdomains and multiple groups.

# Configuration
Add/ change configration paraments
  1.  Acunetix URL
  2.  API Key for Acunetix
 Voila Start using acunetix automation tool
 
 # Requirements
 Shared in requirements.txt file
 
 # Help Menu
![image](https://user-images.githubusercontent.com/39567452/140593922-9f2d1405-2402-4684-a810-b96f18958cb6.png)

  
 # Example
 python3 Acunetix_Operator.py --url http://domain.com --group domaingroup --addtarget 
 
 # Limitations
 When mulitple scans are running, acunetix API becomes unresponsive, currenlty no bypass against timeout

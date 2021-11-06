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
     ___                         __  _
   /   | _______  ______  ___  / /_(_)  __
  / /| |/ ___/ / / / __ \/ _ \/ __/ / |/_/
 / ___ / /__/ /_/ / / / /  __/ /_/ />  <
/_/  |_\___/\__,_/_/ /_/\___/\__/_/_/|_|

   ____                        __
  / __ \____  ___  _________ _/ /_____  _____
 / / / / __ \/ _ \/ ___/ __ `/ __/ __ \/ ___/
/ /_/ / /_/ /  __/ /  / /_/ / /_/ /_/ / /
\____/ .___/\___/_/   \__,_/\__/\____/_/
    /_/


--------------------------------------------------------------------------------------------------
usage: Acunetix_Operator.py [-h] (--targets TARGETS | --url URL) [--groups GROUPS | --group GROUP] [--iscan]
                            [--verbose] (--addtarget | --deltarget | --startscan | --stopscan | --delscan | --status)

Interact with Acunetix scanner using API

optional arguments:
  -h, --help            show this help message and exit
  --targets TARGETS, -t TARGETS
                        Complete path to text file containing line seperated URL addresses for scanning.
  --url URL, -u URL     URL address for scanning.
  --groups GROUPS, -gs GROUPS
                        Complete path to text file containing line seperated Group Names for scanning.
  --group GROUP, -g GROUP
                        Group Name for target.
  --iscan, -i           Start scan immidiatly against provided URLs.
  --verbose, -v         Verbose will print IDs of the operations requested.
  --addtarget, -at      Add target for Provided URL address(es).
  --deltarget, -dt      Del target for Provided URL address(es).
  --startscan, -sa      Stop Scan for Provided URL address(es).
  --stopscan, -ss       Stop Scan for Provided URL address(es).
  --delscan, -ds        Delete Scan for Provided URL address(es).
  --status, -s          Status of Scan for Provided URL address(es).
  
 # Example
 python3 Acunetix_Operator.py --url http://domain.com --group domaingroup --addtarget 
 
 # Limitations
 When mulitple scans are running, acunetix API becomes unresponsive, currenlty no bypass against timeout

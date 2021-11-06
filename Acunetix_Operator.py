#!/usr/bin/python3


import argparse
import json
import traceback

from platform import system as platform
from time import sleep
from sys import exit
from os import system

from colorama import Fore, Style
from colorama import init as colorama_init
from pyfiglet import Figlet

import requests
import requests.packages.urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Acunetix(object):
	"""docstring for Acunetix"""
	# static variables

	url = "Enter your acunnetix URL with port and medium(https) e.g https://localhost:3443"
	apikey = "Aacunetix API Key"


	headers = {}
	verbose = False
	targetconfig = None
	existingTargets = None
	existingScans = None
	existingGroups = None

	def __init__(self,args):
		super(Acunetix, self).__init__()
		self.headers = {"X-Auth":self.apikey,"content-type": "application/json"}
		self.acunetixSettings()	# print header values
		self.targetconfig = self.getTgtConfig()
		self.verbose = False
		self.existingTargets = self.getTargets()
		self.existingScans = self.getscans()
		self.existingGroups = self.getGroups()
		
	
	def updateTargets(self):
		self.existingTargets = self.getTargets()


	def updateScans(self):
		self.existingScans = self.getscans()

	def updateGroups(self):
		self.existingGroups = self.getGroups()

	def setverbose(self,verbose):
		self.verbose=verbose


	def getTargets(self):
		if self.existingTargets:
			print(f"{Fore.MAGENTA}Updating Existing Targets.{Style.RESET_ALL}")
		else:
			print(f"{Fore.MAGENTA}Fetching Existing Targets.{Style.RESET_ALL}")

		final_list = []
		try:
			response = requests.get(self.url+"/api/v1/targets?l=1",data={},headers=self.headers,timeout=30,verify=False)
			response = response.json()
			# print(json.dumps(response,indent=4))		

			if response["pagination"]:
				count = response["pagination"]["count"]
				
				# sleep(5)
				
				while True:
					cursor = None
					if count < 100:
						cursor = 0
					else:
						cursor = 100
						count = count - cursor
					tarres = None

					try:
						tarres = requests.get(self.url+"/api/v1/targets?c="+str(cursor)+"&l="+str(100),data={},headers=self.headers,timeout=30,verify=False)
						tarres = tarres.json()
						final_list.extend(tarres["targets"])
					except Exception as e:
						print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
						traceback.print_exc()
					
					sleep(1)

					if cursor < 100:
						break
				
		except Exception as e:
			print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
			traceback.print_exc()
			
		if self.verbose:
			print(f"{Fore.LIGHTYELLOW_EX}Total Targets gathered: {len(final_list)}{Style.RESET_ALL}")
			print(json.dumps(final_list, indent=4))
		return final_list

	def getscans(self):
		if self.existingScans:
			print(f"{Fore.MAGENTA}Updating Existing Scans.{Style.RESET_ALL}")
		else:
			print(f"{Fore.MAGENTA}Fetching Existing Scans.{Style.RESET_ALL}")

		final_list = []
		try:
			response = requests.get(self.url+"/api/v1/scans?l=1",data={},headers=self.headers,timeout=30,verify=False)
			response = response.json()
			# print(json.dumps(response,indent=4))
			if response["pagination"]:
				count = response["pagination"]["count"]
				
				# sleep(5)
				
				while True:
					cursor = None
					if count < 100:
						cursor = 0
					else:
						cursor = 100
						count = count - cursor

					tarres=None
					try:
						tarres = requests.get(self.url+"/api/v1/scans?c="+str(cursor)+"&l="+str(100),data={},headers=self.headers,timeout=30,verify=False)
						tarres = tarres.json()
						final_list.extend(tarres["scans"])
					except Exception as e:
						print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
						traceback.print_exc()
					sleep(1)

					if cursor < 100:
						break

		except Exception as e:
			print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
			traceback.print_exc()
			
		if self.verbose:
			print(f"{Fore.LIGHTYELLOW_EX}Total Scans gathered: {len(final_list)}{Style.RESET_ALL}")
			print(json.dumps(final_list, indent=4))
		return final_list


	def getGroups(self):
		if self.existingGroups:
			print(f"{Fore.MAGENTA}Updating Existing Groups.{Style.RESET_ALL}")
		else:
			print(f"{Fore.MAGENTA}Fetching Existing Groups.{Style.RESET_ALL}")
		final_list = []

		try:
			response = requests.get(self.url+"/api/v1/target_groups?l=1",data={},headers=self.headers,timeout=30,verify=False)
			response = response.json()
			# print(json.dumps(response,indent=4))
			if response["pagination"]:
				
				count = response["pagination"]["count"]

				while True:
					cursor = None
					if count < 100:
						cursor = 0
					else:
						cursor = 100
						count = count - cursor
					tarres = None
					try:
						tarres = requests.get(self.url+"/api/v1/target_groups?c="+str(cursor)+"&l="+str(100),data={},headers=self.headers,timeout=30,verify=False)
						tarres = tarres.json()
						final_list.extend(tarres["groups"])
					except Exception as e:
						print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
						traceback.print_exc()
					sleep(1)

					if cursor < 100:
						break

		except Exception as e:
			print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
			traceback.print_exc()
		
		if self.verbose:
			print(f"{Fore.LIGHTYELLOW_EX}Total Groups gathered: {len(final_list)}{Style.RESET_ALL}")
			print(json.dumps(final_list, indent=4))
		return final_list

	def getTargetURL(self,id):
		urls = []
		for target in self.existingTargets:
			if id == target["target_id"]:
				urls.append(target["address"])
		return urls

	def getTargetID(self,url):
		ids = []
		for target in self.existingTargets:
			if url == target["address"]:
				ids.append(target["target_id"])
		return ids

	def existingTargetURLs(self):
		urls = []
		for target in self.existingTargets:
			urls.append(target["address"])

		if self.verbose:
			print(f"{Fore.LIGHTYELLOW_EX}Total Targets URLs: {len(urls)}{Style.RESET_ALL}")
			print(json.dumps(urls, indent=4))
		return urls

	def existingTargetIDs(self):
		ids = []
		for target in self.existingTargets:
			ids.append(target["target_id"])
		return ids

	def checkTargetExists(self, target):
		urls = self.existingTargetURLs()

		if target in urls:
			return True
		else:
			return False
	
	
	def existingScanURLs(self):
		scans = self.existingScans
		urls = []
		for scan in scans:
			urls.append(scan["target"]["address"])

		if self.verbose:
			print(f"{Fore.LIGHTYELLOW_EX}Total Scan URLs: {len(urls)}{Style.RESET_ALL}")
			print(json.dumps(urls, indent=4))		
		return urls

	def existingScanIDs(self):
		scans = self.existingScans
		ids = []
		for scan in scans:
			ids.append(scan["target_id"])

		return ids

	def getScanURL(self,id):
		urls = []
		for target in self.existingScans:
			if id == target["scan_id"]:
				urls.append(target["target"]["address"])
		return urls

	def getScanID(self,url):
		ids = []
		for target in self.existingScans:
			if url == target["target"]["address"]:
				ids.append(target["scan_id"])
		return ids

	def existingTargetGroupsName(self):
		names = []
		for name in self.existingGroups:
			names.append(name["name"])
		
		return names

	def getGroupID(self,name):
		ids = []
		for group in self.existingGroups:
			if name == group["name"]:
				ids.append(group["group_id"])
		return ids

	def getGroupName(self,id):
		names = []
		for group in self.existingGroups:
			if id == group["group_id"]:
				names.append(group["name"])
		return names

	def getGroupTargets(self,ids):
		targets = []
		for id in ids:
			try:
				response = requests.get(self.url+"/api/v1/target_groups/"+id+"/targets",data={},headers=self.headers,timeout=30,verify=False)
				response = json.loads(response.content)
				targets.extend(response["target_id_list"])
			except Exception as e:
				print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
				traceback.print_exc()
		return targets
	
	def addtarget(self,targets):
		target_ids = []
		try:
			for tgt in targets:
				if tgt in self.existingTargetURLs():
					print(f"{Fore.YELLOW}Target {Fore.LIGHTCYAN_EX}{tgt}{Fore.YELLOW} already exist in targets.{Style.RESET_ALL}")
					target_ids.extend(self.getTargetID(tgt))

				else:
					data = {"address":tgt,"description":tgt,"criticality":"10"}

					try:
						response = requests.post(self.url+"/api/v1/targets",data=json.dumps(data),headers=self.headers,timeout=30,verify=False)
						result = json.loads(response.content)
						
						# print (json.dumps(result, indent=4))
						
						requests.patch(self.url+"/api/v1/targets/"+str(result["target_id"])+"/configuration",data=json.dumps(self.targetconfig),headers=self.headers,timeout=30*4,verify=False)
						target_ids.append(result['target_id'])

						print (f"{Fore.GREEN}Successfully Created Target: {Fore.LIGHTCYAN_EX} {result['address']} {Style.RESET_ALL}")

					except Exception as e:
						print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
						traceback.print_exc()
					sleep(1)
				self.targetconfig = self.getTgtConfig()
								
		except Exception as e:
			print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
			traceback.print_exc()

		return target_ids

	def deltarget(self,targets):
		target_ids = []
		
		try:
			if getConfirmationAnswer(2):
				for tgt in targets:	
					if tgt in self.existingTargetURLs():
						target_id = self.getTargetID(tgt)
						for deltgt in target_id:
							try:
								requests.delete(self.url+"/api/v1/targets/"+str(deltgt),headers=self.headers,timeout=30,verify=False)
								target_ids.append(deltgt)
								print (f"{Fore.GREEN}successfully Deleted Target: {Fore.LIGHTCYAN_EX} {tgt} {Style.RESET_ALL}")
							except Exception as e:
								print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
								traceback.print_exc()
							sleep(1)
					else:
						continue						
			else:
				pass
		except Exception as e:
			print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
			traceback.print_exc()
		return target_ids
	
	
	def addGroup(self,groups):
		target_ids = []
		try:
			for tgt in groups:
				if tgt in self.existingTargetGroupsName():
					print(f"{Fore.YELLOW}Group {Fore.LIGHTCYAN_EX}{tgt}{Fore.YELLOW} already exist in target groups.{Style.RESET_ALL}")
					target_ids.extend(self.getGroupID(tgt))

				else:
					data = {"name":tgt,"description":tgt}
					try:
						response = requests.post(self.url+"/api/v1/target_groups",data=json.dumps(data),headers=self.headers,timeout=30,verify=False)
						result = json.loads(response.content)
						print (f"{Fore.GREEN}Successfully Created Target Group: {Fore.LIGHTCYAN_EX} {result['name']} {Style.RESET_ALL}")
						target_ids.append(result["group_id"])
					except Exception as e:
						print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
						traceback.print_exc()
					sleep(1)				
								
		except Exception as e:
			print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
			traceback.print_exc()

		return target_ids
	

	def addTargetsToGroup(self,group_ids,ids):
		target_ids = []
		try:
			for group_id in group_ids:
				grouptargets = self.getGroupTargets([group_id])
				for id in ids:
					data = {"group_id":group_id,"add":[id],"remove":[]}
					try:
						response = requests.patch(self.url+"/api/v1/target_groups/"+group_id+"/targets",data=json.dumps(data),headers=self.headers,timeout=30,verify=False)
						if response.status_code == 204:
							if id in grouptargets:
								print (f"{Fore.YELLOW}Target {Fore.LIGHTCYAN_EX}{self.getTargetURL(id)}{Fore.YELLOW} already exists in : {Fore.LIGHTCYAN_EX}{self.getGroupName(group_id)}{Style.RESET_ALL}")
								
							else:
								print (f"{Fore.GREEN}Successfully Added {Fore.LIGHTCYAN_EX}{self.getTargetURL(id)}{Fore.GREEN} in : {Fore.LIGHTCYAN_EX}{self.getGroupName(group_id)}{Style.RESET_ALL}")
					except Exception as e:
						print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
						traceback.print_exc()
								
							
								
		except Exception as e:
			print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
			traceback.print_exc()

		return target_ids

	
	def startscan(self, targets):
		'''
			11111111-1111-1111-1111-111111111112    High Risk Vulnerabilities          
			11111111-1111-1111-1111-111111111115    Weak Passwords        
			11111111-1111-1111-1111-111111111117    Crawl Only         
			11111111-1111-1111-1111-111111111116    Cross-site Scripting Vulnerabilities       
			11111111-1111-1111-1111-111111111113    SQL Injection Vulnerabilities         
			11111111-1111-1111-1111-111111111118    quick_profile_2 0   {"wvs": {"profile": "continuous_quick"}}            
			11111111-1111-1111-1111-111111111114    quick_profile_1 0   {"wvs": {"profile": "continuous_full"}}         
			11111111-1111-1111-1111-111111111111    Full Scan   1   {"wvs": {"profile": "Default"}}         
		'''

		urls = self.existingScanURLs()

		target_ids = []
		try:
			if len(targets) > 4:
				if not getConfirmationAnswer(5):
					return target_ids

			for tgt in targets:
				if not self.checkTargetExists(tgt):
					print(f"{Fore.RED}Target {Fore.LIGHTCYAN_EX}{Fore.RED} does not exists, please create target first.{Style.RESET_ALL}")
					continue
				if tgt in urls:
					print(f"{Fore.RED}Scan already Exists.{Style.RESET_ALL}")
					
					if getConfirmationAnswer(1):
						self.deletescan([tgt])
						self.updateScans()
						target_ids.extend(self.getTargetID(tgt))
					else:
						continue
				else:
					target_ids.extend(self.getTargetID(tgt))

				
		except Exception as e:
			print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
			traceback.print_exc()
		
		return self.startscan_ids(target_ids)
				

	
	def startscan_ids(self, ids):
		'''
			11111111-1111-1111-1111-111111111112    High Risk Vulnerabilities          
			11111111-1111-1111-1111-111111111115    Weak Passwords        
			11111111-1111-1111-1111-111111111117    Crawl Only         
			11111111-1111-1111-1111-111111111116    Cross-site Scripting Vulnerabilities       
			11111111-1111-1111-1111-111111111113    SQL Injection Vulnerabilities         
			11111111-1111-1111-1111-111111111118    quick_profile_2 0   {"wvs": {"profile": "continuous_quick"}}            
			11111111-1111-1111-1111-111111111114    quick_profile_1 0   {"wvs": {"profile": "continuous_full"}}         
			11111111-1111-1111-1111-111111111111    Full Scan   1   {"wvs": {"profile": "Default"}}         
		'''
		
		target_ids = []
		try:
			for id in ids:
				config = self.getScanConfig(id)
				try:
					response = requests.post(self.url+"/api/v1/scans",data=json.dumps(config),headers=self.headers,timeout=30,verify=False)
					result = json.loads(response.content)
					target_ids.append(result['target_id'])
					print(f"{Fore.GREEN}Successfuly started scan against {Fore.LIGHTCYAN_EX}{self.getTargetURL(id)}{Style.RESET_ALL}")
				except Exception as e:
					print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
					traceback.print_exc()
		except Exception as e:
			print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
			traceback.print_exc()

		return target_ids
				

	def deletescan(self,targets):
		target_ids = []
		urls = self.existingScanURLs()
		try:
			if getConfirmationAnswer(3):
				for tgt in targets:
					if tgt in urls:					
						for delscan in self.getScanID(tgt):
							try:
								response = requests.delete(self.url+"/api/v1/scans/"+str(delscan),headers=self.headers,timeout=30,verify=False)
								if response.status_code == 204:
									print(f"{Fore.GREEN}Successfuly deleted the scan of {Fore.LIGHTCYAN_EX}{tgt}{Fore.GREEN} having id {Fore.LIGHTCYAN_EX}{delscan}{Style.RESET_ALL}")
									target_ids.append(delscan)
								else:
									print(f"{Fore.RED}Invalid Response against the scan of {Fore.LIGHTCYAN_EX}{tgt}{Fore.RED} having id {Fore.LIGHTCYAN_EX}{delscan}{Style.RESET_ALL}")
							except Exception as e:
								print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
								traceback.print_exc()
					else:
						print(f"{Fore.RED}No Scan found against {Fore.YELLOW}{tgt}{Style.RESET_ALL}")
			else:
				pass				
		except Exception as e:
			print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
			traceback.print_exc()

		return target_ids


	def stopscan(self,targets):
		target_ids = []
		urls = self.existingScanURLs()
		try:
			for tgt in targets:
				if tgt in urls:					
					for stopscan in self.getScanID(tgt):
						try:
							response = requests.post(self.url+"/api/v1/scans/"+str(stopscan)+"/abort",headers=self.headers,timeout=30,verify=False)
							if response.status_code == 204:
								print(f"{Fore.GREEN}Successfuly stopped the scan of {Fore.LIGHTCYAN_EX}{tgt}{Fore.GREEN} having id {Fore.LIGHTCYAN_EX}{stopscan}{Style.RESET_ALL}")
								target_ids.append(stopscan)
							else:
								print(f"{Fore.RED}Invalid Response against the scan of {Fore.LIGHTCYAN_EX}{tgt}{Fore.RED} having id {Fore.LIGHTCYAN_EX}{stopscan}{Style.RESET_ALL}")
						except Exception as e:
							print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
							traceback.print_exc()
				else:
					print(f"{Fore.RED}No Scan found against {Fore.LIGHTCYAN_EX}{tgt}{Style.RESET_ALL}")
				
		except Exception as e:
			print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
			traceback.print_exc()

		return target_ids


	def getScanConfig(self,target_id):
		config = { "profile_id": "11111111-1111-1111-1111-111111111111", "incremental": False, "schedule": { "disable": False, "start_date": None, "time_sensitive": False }, "user_authorized_to_scan": "yes", 
		"target_id": target_id }
		return config

	def getTgtConfig(self):
		software_names = [SoftwareName.CHROME.value]
		operating_systems = [OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value]   

		user_agent_rotator = UserAgent(software_names=software_names, operating_systems=operating_systems, limit=100)
  
		# Get Random User Agent String.
		user_agent = user_agent_rotator.get_random_user_agent()
  
		config = {
            "excluded_paths":[],
            "user_agent": user_agent,
            #"custom_headers":["Accept: */*","Referer:"+self.url,"Connection: Keep-alive"],
			"custom_headers":[],
            #"custom_cookies":[{"url":self.url,"cookie":"UM_distinctid=15da1bb9287f05-022f43184eb5d5-30667808-fa000-15da1bb9288ba9; PHPSESSID=dj9vq5fso96hpbgkdd7ok9gc83"}],
			"custom_cookies":[],
            "scan_speed":"slow",#sequential/slow/moderate/fast more and more fast
            "technologies":[],#ASP,ASP.NET,PHP,Perl,Java/J2EE,ColdFusion/Jrun,Python,Rails,FrontPage,Node.js
			"limit_crawler_scope":False,
            #代理
            "proxy": {
                "enabled":False,
                "address":"127.0.0.1",
                "protocol":"http",
                "port":8080,
                "username":"",
                "password":""
            },
            #无验证码登录
            "login":{
                "kind": "none",
                "credentials": {
                    "enabled": False, 
                    "username": "test", 
                    "password": "test"
                }
            },
            #401认证
            "authentication":{
                "enabled":False,
                "username":"test",
                "password":"test"
            }
        }
		return config

	def acunetixSettings(self):
		print(f"{Fore.BLUE}Configured Settings: {Style.RESET_ALL}")
		print(f"URL: {Fore.LIGHTBLUE_EX}{self.url}{Style.RESET_ALL}")
		print(f"Authentiaction: {Fore.LIGHTBLUE_EX}{self.headers}{Style.RESET_ALL}")
		


def getConfirmationAnswer(opt):	
	while True:
		answer = None
		if opt == 1:
			answer = input(f"{Fore.RED}Warning: Scan already exists, do you wish to delete existing scan and create new scan (y/n): {Style.RESET_ALL}")
		elif opt == 2:
			answer = input(f"{Fore.RED}Warning: All targets matching the Address will be deleted. Do you wish to continue (y/n): {Style.RESET_ALL}")
		elif opt == 3:
			answer = input(f"{Fore.RED}Warning: All Scans matching the Address will be deleted. Do you wish to continue (y/n): {Style.RESET_ALL}")
		elif opt == 4:
			answer = input(f"{Fore.RED}Warning: All Reports matching the Address will be deleted. Do you wish to continue (y/n): {Style.RESET_ALL}")
		elif opt == 5:
			answer = input(f"{Fore.RED}Warning: Target list exceeding 4 which will likely overload the server. Do you wish to continue (y/n): {Style.RESET_ALL}")
		else:
			answer = 'n'

		if answer == "Y" or answer=="y":
			return True
		elif answer == "N" or answer=="n":
			return False
		else:
			print("Enter valid choice")


def print_logo(clear=True):
	if clear:
		system("cls" if platform() == "Windows" else "clear")

	logo = Figlet(font="slant").renderText("Acunetix Operator")
	print (Fore.LIGHTYELLOW_EX + logo + Style.RESET_ALL)
	print ("\n--------------------------------------------------------------------------------------------------")

def setParser():
	parser = argparse.ArgumentParser(description='Interact with Acunetix scanner using API')
	target = parser.add_mutually_exclusive_group(required=True)
	target.add_argument("--targets", "-t", type=argparse.FileType('r') ,help="Complete path to text file containing \
		line seperated URL addresses for scanning.")
	target.add_argument("--url", "-u", type=str , help="URL address for scanning.")

	tgroup = parser.add_mutually_exclusive_group(required=False)
	tgroup.add_argument("--groups", "-gs", type=argparse.FileType('r') ,help="Complete path to text file containing \
		line seperated Group Names for scanning.")
	tgroup.add_argument("--group", "-g", type=str , help="Group Name for target.")

	parser.add_argument("--iscan", "-i", default=False, action="store_true" , help="Start scan immidiatly against provided URLs.")
	parser.add_argument("--verbose", "-v", default=False, action="store_true" , help="Verbose will print IDs of the operations requested.")

	# Scan
	action = parser.add_mutually_exclusive_group(required=True)
	action.add_argument("--addtarget", "-at",  default=False, action="store_true" ,help="Add target for Provided URL address(es).")
	action.add_argument("--deltarget", "-dt",   default=False, action="store_true" ,help="Del target for Provided URL address(es).")
	action.add_argument("--startscan", "-sa",  default=False, action="store_true" ,help="Stop Scan for Provided URL address(es).")
	action.add_argument("--stopscan", "-ss",   default=False, action="store_true" ,help="Stop Scan for Provided URL address(es).")
	action.add_argument("--delscan", "-ds",   default=False, action="store_true" ,help="Delete Scan for Provided URL address(es).")
	action.add_argument("--status", "-s",  default=False, action="store_true" , help="Status of Scan for Provided URL address(es).")
	# action.add_argument("--genreport", "-gr",  default=False, action="store_true" ,help="Generate Report for Provided URL address(es).")
	# action.add_argument("--getReport", "-r",  default=False, action="store_true" ,help="Get Report for Provided URL address(es).")
	# action.add_argument("--delReport", "-dr",  default=False, action="store_true" ,help="Delete Report for Provided URL address(es).")

	args = parser.parse_args()
	return args


def getArgs(args):
	paramerters = {
		"target":"",
		"group":"",
		"exists":False,
		"iscan":False,
		"action":"",
		"verbose":False,
	}
	if args.url is not None:
		targets = []
		targets.append(args.url)
		paramerters["target"] = targets
	elif args.targets is not None:
		targets= []
		with args.targets as file:
			lines = file.readlines()
			for l in lines:
				targets.append(l.strip())
		paramerters["target"] = targets
		
	if args.group is not None:
		groups = []
		groups.append(args.group)
		paramerters["group"] = groups
	elif args.groups is not None:
		groups = []
		with args.groups as file:
			lines = file.readlines()
			for l in lines:
				groups.append(l.strip())
		paramerters["group"] = groups


	if args.iscan:
		paramerters["iscan"] = True
	if args.verbose:
		paramerters["verbose"] = True

	if args.addtarget:
		paramerters["action"] = "addtarget"
	elif args.deltarget:
		paramerters["action"] = "deltarget"
	elif args.startscan:
		paramerters["action"] = "startscan"
	elif args.stopscan:
		paramerters["action"] = "stopscan"
	elif args.delscan:
		paramerters["action"] = "delscan"

	return paramerters


def chunks(my_list, n):
    final = [my_list[i * n:(i + 1) * n] for i in range((len(my_list) + n - 1) // n )]
    return final

def process(par):
	acunetix = Acunetix(None)
	
	verbose = par["verbose"]

	if verbose:
		acunetix.setverbose(True)

	if par["action"] == "addtarget":
		ids = acunetix.addtarget(par["target"])
		sleep(1)
		acunetix.updateTargets()

		if verbose:
			print(f"{Fore.LIGHTBLUE_EX}Printing IDs of the Targets.{Style.RESET_ALL}")
			print(ids)

		if par["group"]:
			group = acunetix.addGroup(par["group"])
			if verbose:
				print(f"{Fore.LIGHTBLUE_EX}Printing IDs of the Groups.{Style.RESET_ALL}")
			sleep(1)
			print(group)
			acunetix.updateGroups()
			acunetix.addTargetsToGroup(group, ids)

			

		if par["iscan"]:
			scans = acunetix.startscan_ids(ids)
			acunetix.updateScans()
			if verbose:
				print(f"{Fore.LIGHTBLUE_EX}Printing IDs of the Scans.{Style.RESET_ALL}")
				print(scans)

	elif par["action"] == "deltarget":
		ids = acunetix.deltarget(par["target"])
		acunetix.updateTargets()

		if len(ids) == 0:
			print(f"{Fore.RED}No target Found on acunetix Server.{Style.RESET_ALL}")
		
		if verbose:
			print(f"{Fore.LIGHTBLUE_EX}Printing IDs of the deleted Targets.{Style.RESET_ALL}")
			print(ids)

	elif par["action"] == "startscan":
		ids = acunetix.startscan(par["target"])
		acunetix.updateScans()
		if verbose:
			print(f"{Fore.LIGHTBLUE_EX}Printing IDs of the Scans Started.{Style.RESET_ALL}")
			print(ids)
		
	elif par["action"] == "stopscan":
		ids = acunetix.stopscan(par["target"])
		acunetix.updateScans()
		if verbose:
			print(f"{Fore.LIGHTBLUE_EX}Printing IDs of the Scans Stoped.{Style.RESET_ALL}")
			print(ids)
		
	elif par["action"] == "delscan":
		ids = acunetix.deletescan(par["target"])
		acunetix.updateScans()
		if verbose:
			print(f"{Fore.LIGHTBLUE_EX}Printing IDs of the Deleted Scans.{Style.RESET_ALL}")
			print(ids)
		


def main():
	print_logo()
	args = setParser()		# Argument Parser
	par = getArgs(args)		# Process Args passed

	colorama_init()			# setting colored terminal	

	process(par)


if __name__ == '__main__':
	main()

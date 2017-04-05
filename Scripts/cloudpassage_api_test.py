#This program is the test for cloudpassage API functionality
import sys, base64, requests, json, csv, datetime,xlsxwriter

#Function calls the api and grabs all the asset information about the servers
def harvest_server_info(token):
	url = "https://api.cloudpassage.com/v1/servers?state=active"
	r = requests.get(url, headers={"Authorization": "Bearer %s" %token})
	decode = json.loads(r.text)
	return decode
#Function grabs vuln scan info for all servers
def get_vuln_scan_results(token, server_info):
#Opens Excel for writing 
	book = xlsxwriter.Workbook(	"vulnscan.xlsx")
	sheet = book.add_worksheet("Sheet 1")
	header = ["Hostname","IP Address","Package Name","Version Level","Critical","CVE","CVSS Score", "Type"]
	sheet.write_row(0,0,header)
#Gets vuln info 
	num_servers = len(server_info["servers"])
	x = 0
	a = 1
#	important_list = ["Authentication Issues CWE-287","Command Injection CWE-77", "Credentials Management CWE-255", "Cryptographic Issues CWE-310", "Permissions, Privileges, and Access Control CWE-264", "OS Command Injections CWE-78" , "SQL Injection CWE-89"]
	important_list = ["Authentication Issues CWE-287","Authentication Issues CWE-287", "Buffer Errors CWE-119", "Code CWE-17" ,"Code Injection CWE-94","Command Injection CWE-77"
,"Configuration	CWE-16","Credentials Management	CWE-255","Cross-Site Request Forgery (CSRF)	CWE-352","Cross-Site Scripting (XSS) CWE-79","Cryptographic Issues CWE-310"
,"Data Handling	CWE-19","Format String Vulnerability CWE-134","Improper Access Control CWE-284","Indicator of Poor Code Quality	CWE-398"
,"Information Leak / Disclosure	CWE-200","Information Management Errors	CWE-199","Injection	CWE-74","Input Validation WE-20"
,"Insufficient Information	NVD-CWE-noinfo","Insufficient Verification of Data Authenticity	CWE-345","Link Following CWE-59","Location CWE-1"
,"Numeric Errors CWE-189","OS Command Injections CWE-78","Other	NVD-CWE-Other","Path Equivalence CWE-21","Path Traversal	CWE-22"
,"Permissions, Privileges, and Access Control CWE-264","Race Conditions	CWE-362","Resource Management Errors CWE-399","Security Features CWE-254"
,"Source Code CWE-18","SQL Injection CWE-89","Time and State CWE-361"]
	while x < num_servers:
		url = "https://api.cloudpassage.com/v1/servers/%s/svm" %(server_info["servers"][x]["id"])
		r = requests.get(url, headers={"Authorization": "Bearer %s" %token})
		decoded = json.loads(r.text)
		vuln_length = len(decoded["scan"]["findings"])
		z = 0
		if "10.129" in server_info["servers"][x]["primary_ip_address"]:
			while z < vuln_length:
				if 'bad' in decoded["scan"]["findings"][z]["status"]:
					cve = calc_high_cvss(decoded,z)
					summary = get_cwe_id(cve[0], token)
					if summary in important_list:
						dump = [server_info["servers"][x]["hostname"],server_info["servers"][x]["primary_ip_address"],decoded["scan"]["findings"][z]["package_name"],decoded["scan"]["findings"][z]["package_version"],decoded["scan"]["findings"][z]["critical"],cve[0],cve[1],summary]
						sheet.write_row(a,0,dump)
						a +=1
				z+=1
		z = 0
		x += 1
	book.close()
def get_cwe_id(cve, token):
	url = "https://api.cloudpassage.com/v1/cve_details/%s" %(cve)
	r = requests.get(url, headers={"Authorization": "Bearer %s" %token})
	decoded = json.loads(r.text)
	cwe_list = ["Authentication Issues CWE-287","Authentication Issues CWE-287", "Buffer Errors CWE-119", "Code CWE-17" ,"Code Injection CWE-94","Command Injection CWE-77"
,"Configuration	CWE-16","Credentials Management	CWE-255","Cross-Site Request Forgery (CSRF)	CWE-352","Cross-Site Scripting (XSS) CWE-79","Cryptographic Issues CWE-310"
,"Data Handling	CWE-19","Format String Vulnerability CWE-134","Improper Access Control CWE-284","Indicator of Poor Code Quality	CWE-398"
,"Information Leak / Disclosure	CWE-200","Information Management Errors	CWE-199","Injection	CWE-74","Input Validation WE-20"
,"Insufficient Information	NVD-CWE-noinfo","Insufficient Verification of Data Authenticity	CWE-345","Link Following CWE-59","Location CWE-1"
,"Numeric Errors CWE-189","OS Command Injections CWE-78","Other	NVD-CWE-Other","Path Equivalence CWE-21","Path Traversal	CWE-22"
,"Permissions, Privileges, and Access Control CWE-264","Race Conditions	CWE-362","Resource Management Errors CWE-399","Security Features CWE-254"
,"Source Code CWE-18","SQL Injection CWE-89","Time and State CWE-361"]
	for item in cwe_list:
		if str(decoded["cwe_id"]) in str(item):
			return item
def calc_high_cvss(decoded,z):
	cve_len = len(decoded["scan"]["findings"][z]["cve_entries"])
	x = 0
	while x < cve_len:
		cve_entry = decoded["scan"]["findings"][z]["cve_entries"][x]["cve_entry"]
		cvss_score = decoded["scan"]["findings"][z]["cve_entries"][x]["cvss_score"]
		cve = [cve_entry, cvss_score]
		if cvss_score > decoded["scan"]["findings"][z]["cve_entries"][x]["cvss_score"]:
			cve_entry = decoded["scan"]["findings"][z]["cve_entries"][x]["cve_entry"]
			cvss_score = decoded["scan"]["findings"][z]["cve_entries"][x]["cvss_score"]
			cve = [cve_entry, cvss_score]
		x += 1
	return(cve)	
def get_date():
	today = datetime.date.today()
	today = today.strftime('%m-%d-%Y')
	yesterday = datetime.date.today() - datetime.timedelta(days=1) 
	yesterday= yesterday.strftime('%m-%d-%Y')
def main():
	url = "https://api.cloudpassage.com/oauth/access_token?grant_type=client_credentials"
	encoded = base64.b64encode("a68ead71:86fe2a2b036539b0bf94f4f90590b5a1")
	r = requests.post(url, headers={"Authorization": "Basic %s" %encoded})
	decoded = json.loads(r.text)
	server_info = harvest_server_info(decoded["access_token"])
#	get_users(decoded["access_token"])
	get_vuln_scan_results(decoded["access_token"], server_info)

if __name__ == "__main__":
	sys.exit(main())
	

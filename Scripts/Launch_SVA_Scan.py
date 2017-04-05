#This program launches a SVA scan for a single instance
#USE IS AS FOLLOWS: ./Launch_SVA_Scan.py <hostname>
import sys, base64, requests, json, csv, datetime, time

def harvest_server_info(token,hostname):
	url = "https://api.cloudpassage.com/v1/servers?hostname=%s" %(hostname)
	r = requests.get(url, headers={"Authorization": "Bearer %s" %token})
	decode = json.loads(r.text)
	return decode
def launch_scan(token, server_info):
	url = "https://api.cloudpassage.com/v1/servers/%s/scans" %(server_info["servers"][0]["id"])
	data = json.dumps({"scan": {"module": "svm"}})
	r = requests.post(url, data, headers={"Authorization": "Bearer %s" %token, "Content-Type": "application/json"})
def fetch_latest_scan(token, server_info):
	#waits for scan to finish 
	time.sleep(120)
	url =  "https://api.cloudpassage.com/v1/servers/%s/svm" %(server_info["servers"][0]["id"])
	r = requests.get(url, headers={"Authorization": "Bearer %s" %token, "Content-Type": "application/json"})
	decode = json.loads(r.text)
	print "Critical Findings Count: " + str(decode["scan"]["critical_findings_count"])
	print "High Findings Count: " + str(decode["scan"]["non_critical_findings_count"])
def main():
	hostname = sys.argv[1]
	url = "https://api.cloudpassage.com/oauth/access_token?grant_type=client_credentials"
	encoded = base64.b64encode("a68ead71:86fe2a2b036539b0bf94f4f90590b5a1")
	r = requests.post(url, headers={"Authorization": "Basic %s" %encoded})
	decoded = json.loads(r.text)
	server_info = harvest_server_info(decoded["access_token"],hostname)
	launch_scan(decoded["access_token"], server_info)
	fetch_latest_scan(decoded["access_token"], server_info)
if __name__ == "__main__":
	sys.exit(main())
	

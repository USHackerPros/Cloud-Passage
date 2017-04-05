#This program
#USE IS AS FOLLOWS: ./ICHS_Metadata_Export.py
# Todo:
# P1 enumerate SG Objects
# - include report of files out of baseline
# - optimize API calls
# - include Bit9 enforcement state
# - create summary/dashboard tab auto-generated in excel that has management view
import sys, base64, requests, json, csv, datetime, time, boto.ec2, xlsxwriter

def to_lower(d):
	#convert scalar to
	return dict((k.lower(), v) for k, v in d.iteritems())
def get_aws_ips(cp_ips, token):
	#build excel file for output
	dtm = datetime.datetime.now()
	xlsxname = "tags_report_" + dtm.isoformat() + ".xlsx"
	book = xlsxwriter.Workbook(xlsxname)
	sheet = book.add_worksheet("Tagging Report")
	header = ["AWS Instance ID","IP","Hostname","Env Tag","Owner","ARN","AMI ID","Instance Type","Launch Time","Age","VPC ID","Virtualization Type","Friendly Name","Platform","Kernel Ver","Security Groups","Autoscale Group","CloudPassage Group","CP State","CP Daemon Version","CP Self-Verify Failed","CP Last State Change","Last Scan","Critical Vulns", "High Vulns","FIM Crit Delta","FIM High Delta"]
	sheet.write_row(0,0,header)
	#build excel formula (text here, interperted by excel client)
	agefm = "=NOW()-CONCATENATE(LEFT(INDIRECT(\"RC[-1]\",0),10),\" \",MID(INDIRECT(\"RC[-1]\",0),12,8))"
	conn = boto.ec2.connect_to_region('us-west-2',aws_access_key_id='AKIAJZCS2M5MP7JFV5ZA', aws_secret_access_key='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')
	reservations = conn.get_all_instances()
	instances = [i for r in reservations for i in r.instances]
	vulns_inventory = []
	#	reset aws ip array
	aws_running_ips = []
	a = 1
	#iterate through AWS IPs to get instance and tag data.  env = tag data, i = instance object
	for i in instances:
		if "running" in str(i.__dict__["_state"]):
			#instance data
			ins_id = i.__dict__["id"]
			ami_id = i.__dict__["image_id"]
			type = i.__dict__["instance_type"]
			launchtm = i.__dict__["launch_time"]
			prvip = i.__dict__["private_ip_address"]
			prvdns = i.__dict__["private_dns_name"]
			vpc_id = i.__dict__["vpc_id"]
			virt_ty = i.__dict__["virtualization_type"]
			knl = i.__dict__["kernel"]
			pltfm = i.__dict__["platform"]
			sgsobj = i.__dict__["groups"]
			sgs = ""
			
			#grab name data to make security group info human-readable
			for z in sgsobj:
				sgs = sgs + z.name + ", "

			#extract from tagging data
			text = i.__dict__["tags"]
			env = to_lower(text)
			if "env" in env:
				tgenv = env["env"]
			else:
				tgenv = "N/A"

			if "hostname" in env:
				tghstnm = env["hostname"]
			else:
				tghstnm = "N/A"

			if "aws:cloudformation:stack-id" in env:
				arnid = env["aws:cloudformation:stack-id"]
			else:
				arnid = "N/A"

			if "aws:autoscaling:groupName" in env:
				asgrp = env["aws:autoscaling:groupName"]
			else:
				asgrp = "N/A"
			
			if "owner" in env:
				owrnm = env["owner"]
			else:
				owrnm = "N/A"
			
			if "name" in env:
				tgname = env["name"]
			else:
				tgname = "N/A"
			
			#enumerate the CP data
			if prvip in (x[0] for x in cp_ips):
				x = [g for g, x in enumerate(cp_ips) if x[0] == prvip][0]
				cp_grp = cp_ips[x][1]
				cp_state = cp_ips[x][2]
				cp_ver = cp_ips[x][3]
				cp_verify = cp_ips[x][4]
				cp_last_chg = cp_ips[x][5]

				# SVM Components
				url =  "https://api.cloudpassage.com/v1/servers/%s/svm" %(cp_ips[x][6])
				r = requests.get(url, headers={"Authorization": "Bearer %s" %token, "Content-Type": "application/json"})
				decode_svm = json.loads(r.text)
				cp_crit_vulns = decode_svm["scan"]["critical_findings_count"]
				cp_high_vulns = decode_svm["scan"]["non_critical_findings_count"]
				cp_lastscan = decode_svm["scan"]["completed_at"]
				for item in decode_svm["scan"]["findings"]:
					if "bad" in item["status"]:

						svm_cve = "CVE Test"
						svm_cvss = "CVSS Test"
						svm_package = item["package_name"]
						svm_ver = item["package_version"]
						svm_crit = item["critical"]
						svm_cve = ""
						svm_cvss = ""
						for cve in item["cve_entries"]:
							svm_cve = svm_cve + cve["cve_entry"] + "; "
							svm_cvss = svm_cvss + str(cve["cvss_score"]) + "; "
						vulns_inventory.append([prvip,svm_cve,svm_package,svm_ver,svm_cvss,str(svm_crit)])
				
				# FIM Components
				url =  "https://api.cloudpassage.com/v1/servers/%s/fim" %(cp_ips[x][6])
				r = requests.get(url, headers={"Authorization": "Bearer %s" %token, "Content-Type": "application/json"})
				decode_fim = json.loads(r.text)
				if "scan" in decode_fim:
					cp_fim_crit = decode_fim["scan"]["critical_findings_count"]
					cp_fim_high = decode_fim["scan"]["non_critical_findings_count"]
				else:
					#need to investigate why scans are not run
					cp_fim_crit = "Scan not run"
					cp_fim_high = "Scan not run"
			#we don't have a CP record.
			else:
				cp_grp = "N/A"
				cp_state = "N/A"
				cp_ver = "N/A"
				cp_verify = "N/A"
				cp_last_chg = "N/A"
				cp_crit_vulns = "N/A"
				cp_high_vulns = "N/A"
				cp_lastscan = "N/A"
				cp_fim_crit = "N/A"
				cp_fim_high = "N/A"
			
			dump = (ins_id,prvip,prvdns,tgenv,owrnm,arnid,ami_id,type,launchtm,agefm,vpc_id,virt_ty,tgname,pltfm,knl,sgs,asgrp,cp_grp,cp_state,cp_ver,cp_verify,cp_last_chg,cp_lastscan,cp_crit_vulns,cp_high_vulns,cp_fim_crit,cp_fim_high)
			sheet.write_row(a,0,dump)
			#print "Completed " + str(a) + " of " + str(len(instances)) + ". Token life remaining: " + str(900 - (time.time() - startTime))
			a += 1
			

	# extract vuln info into workbook
	vh_head = ["IP","CWE","Component","Ver","CVSS","Critical"]
	vulns_sheet = book.add_worksheet("Vuln Report")
	vulns_sheet.write_row(0,0,vh_head)
	a = 1
	for item in vulns_inventory:
		dump = (item[0],item[1],item[2],item[3],item[4],item[5])
		vulns_sheet.write_row(a,0,dump)
		a += 1
	book.close()
	
	return aws_running_ips

def get_cp_ips(token):
	url = "https://api.cloudpassage.com/v1/servers?state=active"
	r = requests.get(url, headers={"Authorization": "Bearer %s" %token, "Content-Type": "application/json"})
	decode = json.loads(r.text)
	cp_ips = []
	for item in decode["servers"]:
		#	if "10.129" in item["primary_ip_address"]:
		cp_ips.append([item["primary_ip_address"],item["group_name"],item["state"],item["daemon_version"],item["self_verification_failed"],item["last_state_change"],item["id"]])
	return cp_ips

def main():
	url = "https://api.cloudpassage.com/oauth/access_token?grant_type=client_credentials"
	
	encoded = base64.b64encode("b75f1e88:698ef5944c53c35553360c19c10f8693")
	r = requests.post(url, headers={"Authorization": "Basic %s" %encoded})
	decoded = json.loads(r.text)
	global startTime
	startTime = time.time()
	print "CP Token expires in: " + str(decoded["expires_in"])
	cp_ips = get_cp_ips(decoded["access_token"])
	aws_running_ips = get_aws_ips(cp_ips, decoded["access_token"])
	print "Time to execute: "+ str(time.time() - startTime)
if __name__ == "__main__":
	sys.exit(main())

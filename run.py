# Owner : Jayesh Patel
import os
import socket
from BeautifulSoup import BeautifulSoup as BS
import urllib2 
import argparse
import time
import datetime
import re
import sys
import json
import configparser
import logging
import lib.logfile
import subprocess
import commands
from pexpect import pxssh
import pexpect
import requests
import yaml


logger = logging.getLogger('main')

class evader_test():
	def __init__(self, dst_ip, path_pcap, fd, payload_file, test_type, testName, input_type, input_testcase, enable_ssl):
		self.dst_ip = dst_ip
		self.server_ip = self.get_ip_address()
		self.path_pcap = path_pcap
		self.fd = fd
		self.test_type = test_type
		self.payload_file = payload_file
		self.input_type = input_type
		self.input_testcase = input_testcase
		self.enable_ssl = enable_ssl
		self.testName = testName

		if self.enable_ssl == "yes":
			self.protocol_sup = "https"
		else:
			self.protocol_sup = "http"
			

		print "file path report %s" % self.fd
		self.percent_sign = str("%26")

		self.attack_list = []
		self.app = configparser.ConfigParser()
		self.app.read('appliance.conf')
		self.email_addr = self.app.get('list','email_addr')

		print self.email_addr


	def traffic(self, url, headers1):
		try:
			self.response_data = ""
			if self.enable_ssl == "yes":
                		response = requests.get(url, headers=headers1, verify=False)
			else:
                		response = requests.get(url, headers=headers1)

			self.response_data = response.content
                	return response
		except Exception as err:
			return err

	def get_ip_address(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("8.8.8.8", 80))
		return s.getsockname()[0]	


	def check_response(self, data):
		print "data_content %s" % data
		if ('Error code 404.') in data:
        		return "Not Found"
		else:
			return "Found"


	def array_attack(self, attack):
		app1 = configparser.ConfigParser()
                app1.read('attack_list.conf')
		attack1 = app1.get('alist',attack)
		self.attack_list = attack1.split(';')

	def payload(self):
		if self.input_type == "file":
			with open("%s" % self.payload_file) as attack:
				self.payload_list = attack.read().splitlines()
		else:
			self.payload_list = []
			self.payload_list.append(self.payload_file)
			print "jayesh %s " % self.payload_list

	def html_evasion_type(self):
		with open(self.input_testcase) as attack:
			self.html_evasion_type_list = attack.read().splitlines()

	def get_report(self):
                if self.input_type == "file":
                        os.system("./report2.sh %s %s %s > %s.html" % (self.testName, self.fd, self.server_ip, self.testName))
                        print "./report2.sh %s %s %s > %s.html" % (self.testName, self.fd, self.server_ip, self.testName)
                else:
                        os.system("./report3.sh %s %s %s %s.csv > %s.html" % (self.testName, self.fd, self.server_ip, self.payload_file, self.testName))
                        print "./report3.sh %s %s %s %s.csv > %s.html" % (self.testName, self.fd, self.server_ip, self.payload_file, self.testName)


	def get_email(self):
		os.system("echo \"$(cat %s.html)\" | mail -s \"%s - HTML Evasion Sanity Results\" -a \"From: htmlEvasion@jays-tech.com\" -a \"MIME-Version: 1.0\" -a \"Content-Type: text/html\" %s" % (self.testName, self.testName, self.email_addr))
		

	
	def get_command(self):

		self.payload()
		self.html_evasion_type()

		for html_evasion_type in self.html_evasion_type_list:

		    testcase_name = html_evasion_type.split(',')[0]
		    html_evasion_name = html_evasion_type.split(',')[1]
		    compress_evasion = html_evasion_type.split(',')[2]
		    chunked_evasion = html_evasion_type.split(',')[3]
		    utf_evasion = html_evasion_type.split(',')[4]
		    padding = html_evasion_type.split(',')[5]


		    if chunked_evasion != "None":
			header_values1 = "'Content-Encoding': 'chunked'"
			header_values1r = '--header="Content-Encoding: chunked"'

		    if compress_evasion != "None":
			header_values1 = "'Content-Encoding': '%s'" % compress_evasion
			header_values1r = '--header="Content-Encoding: %s"' % compress_evasion
			
		    if chunked_evasion != "None" and compress_evasion != "None":
			header_values1 = "'Content-Encoding': '%s, chunked'" % compress_evasion
			header_values1r = '--header="Content-Encoding: %s, chunked"' % compress_evasion

		    if chunked_evasion == "None" and compress_evasion == "None":
			header_values1 = "'Content-Encoding': 'default'"
			header_values1r = '--header="Content-Encoding: default"'

		    if utf_evasion != "None" :
			header_values2 = "'Content-Type': 'text/html, charset=%s'" % utf_evasion
			header_values2r = '--header="Content-Type: text/html, charset=%s"' % utf_evasion

		    if utf_evasion == "None" :
			header_values2 = "'Content-Type': 'text/html'"
			header_values2r = '--header="Content-Type: text/html"'

			
		    header_value = "{%s, %s, 'Connection': 'keep-alive'}" % (header_values1, header_values2)
		    header_valuesr = header_values1r + " " + header_values2r
	 	    header_values = yaml.load(header_value)
            
		    for file_name in self.payload_list:
			run_command = "%s://%s/%s?type=%s%sevasion=%s%scompress=%s%schunked=%s%scharacterset=%s%spadding=%s" %(self.protocol_sup, self.dst_ip, file_name, self.test_type, self.percent_sign, html_evasion_name, self.percent_sign, compress_evasion, self.percent_sign, chunked_evasion, self.percent_sign, utf_evasion, self.percent_sign, padding)
			print run_command


			result = self.traffic(run_command, header_values)


			r1 = re.search(r'Connection reset by peer', str(result))
			if r1:
        			attack_result = "PASS"

			r2 = re.search(r'Response \[200\]', str(result))
			if r2:
        			attack_result = "FAILED"
				"""
	                        if testcase_name == "plain-poc":
        	                        self.payload_list.remove(file_name)
				"""

			check_status = self.check_response(self.response_data)


			if check_status != "Found":
				attack_result = "EvasionError"
				"""
                        	if testcase_name == "plain-poc":
                                	self.payload_list.remove(file_name)

				"""

			if not r1 and not r2 and check_status == "Found":
				attack_result = "EvasionError"
				"""
	                        if testcase_name == "plain-poc":
                	                self.payload_list.remove(file_name)
				"""
					
			final_report = testcase_name + ";" + html_evasion_name +";"+ file_name +";"+ compress_evasion + ";" + chunked_evasion + ";" + utf_evasion + ";"+ attack_result + ";" + "wget " + header_valuesr + " " +run_command
			print final_report
			self.fo1 = open(self.path_pcap+"/html_"+file_name +".csv", "a") 
			self.fo1.write(final_report+"\n")
			self.fo1.close()
		
		self.get_report()
		time.sleep(10)
		print "================================= Completed ========================================="
		print "Report Directory %s" % self.path_pcap
		print "Final HTMl Report %s.html" % self.testName 
		print "================================= Completed ========================================="
		self.get_email()


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Pass Argument')
	parser.add_argument('dip', type=str, metavar='Destination IP', help='Enter Destination IP')
	parser.add_argument('payload_file', type=str, metavar='Payload File Name', help='Enter Payload File Name')
	parser.add_argument('test_type', type=str, metavar='Enter Test Type', help='Enter Test Type html/js')
	parser.add_argument('report_path', type=str, metavar='Enter Report path', help='Enter Report Path')
	parser.add_argument('testName', type=str, metavar='Enter Test Name', help='Enter Test Name which is report name')
	parser.add_argument('input_type', type=str, metavar='Payload Input type', help='Payload Input Type (file/payload)')
	parser.add_argument('input_testcase', type=str, metavar='Input Tescase File', help='Input Test Case File')
	parser.add_argument('enable_ssl', type=str, metavar='Enable SSL Support', help='Enable SSL Support yes/no')

	args = parser.parse_args()

        if args.report_path == "None":
                fd = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
		print fd
                mydir = os.path.join(os.getcwd()+"/report/"+fd)
                path_report = mydir
        else:
		fd = args.report_path.split('/')[1]
                mydir = os.path.join(args.report_path)
                path_report = mydir


	os.system("rm -rf %s/done" % mydir)

	if not os.path.exists(mydir):
        	os.makedirs(mydir)

	res = evader_test(args.dip, path_report, fd, args.payload_file, args.test_type, args.testName, args.input_type, args.input_testcase, args.enable_ssl)
	print res.get_command()
	os.system("touch %s/done" % mydir)
	

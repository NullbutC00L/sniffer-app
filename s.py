import pcapy
import time	
import random
import datetime	
#Virustotal iimport	
import requests
import _thread



devices=pcapy.findalldevs()

print (devices)


##not tested at all
def VirusTotalApi():
	print('got here')
	#params = {'apikey': '-YOUR API KEY HERE-'}
	#files = {'file': ('myfile.exe', open('myfile.exe', 'rb'))}
	#response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
	json_response = 'a'#response.json()

	f=open('responses.json','a')
	f.write(json_response)
	f.close()

def live_capture():
	cap = pcapy.open_live("any" , 65536 , 1 , 0)
	dumper= cap.dump_open('scans/'+str(datetime.datetime.now())+'.pcap')
	size=0
	while(size<=120000000):
		(header,packet)=cap.next()
		dumper.dump(header,packet)
		size=size+20+header.getcaplen()
		print(str(header.getcaplen())+'final-->'+str(size))
	dumper.close()
	try:
		_thread.start_new_thread(VirusTotalApi,())	
	except:
		print('error while thread was going nuts')
		

def random_starter():
	periodicity=1

	print()

	#time.sleep(random.randint(10*periodicity,120*periodicity))
	live_capture()

random_starter()








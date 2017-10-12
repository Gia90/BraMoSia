import socket
import requests
import xml.dom.minidom as minidom
from xml.parsers.expat import ExpatError

from pysnmp.hlapi import *

# Brand, Model and other info from IP Address
class BraMoUpnp:
	
    _ipaddr = None

    # SSDP/UPNP props
    _mcast_addr = "239.255.255.250"
    _port = 1900
    _mx = 2
    _st = "upnp:rootdevice"	# "ssdp:all"
    _msearch_req = "M-SEARCH * HTTP/1.1\r\n" + \
		   "HOST: %s:%d\r\n" + \
    		   "MAN: \"ssdp:discover\"\r\n" + \
	           "MX: %d\r\n" + \
	           "ST: %s\r\n" + \
		   "\r\n";
    _upnp_dev_details = ["friendlyName","modelDescription","modelName","modelNumber","modelURL","presentationURL", "UPC","manufacturer","manufacturerURL"]

    def __init__(self, ipaddr, port=None, search_target=None, DEBUG=None):
        self._ipaddr = ipaddr
        if port: self._port = port
        if search_target: self._st = search_target
        if DEBUG: self.__DEBUG = DEBUG

    # Find the uPnP device with the specified ipaddr
    def _upnp_find_dev(self):
        upnp_dev_descr_url = None
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.settimeout(10)
		sock.sendto(self._msearch_req % (self._mcast_addr, self._port, self._mx, self._st), (self._ipaddr, self._port))
		while True:
		    resp = sock.recv(1000)
		    if self._ipaddr in resp:
		        # searched uPnP dev found!
		        for line in resp.split("\n"):
		            if line.lower().startswith("location:"):
		                upnp_dev_descr_url = line.split(" ", 1)[1].strip()
		        break
	        sock.close()
	except socket.error as e:
		raise Exception("Error during uPnP discover: "+str(e))
	     
        return upnp_dev_descr_url

    # Extract dev details from the uPnP descriptor file exposed at "upnp_dev_url"
    def _upnp_get_dev_details(self, upnp_dev_url):
        headers = {
                        'USER-AGENT':'UPnP/1.0',
                        'CONTENT-TYPE':'text/xml; charset="utf-8"'
                  }
	dev_info = []
	try:
		r = requests.get(upnp_dev_url, headers=headers)
		if r.status_code == requests.codes.ok:
			upnp_dev_dom = minidom.parseString(r.text)
			for dev in upnp_dev_dom.getElementsByTagName("device"):    
		 	    dev_details  = {}
			    for tag in self._upnp_dev_details:
				try:
					dev_details[tag] = str(dev.getElementsByTagName(tag)[0].childNodes[0].data)
				except IndexError:
					continue
			    dev_info.append(dev_details)
		else:
			raise Exception("Cannot retrieve uPnP device descriptor file.")
	except ExpatError as e:
		raise Exception("Error while extracting device details from uPnP descriptor: "+str(e))
		
        return dev_info

    def get_details(self):
	upnp_dev_descr_url = self._upnp_find_dev()
	dev_details = self._upnp_get_dev_details(upnp_dev_descr_url)
        return dev_details



class BraMoSnmp:
	_ipaddr = ""
	_port = 161
	_community = "public"

	def __init__(self, ipaddr, port=None, community=None):
		self._ipaddr = ipaddr
		if port: self._port= port
		if community: self._community = community

	def get_details(self):
		errorIndication, errorStatus, errorIndex, varBinds = next(
		    getCmd(SnmpEngine(),
			   CommunityData( self._community, mpModel=0),
			   UdpTransportTarget( (self._ipaddr, self._port) ),
			   ContextData(),
			   ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
		)

		if errorIndication:
		    raise Exception(errorIndication)
		elif errorStatus:
		    raise Exception('%s at %s' % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
		else:
	            for varBind in varBinds:
			return { varBind[0].prettyPrint() : varBind[1].prettyPrint() }



#!/usr/bin/env python

try:
	from scapy.all import *
except Exception, e:
	print 'Failed to import scapy:',e
	exit(1)

# Brand, Model and other info from wireless BSSID
class BraMoWi:
	_iface = None
	_bssid = None
	_timeout = 5
	_stealth = False

	__WPS_ID = "\x00\x50\xF2\x04"
    #Dictionary of relevent WPS tags and values
	__wps_tags = {
					'APLocked'      : {'id' : 0x1057,    'desc' : None},
					'WPSUUID-E'     : {'id' : 0x1047,    'desc' : None},
					'WPSRFBands'    : {'id' : 0x103C,    'desc' : None},
					'WPSRegistrar'  : {'id' : 0x1041,    'desc' : None},
					'WPSState'      : {'id' : 0x1044,    'desc' : {
					                                                0x01 : 'Not Configured',
					                                                0x02 : 'Configured'
					                                              }
					                  },
					'WPSVersion'    : {'id' : 0x104a,    'desc' : {
					                                                0x10 : '1.0',
					                                                0x11 : '1.1'
					                                              }
					                  },
					'WPSRegConfig'  : {'id' : 0x1053,    'desc' : {
					                                                0x0001 : 'USB',
					                                                0x0002 : 'Ethernet',
					                                                0x0004 : 'Label',
					                                                0x0008 : 'Display',
					                                                0x0010 : 'External NFC',
					                                                0x0020 : 'Internal NFC',
					                                                0x0040 : 'NFC Interface',
					                                                0x0080 : 'Push Button',
					                                                0x0100 : 'Keypad'
					                                              },
					                  'action' : 'or'
					                 },
					'WPSPasswordID' : {'id' : 0x1012,    'desc' : {
					                                                0x0000 : 'Pin',
					                                                0x0004 : 'PushButton'
					                                              }
					                  }

    }

	def __init__(self, iface=None, bssid=None, timeout=None, stealth=None):
		if(bssid):
			self._bssid = bssid
		if(iface):
			self._bssid = iface
		if(timeout):
			self._timeout = timeout
		if(stealth):
			self._stealth = True

	def _p_handler(self, packet):
		# the "packet" is already filtered by the "sniff" filters parameters
		# So, we are sure it will be type blah blah
		dot11elt = packet.getlayer(Dot11Elt)
		while dot11elt:
			if self._is_wpselt(dot11elt):
				break
			dot11elt = dot11elt.payload.getlayer(Dot11Elt)

		if(dot11elt):
			#self._print_wpsinfo( self._parse_wpselt(dot11elt), "", "")
			print( self._parse_wpselt(dot11elt) )

	#Check if an element is a WPS element
	def _is_wpselt(self, elt):
		if elt.ID == 221 and elt.info.startswith(self.__WPS_ID):
			return True
		return False

	#Converts an array of bytes ('\x01\x02\x03...') to an integer value
	def __str2int(self,string):
		intval = 0
		shift = (len(string)-1) * 8;

		for byte in string:
			try:
			    intval += int(ord(byte))<<shift
			    shift -= 8
			except Exception,e:
			    print 'Caught exception converting string to int:',e
			    return False
		return intval

	#Parse a particular ELT layer from a packet looking for WPS info
	def _parse_wpselt(self,elt):
	    data = None
	    tagNum = elt.ID
	    wpsInfo = {}
	    minSize = offset = 4
	    typeSize = versionSize = 2

	    #ELTs must be this high to ride!
	    if elt.len > minSize:
	        #Loop through the entire ELT
	        while offset < elt.len:
	            key = ''
	            val = ''

	            try:
	                #Get the ELT type code
	                eltType = self.__str2int(elt.info[offset:offset+typeSize])
	                offset += typeSize
	                #Get the ELT data length
	                eltLen = self.__str2int(elt.info[offset:offset+versionSize])
	                offset += versionSize
	                #Pull this ELT's data out
	                data = elt.info[offset:offset+eltLen]
	                data = self.__str2int(data)
	            except:
	                return False

	            #Check if we got a WPS-related ELT type
	            for (key,tinfo) in self.__wps_tags.iteritems():
	                if eltType == tinfo['id']:
	                    if tinfo.has_key('action') and tinfo['action'] == 'or':
	                        for method,name in tinfo['desc'].iteritems():
	                            if (data | method) == data:
	                                val += name + ' | '
	                        val = val[:-3]
	                    else:
	                        try:
	                            val = tinfo['desc'][data]
	                        except Exception, e:
	                            val = str(hex(data))
	                    break


	            if key and val:
	                wpsInfo[key] = val
	            offset += eltLen
	    return wpsInfo

	def get_details(self):
		if(not self._stealth):
		    print("Send probe request here!")
		    bssid_filter = lambda p: ( p.haslayer(Dot11ProbeResp) and p[Dot11].addr3 == self._bssid.lower() )
                else:
		    bssid_filter = lambda p: ( p.haslayer(Dot11Beacon) and p[Dot11].addr3 == self._bssid.lower() )

		# Start the sniffer
		sniff(iface= self._iface, prn=self._p_handler, lfilter=bssid_filter, stop_filter=bssid_filter, timeout=self._timeout)


if __name__ == "__main__":
	BraMoWi(bssid="94:4A:0C:BB:7A:B3").get_details()

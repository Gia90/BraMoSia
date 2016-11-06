#API base url,you can also use https if you need
url = "https://macvendors.co/api/"

def vendor_from_api(macaddr):
	r=requests.get(url+macaddr);
	return r.json()



# Download oui.txt from: http://standards-oui.ieee.org/oui.txt
# or run "update-oui" in Kali Linux
# Brand, Model and other info from MAC address
class BraMoMac:
	_ouidb = "/var/lib/ieee-data/oui.txt"
	
	def __init__(self, ouidb=None):
		if(ouidb):
			self._ouidb = ouidb
	
	def __extract_oui(self, macaddr):
		oui = macaddr if( len(macaddr) == 8) else macaddr[0:8]
		oui = oui.replace(":","").upper()
		return oui
	
	def get_vendor(self, macaddr):
		oui = self.__extract_oui(macaddr)
		vendors = []
		try:
			with open( self._ouidb, 'r' ) as ouif:
				for row in ouif:
					if oui == row[0:6]:
						vendor = row
					elif( "vendor" in locals() ):
						if row.strip() != "":
								vendor += row
						else:
							vendor = vendor.split("\t\t", 1)[1].strip().replace("\r\n\t\t\t\t", " ") 
							vendors.append(vendor);
							del vendor
		except IOError:
			raise Exception( "Cannot open \""+self._ouidb+"\". Is it correct?" )
		return vendors


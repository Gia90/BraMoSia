import requests

# Download oui.txt from: http://standards-oui.ieee.org/oui.txt
# or run "update-oui" in Kali Linux

# Brand, Model and other info from MAC address
class BraMoMac:
	_local_ouidb = "/var/lib/ieee-data/oui.txt"
	_online_ouidb = "http://standards-oui.ieee.org/oui.txt"
	_online = False

	def __init__(self, ouidb=None, online=False):
		if(ouidb):
			self._local_ouidb = ouidb
		self._online = online

	def __extract_oui(self, macaddr):
		oui = macaddr if( len(macaddr) == 8) else macaddr[0:8]
		oui = oui.replace(":","").upper()
		return oui

	def __open_ouidb(self):
		ouidb_content = None
		if(self._online):
			try:
				ouidb_content = requests.get(self._online_ouidb, stream=True).iter_lines(decode_unicode=True, delimiter="\r\n")
			except requests.exceptions.RequestException as e:
				raise Exception( "Cannot get \""+self._online_ouidb+"\". Is it up?" )
		else:
			try:
				ouidb_content = open( self._local_ouidb, 'r' )
			except IOError:
				raise Exception( "Cannot open \""+self._local_ouidb+"\". Is it correct?" )
		return ouidb_content

	def get_vendor(self, macaddr):
		oui = self.__extract_oui(macaddr)
		vendors = []
		ouidb = self.__open_ouidb()
		for row in ouidb:
			if oui == row[0:6]:
				vendor = row.strip()
			elif( "vendor" in locals() ):
				if row.strip():
						vendor += row.strip() + " "
				else:
					vendor = vendor.split("\t\t", 1)[1].strip().replace("\r\n\t\t\t\t", " ")
					vendors.append(vendor);
					del vendor
		return vendors

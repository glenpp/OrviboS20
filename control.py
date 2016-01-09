#!/usr/bin/python


# see https://stikonas.eu/wordpress/2015/02/24/reverse-engineering-orvibo-s20-socket/
# see https://wiki.python.org/moin/UdpCommunication




import sys
import socket
import struct

import pprint



# get args
def usage():
	sys.stderr.write ( "Usage:\n" )
	sys.stderr.write ( "\t%s connect <addr (fast blue broadcast 10.10.100.255)> <wlan ssid>\n" % (sys.argv[0]) )
	sys.stderr.write ( "\t\t[ requires rapid flahsing blue / solid red (unconnected/connected) mode ]\n" )
	sys.stderr.write ( "\t%s discover <broadcast addr> <MAC>\n" % (sys.argv[0]) )
	sys.stderr.write ( "\t%s globaldiscover <broadcast addr>\n" % (sys.argv[0]) )
	sys.stderr.write ( "\t%s subscribe <addr> <MAC>\n" % (sys.argv[0]) )
	sys.stderr.write ( "\t%s listen\n" % (sys.argv[0]) )
	sys.exit ( 1 )

if len ( sys.argv ) >= 2:
	command = sys.argv[1]
	if command == 'connect':
		if len ( sys.argv ) != 4: usage()
		ip = sys.argv[2]	# barodcast address to use
		wlan = sys.argv[3]
	elif command in [ 'discover', 'subscribe', 'poweron', 'poweroff' ]:
		if len ( sys.argv ) != 4: usage()
		ip = sys.argv[2]	# barodcast address to use
		mac = sys.argv[3]
	elif command == 'globaldiscover':
		if len ( sys.argv ) != 3: usage()
		ip = sys.argv[2]	# barodcast address to use
	elif command == 'listen':
		if len ( sys.argv ) != 2: usage()
else:
	usage()




# decifer returned / broadcast discovery packets

class orviboS20:
	port = 10000
	def __init__ ( self ):
		self.subscribed = None
		self.exitontimeout = False
		# TODO get a lock (file lock?) for port 10000 TODO
		# get a connection sorted
		self.sock = socket.socket (
				socket.AF_INET,	# Internet
				socket.SOCK_DGRAM	# UDP
			)
		self.sock.setsockopt ( socket.SOL_SOCKET, socket.SO_BROADCAST, 1 )	# https://stackoverflow.com/questions/11457676/python-socket-error-errno-13-permission-denied
		self.sock.bind ( ('',self.port) )

	def _settimeout ( self, timeout = None ):
		self.sock.settimeout ( timeout )	# seconds - in reality << 1 is needed, None = blocking (wait forever)

	def _listendiscover ( self ):
		status = {
				'exit': True,
				'timeout': False,
				'detail': {},
			}
		if self.exitontimeout: status['exit'] = False	# we should wait for timeout, not just exit
		# we need to run and catch timeouts
		try:
			data,addr = self.sock.recvfrom ( 1024 )
			# decode
			status['address'],status['port'] = addr
			status['detail']['length'] = struct.unpack ( '>H', data[2:4] )[0]
			status['detail']['commandid'] = struct.unpack ( '>H', data[4:6] )[0]
			print "Length: %d" % status['detail']['length']
			print "commandid: 0x%04x" % status['detail']['commandid']
			# then based on the lenth / command we can expect different stuff
			if status['detail']['length'] == 6 and status['detail']['commandid'] == 0x7161:
				# already got everything
				# global discovery - we probably sent this
				print "command: Global Discovery"
				status['command'] = 'Global Discovery'
				status['exit'] = False	# expect more after this
			elif status['detail']['length'] == 18 and status['detail']['commandid'] == 0x7167:
				# discovery - we probably sent this
				print "command: Discovery"
				status['command'] = 'Discovery'
				status['exit'] = False	# expect more after this
				# get remaining stuff
				status['detail']['dstmac'] = struct.unpack ( '6B', data[6:12] )
				status['detail']['srcmac'] = struct.unpack ( '6B', data[12:18] )
				print "mac: %s" % ':'.join( [ '%02x' % c for c in status['detail']['dstmac']  ] )
				print "padding: %s" % ':'.join( [ '%02x' % c for c in status['detail']['srcmac'] ] )
			elif status['detail']['length'] == 42 and ( status['detail']['commandid'] == 0x7161 or status['detail']['commandid'] == 0x7167 ):
				# returned discovery
				print "command: Discovery (response)"
				status['command'] = 'Discovery (response)'
				# get remaining stuff
				zero = struct.unpack ( '>B', data[6:7] )[0]
				if zero != 0: sys.stderr.write ( "WARNING: zero = 0x%02x\n" % zero )
				status['detail']['dstmac'] = struct.unpack ( '6B', data[7:13] )
				status['detail']['srcmac'] = struct.unpack ( '6B', data[13:19] )
				dstmacr = struct.unpack ( '6B', data[19:25] )
				srcmacr = struct.unpack ( '6B', data[25:31] )
				print "mac: %s" % ':'.join( [ '%02x' % c for c in status['detail']['dstmac']  ] )
				print "padding: %s" % ':'.join( [ '%02x' % c for c in status['detail']['srcmac'] ] )
				status['detail']['soc'] = data[31:37]
				print "soc: %s" % status['detail']['soc']
				status['detail']['timer'] = struct.unpack ( 'I', data[37:41] )
				print "1900+sec: %d" % status['detail']['timer']
				status['state'] = struct.unpack ( 'B', data[41] )
				print "state: %d" % status['state']
			elif status['detail']['length'] == 24 and status['detail']['commandid'] == 0x636c:
				# returned subscription TODO separate this - we should only be looking for subscription related stuff after and not tricked by other (discovery) stuff
				status['detail']['dstmac'] = struct.unpack ( '6B', data[6:12] )
				status['detail']['srcmac'] = struct.unpack ( '6B', data[12:18] )
				print "mac: %s" % ':'.join( [ '%02x' % c for c in status['detail']['dstmac']  ] )
				print "padding: %s" % ':'.join( [ '%02x' % c for c in status['detail']['srcmac'] ] )
				zero = struct.unpack ( '>5B', data[18:23] )
				for i in range(5):
					if zero[i] != 0: sys.stderr.write ( "WARNING: zero[%d] = 0x%02x\n" % (i,zero) )
				status['state'] = struct.unpack ( 'B', data[23] )[0]
				print "state: %d" % status['state']
			elif status['detail']['length'] == 23 and status['detail']['commandid'] == 0x6463:
				# returned power on/off TODO separate this - we should only be looking for subscription related stuff after and not tricked by other (discovery) stuff
				status['detail']['dstmac'] = struct.unpack ( '6B', data[6:12] )
				status['detail']['srcmac'] = struct.unpack ( '6B', data[12:18] )
				print "mac: %s" % ':'.join( [ '%02x' % c for c in status['detail']['dstmac']  ] )
				print "padding: %s" % ':'.join( [ '%02x' % c for c in status['detail']['srcmac'] ] )
				zero = struct.unpack ( '>5B', data[18:23] )
				for i in range(5):
					if zero[i] != 0: sys.stderr.write ( "WARNING: zero[%d] = 0x%02x\n" % (i,zero) )
				# previous info said 4 bytes zero, 5th state, but on my S20 this is always zero, so assume as above 5 bytes zero, no state
			else:
				raise
		except socket.timeout:
			# if we are doing timeouts then just catch it - it's probably for a reason
			status['timeout'] = True
			if self.exitontimeout: status['exit'] = True
		except:	# TODO this should be more specific to avoid trapping syntax errors
			sys.stderr.write ( "Unknown packet:\n" )
			for c in struct.unpack ( '%dB' % len(data), data ):
				sys.stderr.write ( "* %02x \"%s\"\n" % (c,chr(c)) )

		return status



	def listen ( self ):
		self._settimeout ( None )	# set blocking
		self.exitontimeout = False
		return self._listendiscover ()
	def discover ( self, ip, mac ):
		self._settimeout ( 2 )
		self.exitontimeout = True
		macasbin = ''.join ( [ struct.pack ( 'B', int(x,16) ) for x in mac.split ( ':' ) ] )
		self.sock.sendto ( 'hd\x00\x12\x71\x67'+macasbin+'      ' , ( ip, 10000 ) )
		data = []
		while True:
			resp = self._listendiscover ()
			data.append ( resp )
			if resp['exit']: break
		return data
	def globaldiscover ( self, ip ):
		self._settimeout ( 2 )
		self.exitontimeout = True
		self.sock.sendto ( 'hd\x00\x06\x71\x61' , ( ip, 10000 ) )
		data = []
		while True:
			resp = self._listendiscover ()
			data.append ( resp )
			if resp['exit']: break
		return data
	def subscribe ( self, ip, mac ):
		self._settimeout ( 2 )
		self.exitontimeout = True
		macasbin = ''.join ( [ struct.pack ( 'B', int(x,16) ) for x in mac.split ( ':' ) ] )
		macasbinr = ''.join ( reversed ( [ struct.pack ( 'B', int(x,16) ) for x in mac.split ( ':' ) ] ) )
		self.sock.sendto ( '\x68\x64\x00\x1e\x63\x6c'+macasbin+'      '+macasbinr+'      ' , ( ip, 10000 ) )
		resp = self._listendiscover ()
		self.subscribed = [ resp['address'], ''.join ( [ struct.pack ( 'B', x ) for x in resp['detail']['dstmac'] ] ) ]
		return resp

	def _subscribeifneeded ( self, ip, mac ):
		if mac == None and self.subscribed != None:
			# already subscribed
			pass
		elif ip != None and mac != None:
			# subscribe or check existing subscription
			macasbin = ''.join ( [ struct.pack ( 'B', int(x,16) ) for x in mac.split ( ':' ) ] )
			if self.subscribed == None or self.subscribed[1] != macasbin:
				# new subscription / re-subscription
				self.subscribe ( ip, mac )
				if self.subscribed == None or self.subscribed[1] != macasbin:
					raise	# something failed
	def poweron ( self, ip = None, mac = None ):
		self._subscribeifneeded ( ip, mac )
		# we should now be subscribed - go ahead with the power command
		self.sock.sendto ( '\x68\x64\x00\x17\x64\x63'+self.subscribed[1]+'      \x00\x00\x00\x00\x01', ( self.subscribed[0], 10000 ) )
		resp = self._listendiscover ()
		pprint.pprint ( resp )
		return resp

	def poweroff ( self, ip = None, mac = None ):
		self._subscribeifneeded ( ip, mac )
		# we should now be subscribed - go ahead with the power command
		self.sock.sendto ( '\x68\x64\x00\x17\x64\x63'+self.subscribed[1]+'      \x00\x00\x00\x00\x00', ( self.subscribed[0], 10000 ) )
		resp = self._listendiscover ()
		pprint.pprint ( resp )
		return resp








if command == 'connect':
	sock = socket.socket (
			socket.AF_INET,	# Internet
			socket.SOCK_DGRAM	# UDP
		)
	sock.setsockopt ( socket.SOL_SOCKET, socket.SO_BROADCAST, 1 )	# https://stackoverflow.com/questions/11457676/python-socket-error-errno-13-permission-denied
	sock.settimeout ( 2 )	# seconds - in reality << 1 is needed

	# connect to network
	sock.sendto ( 'HF-A11ASSISTHREAD' , (ip,48899) )
	data,addr = sock.recvfrom ( 1024 )
	socketip,socketmac,sockethost = data.split ( ',' )
	print socketip,socketmac,sockethost
	sock.sendto ( '+ok' , (ip,48899) )	# ack
	sock.sendto ( "AT+WSSSID=%s\r" % wlan, (ip,48899) )
	data,addr = sock.recvfrom ( 1024 )
	if data.rstrip() != '+ok':
		sys.exit ( "FATAL - got \"%s\" in response to set SSID\n" % data.rstrip() )
	key = raw_input (  "Enter WIFI key for \"%s\": " % wlan )
	sock.sendto ( "AT+WSKEY=WPA2PSK,AES,%s\r" % key, (ip,48899) )
	data,addr = sock.recvfrom ( 1024 )
	if data.rstrip() != '+ok':
		sys.exit ( "FATAL - got \"%s\" in response to set KEY\n" % data.rstrip() )
	sock.sendto ( "AT+WMODE=STA\r" , (ip,48899) )
	data,addr = sock.recvfrom ( 1024 )
	if data.rstrip() != '+ok':
		sys.exit ( "FATAL - got \"%s\" in response to set MODE\n" % data.rstrip() )
	sock.sendto ( "AT+Z\r" , (ip,48899) )	# no return
	print "connect complete to \"%s\"" % wlan
elif command == 'listen':	# listen for stuff sent round
	print "listen"
	control = orviboS20 ()
	while True:
		resp = control.listen ()
		pprint.pprint ( resp )
		if resp['exit']: break
elif command == 'discover':
	control = orviboS20 ()
	resp = control.discover ( ip, mac )
	pprint.pprint ( resp )
elif command == 'globaldiscover':
	control = orviboS20 ()
	resp = control.globaldiscover ( ip )
	pprint.pprint ( resp )
elif command == 'subscribe':
	control = orviboS20 ()
	resp = control.subscribe ( ip, mac )
	pprint.pprint ( resp )
elif command == 'poweron':
	control = orviboS20 ()
	control.poweron ( ip, mac )

elif command == 'poweroff':
	control = orviboS20 ()
	control.poweroff ( ip, mac )
# TODO TABLE DATA
# TODO SOCKET DATA
# TODO Timing DATA











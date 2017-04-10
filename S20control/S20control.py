#!/usr/bin/python
#
# Copyright (C) 2016  Glen Pitt-Pladdy
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
#
# See https://www.pitt-pladdy.com/blog/_20160121-103754_0000_Orvibo_S20_Wifi_Power_Socket_Utility/


# For original reverse engineering work see:
# https://stikonas.eu/wordpress/2015/02/24/reverse-engineering-orvibo-s20-socket/
# https://wiki.python.org/moin/UdpCommunication

# Thanks for contributions to:
#	Guy Sheffer - https://github.com/guysoft
#	alexyr - https://github.com/alexyr




import sys
import pprint
import socket
import struct
import sys
import time


# get args
def usage():
    print >>sys.stderr, "Usage:"
    print >>sys.stderr, "\t%s connect <addr (fast blue broadcast 10.10.100.255)> <wlan ssid>" % (sys.argv[0])
    print >>sys.stderr, "\t\t[ requires rapid flahsing blue / solid red (unconnected/connected) mode ]"
    print >>sys.stderr, "\t%s discover <broadcast addr> <MAC>" % (sys.argv[0])
    print >>sys.stderr, "\t%s globaldiscover <broadcast addr>" % (sys.argv[0])
    print >>sys.stderr, "\t%s _subscribe <addr> <MAC>" % (sys.argv[0])
    print >>sys.stderr, "\t%s getstate <addr> <MAC>" % (sys.argv[0])
    print >>sys.stderr, "\t%s poweron <addr> <MAC>" % (sys.argv[0])
    print >>sys.stderr, "\t%s poweroff <addr> <MAC>" % (sys.argv[0])
    print >>sys.stderr, "\t%s listen" % (sys.argv[0])
    sys.exit(1)


class OrviboS20:
    """
    main class for Orvibo S20
    """
    port = 10000

    class UnknownPacket(Exception):
        def __init__(self, value):
            self.value = value

        def __str__(self):
            return repr(self.value)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __init__(self):
        self.subscribed = None
        self.exitontimeout = False
        # TODO: get a lock (file lock?) for port 10000
        # get a connection sorted
        self.sock = socket.socket(
            socket.AF_INET,  # Internet
            socket.SOCK_DGRAM  # UDP
        )
        # https://stackoverflow.com/questions/11457676/python-socket-error-errno-13-permission-denied
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', self.port))

    def close(self):
        try:
            self.sock.close()
        except Exception as e:
            print e

    def _settimeout(self, timeout=None):
        self.sock.settimeout(timeout)  # seconds - in reality << 1 is needed, None = blocking (wait forever)

    # takes payload excluding first 4 (magic, size) bytes
    def _sendpacket(self, payload, ip):
        data = [0x68, 0x64, 0x00, len(payload) + 4]
        data.extend(payload)
        # print data
        self.sock.sendto(''.join([struct.pack('B', x) for x in data]), (ip, 10000))

    def _listendiscover(self):
        status = {
            'exit': True,
            'timeout': False,
            'detail': {},
        }
        if self.exitontimeout:
            status['exit'] = False  # we should wait for timeout, not just exit
        # we need to run and catch timeouts
        try:
            data, addr = self.sock.recvfrom(1024)
            # check magic for a valid packet
            if data[0:2] != 'hd':
                return None
            # decode
            status['address'], status['port'] = addr
            status['detail']['length'] = struct.unpack('>H', data[2:4])[0]
            status['detail']['commandid'] = struct.unpack('>H', data[4:6])[0]
            # print "Length: %d" % status['detail']['length']
            # print "commandid: 0x%04x" % status['detail']['commandid']
            # then based on the lenth / command we can expect different stuff
            if status['detail']['length'] == 6 and status['detail']['commandid'] == 0x7161:
                # already got everything
                # global discovery - we probably sent this
                # print "command: Global Discovery"
                status['command'] = 'Global Discovery'
                status['exit'] = False  # expect more after this
            elif status['detail']['length'] == 18 and status['detail']['commandid'] == 0x7167:
                # discovery - we probably sent this
                # print "command: Discovery"
                status['command'] = 'Discovery'
                status['exit'] = False  # expect more after this
                # get remaining stuff
                status['detail']['dstmac'] = struct.unpack('6B', data[6:12])
                status['detail']['srcmac'] = struct.unpack('6B', data[12:18])
            # print "mac: %s" % ':'.join( [ '%02x' % c for c in status['detail']['dstmac']  ] )
            # print "padding: %s" % ':'.join( [ '%02x' % c for c in status['detail']['srcmac'] ] )
            elif status['detail']['length'] == 42 and (
                            status['detail']['commandid'] == 0x7161 or status['detail']['commandid'] == 0x7167):
                # returned discovery
                # print "command: Discovery (response)"
                status['command'] = 'Discovery (response)'
                # get remaining stuff
                zero = struct.unpack('>B', data[6:7])[0]
                if zero != 0:
                    print >>sys.stderr, "WARNING: [0] zero = 0x%02x\n" % zero
                status['detail']['dstmac'] = struct.unpack('6B', data[7:13])
                status['detail']['srcmac'] = struct.unpack('6B', data[13:19])
                dstmacr = struct.unpack('6B', data[19:25])
                srcmacr = struct.unpack('6B', data[25:31])
                # print "mac: %s" % ':'.join( [ '%02x' % c for c in status['detail']['dstmac']  ] )
                # print "padding: %s" % ':'.join( [ '%02x' % c for c in status['detail']['srcmac'] ] )
                status['detail']['soc'] = data[31:37]
                # print "soc: %s" % status['detail']['soc']
                status['detail']['timer'] = struct.unpack('I', data[37:41])[0]
                # print "1900+sec: %d" % status['detail']['timer']
                status['state'] = struct.unpack('B', data[41])[0]
            # print "state: %d" % status['state']
            elif status['detail']['length'] == 24 and status['detail']['commandid'] == 0x636c:
                # returned subscription TODO separate this - we should only be looking for subscription related stuff after and not tricked by other (discovery) stuff
                status['detail']['dstmac'] = struct.unpack('6B', data[6:12])
                status['detail']['srcmac'] = struct.unpack('6B', data[12:18])
                # print "mac: %s" % ':'.join( [ '%02x' % c for c in status['detail']['dstmac']  ] )
                # print "padding: %s" % ':'.join( [ '%02x' % c for c in status['detail']['srcmac'] ] )
                zero = struct.unpack('>5B', data[18:23])
                for i in range(5):
                    if zero[i] != 0:
                        print >>sys.stderr, "WARNING: [1] zero[%d] = 0x%02x\n" % (i, zero)
                status['state'] = struct.unpack('B', data[23])[0]
            # print "state: %d" % status['state']
            elif status['detail']['length'] == 23 and status['detail']['commandid'] == 0x6463:
                # returned power on/off TODO separate this - we should only be looking for subscription related stuff after and not tricked by other (discovery) stuff
                status['detail']['dstmac'] = struct.unpack('6B', data[6:12])
                status['detail']['srcmac'] = struct.unpack('6B', data[12:18])
                # print "mac: %s" % ':'.join( [ '%02x' % c for c in status['detail']['dstmac']  ] )
                # print "padding: %s" % ':'.join( [ '%02x' % c for c in status['detail']['srcmac'] ] )
                status['detail']['peercount'] = struct.unpack('B', data[18])  # number of peers on the network
                zero = struct.unpack('>4B', data[19:23])
                for i in range(4):
                    if zero[i] != 0:
                        print >>sys.stderr, "WARNING: [2] zero[%d] = 0x%02x\n" % (i, zero[i])
                    # previous info said 4 bytes zero, 5th state, but on my S20 this is always zero, so assume as above 5 bytes zero, no state
            else:
                raise UnknownPacket
        except socket.timeout:
            # if we are doing timeouts then just catch it - it's probably for a reason
            status['timeout'] = True
            if self.exitontimeout:
                status['exit'] = True
        except UnknownPacket, e:  # TODO this should be more specific to avoid trapping syntax errors
            print >>sys.stderr, "Error: %s:" % e
            print >>sys.stderr, "Unknown packet:"
            for c in struct.unpack('%dB' % len(data), data):
                print >>sys.stderr, "* %02x \"%s\"\n" % (c, chr(c))

        # fill in text MAC
        if 'detail' in status:
            if 'dstmac' in status['detail']:
                status['dstmachex'] = ':'.join(['%02x' % c for c in status['detail']['dstmac']])
            if 'srcmac' in status['detail']:
                status['srcmachex'] = ':'.join(['%02x' % c for c in status['detail']['srcmac']])

        return status

    def listen(self):
        self._settimeout(None)  # set blocking
        self.exitontimeout = False
        return self._listendiscover()

    def discover(self, ip, mac):
        self._settimeout(2)
        self.exitontimeout = True
        # macasbin = ''.join ( [ struct.pack ( 'B', int(x,16) ) for x in mac.split ( ':' ) ] )
        # self.sock.sendto ( 'hd\x00\x12\x71\x67'+macasbin+'      ' , ( ip, 10000 ) )
        data = [0x71, 0x67]
        data.extend([int(x, 16) for x in mac.split(':')])
        data.extend([0x20, 0x20, 0x20, 0x20, 0x20, 0x20])
        self._sendpacket(data, ip)
        data = []
        while True:
            resp = self._listendiscover()
            data.append(resp)
            if resp['exit']:
                break
        return data

    def globaldiscover(self, ip):
        self._settimeout(2)
        self.exitontimeout = True
        # self.sock.sendto ( 'hd\x00\x06\x71\x61' , ( ip, 10000 ) )
        self._sendpacket([0x71, 0x61], ip)
        data = []
        while True:
            resp = self._listendiscover()
            data.append(resp)
            if resp['exit']:
                break
        return data

    def subscribe(self, ip, mac):
        self._settimeout(2)
        self.exitontimeout = True
        data = [0x63, 0x6c]
        data.extend([int(x, 16) for x in mac.split(':')])
        data.extend([0x20, 0x20, 0x20, 0x20, 0x20, 0x20])
        data.extend([int(x, 16) for x in reversed(mac.split(':'))])
        data.extend([0x20, 0x20, 0x20, 0x20, 0x20, 0x20])
        self._sendpacket(data, ip)
        resp = self._listendiscover()
        if 'address' not in resp:
            return None

        self.subscribed = [
            resp['address'],
            ''.join([struct.pack('B', x) for x in resp['detail']['dstmac']]),
            # ':'.join ( [ "%02x" % x for x in resp['detail']['dstmac'] ] )
            [x for x in resp['detail']['dstmac']]
        ]
        time.sleep(0.01)  # need a delay >6ms to be reliable - comands before that may be ignored
        return resp

    def _subscribeifneeded(self, ip, mac):
        if mac is None and self.subscribed is not None:
            # already subscribed
            pass
        elif ip is not None and mac is not None:
            # subscribe or check existing subscription
            macasbin = ''.join([struct.pack('B', int(x, 16)) for x in mac.split(':')])
            if self.subscribed is None or self.subscribed[1] != macasbin:
                # new subscription / re-subscription
                self.subscribe(ip, mac)
                if self.subscribed is None or self.subscribed[1] != macasbin:
                    raise Exception('self.subscribe failed: %s' % self.subscribed)  # something failed

    def poweron(self, ip=None, mac=None):
        self._subscribeifneeded(ip, mac)
        # we should now be subscribed - go ahead with the power command
        data = [0x64, 0x63]
        data.extend(self.subscribed[2])
        data.extend([0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x01])
        self._sendpacket(data, self.subscribed[0])
        resp = self._listendiscover()
        # pprint.pprint ( resp )
        return resp

    def poweroff(self, ip=None, mac=None):
        self._subscribeifneeded(ip, mac)
        # we should now be subscribed - go ahead with the power command
        data = [0x64, 0x63]
        data.extend(self.subscribed[2])
        data.extend([0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00])
        self._sendpacket(data, self.subscribed[0])
        resp = self._listendiscover()
        # pprint.pprint ( resp )
        return resp


def main():
    if len(sys.argv) >= 2:
        command = sys.argv[1]
        if command == 'connect':
            if len(sys.argv) != 4:
                usage()
            ip = sys.argv[2]  # broadcast address to use
            wlan = sys.argv[3]
        elif command in ['discover', '_subscribe', 'getstate', 'poweron', 'poweroff']:
            if len(sys.argv) != 4:
                usage()
            ip = sys.argv[2]  # broadcast address to use
            mac = sys.argv[3]
        elif command == 'globaldiscover':
            if len(sys.argv) != 3:
                usage()
            ip = sys.argv[2]  # broadcast address to use
        elif command == 'listen':
            if len(sys.argv) != 2:
                usage()
        else:
            usage()
    else:
        usage()

    if command == 'connect':
        sock = socket.socket(
            socket.AF_INET,  # Internet
            socket.SOCK_DGRAM  # UDP
        )
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,
                        1)  # https://stackoverflow.com/questions/11457676/python-socket-error-errno-13-permission-denied
        sock.settimeout(2)  # seconds - in reality << 1 is needed

        # connect to network
        sock.sendto('HF-A11ASSISTHREAD', (ip, 48899))
        data, addr = sock.recvfrom(1024)
        socketip, socketmac, sockethost = data.split(',')
        print socketip, socketmac, sockethost
        sock.sendto('+ok', (ip, 48899))  # ack
        sock.sendto("AT+WSSSID=%s\r" % wlan, (ip, 48899))
        data, addr = sock.recvfrom(1024)

        if data.rstrip() != '+ok':
            print >>sys.stderr, 'FATAL - got "%s" in response to set SSID' % data.rstrip()
            sys.exit(1)

        key = raw_input('Enter WIFI key for "%s": ' % wlan)
        sock.sendto("AT+WSKEY=WPA2PSK,AES,%s\r" % key, (ip, 48899))
        data, addr = sock.recvfrom(1024)

        if data.rstrip() != '+ok':
            print >>sys.stderr, 'FATAL - got "%s" in response to set KEY' % data.rstrip()
            sys.exit(1)

        sock.sendto("AT+WMODE=STA\r", (ip, 48899))
        data, addr = sock.recvfrom(1024)

        if data.rstrip() != '+ok':
            print >>sys.stderr, 'FATAL - got "%s" in response to set MODE' % data.rstrip()
            sys.exit(1)

        sock.sendto("AT+Z\r", (ip, 48899))  # no return
        print "connect complete to \"%s\"" % wlan

    elif command == 'listen':  # listen for stuff sent round
        print "listen"
        with OrviboS20() as control:
            while True:
                resp = control.listen()
                pprint.pprint(resp)
                if resp['exit']:
                    break

    elif command == 'discover':
        with OrviboS20() as control:
            resp = control.discover(ip, mac)
            pprint.pprint(resp)

    elif command == 'globaldiscover':
        with OrviboS20() as control:
            resp = control.globaldiscover(ip)
            pprint.pprint(resp)

    elif command == '_subscribe':
        with OrviboS20() as control:
            resp = control.subscribe(ip, mac)
            pprint.pprint(resp)

    elif command == 'getstate':
        with OrviboS20() as control:
            resp = control.subscribe(ip, mac)
            if not resp:
                sys.exit(100)
            sys.exit(0 if resp['state'] == 1 else 1)

    elif command == 'poweron':
        with OrviboS20() as control:
            control.poweron(ip, mac)

    elif command == 'poweroff':
        with OrviboS20() as control:
            control.poweroff(ip, mac)

    # TODO TABLE DATA
    # TODO SOCKET DATA
    # TODO Timing DATA


if __name__ == "__main__":
    main()

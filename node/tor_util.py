import socks
import sys
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
import time
import constants

LOGGING = 1

def log(s):
    if LOGGING:
        print '%s: Tor Redirector: %s' % (time.ctime(), s)
        sys.stdout.flush()

def is_onion_addr(addr):
    return addr.endswith(".onion")

class TorRedirector(Thread):
    def __init__(self, targethost, targetport):
        Thread.__init__(self)
        # socksiPy errors if given a unicode address which OB sometimes generates - so we force ascii
        self.targethost = str(targethost).encode('ascii')
        self.targetport = targetport
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.sock.bind(('', 0))  # bind to an available socket
        self.localport = self.sock.getsockname()[1]
        log('Bound to 127.0.0.1:%s -> %s:%s' % (self.localport, self.targethost, self.targetport))
        self.sock.listen(5)
    def run(self):
        ClientSock, address = self.sock.accept()
        log('Client connected from %s, connecting to %s:%s' % (address, self.targethost, self.targetport))
        RemoteSock = socks.socksocket(AF_INET, SOCK_STREAM)
        RemoteSock.setproxy(socks.PROXY_TYPE_SOCKS5, constants.SOCKS5_PROXY_HOST, constants.SOCKS5_PROXY_PORT, True)
        try:
            RemoteSock.connect((self.targethost, self.targetport))
        except socks.Socks5Error:
            log('Error connecting to target host via Tor')
            ClientSock.close()
            RemoteSock.close()
            self.sock.close()
            return
        ClientSock.settimeout(0.1)
        RemoteSock.settimeout(0.1)
        while 1:
            try:
                dataout = ClientSock.recv(1024000)
                if not dataout:
                    log('Client disconnected')
                    break
                RemoteSock.send(dataout)
            except Exception, e:
                if e.args[0] == 'timed out':
                    pass  # ignore timeouts
                else:
                    log('Error ' + e.args[0])
                    break
            try:
                datain = RemoteSock.recv(1024000)
                if not datain:
                    log('Remote host disconnected')
                    break
                ClientSock.send(datain)
            except Exception, e:
                if e.args[0] == 'timed out':
                    pass  # ignore timeouts
                else:
                    log('Error ' + e.args[0])
                    break

        ClientSock.close()
        RemoteSock.close()
        self.sock.close()
        log('Exiting')


if __name__ == '__main__':
    print 'Starting Tor Redirector'

    ptargetport = int(sys.argv[1])
    ptargethost = sys.argv[2]
    TorRedirector(ptargethost, ptargetport).start()

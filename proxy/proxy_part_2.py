#!/usr/bin/python

import socket
import select
import time
import sys
import binascii

def get_dest(_srcIp, _srcPort):
	file = open("/sys/class/fw/fw/conn_tab", "r") 
	for line in file:
		splitedLine = line.split(" ")
		srcIp = splitedLine[1]
		srcPort = splitedLine[3]
		if (srcIp == _srcIp) and (int(srcPort) == int(_srcPort)):	
			dstIp = splitedLine[2]
			dstPort = splitedLine[4]
			file.close()
			return (dstIp, int(dstPort))
	file.close()
	return None

def is_exe_file(DATA):
	if len(DATA) < 2:
		return -1
	str1="";
	for x in range (2):
		str1+=binascii.hexlify(DATA[x])
	if str1 == "4d5a":
		return 1;
	return -1

# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 100000
delay = 0.0001


class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            #self.forward.bind(('',10004))
            self.forward.connect((host, port))

            return self.forward
        except Exception, e:
            print e
            return False

class TheServer:
    input_list = []
    channel = {}
		    
    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)

    def main_loop(self):
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break
                    
                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break 
                else:
                    self.on_recv()

    def on_accept(self):
    
        clientsock, clientaddr = self.server.accept()
        dest_socket=get_dest(clientaddr[0],clientaddr[1])
        forward = Forward().start(dest_socket[0], dest_socket[1])
        if forward:
            print clientaddr, "has connected"
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            print "Can't establish connection with remote server.",
            print "Closing connection with client side", clientaddr
            clientsock.close()

    def on_close(self):
        print self.s.getpeername(), "has disconnected"
        #remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.channel[self.s].close()
        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self):
        data = self.data
        
        # here we can parse and/or modify the data before send forward
        if (self.s.getpeername()[1] == 20 ):
			if (is_exe_file(data)==1) :
				file = open("/sys/class/fw/fw/proxy_conn", "w") 
				file.write(" "+str(self.s.getpeername()[0])+" ")
				file.write(str(self.channel[self.s].getpeername()[0])+" ")
				file.write(str(self.s.getpeername()[1])+" ")
				file.write(str(self.channel[self.s].getpeername()[1])+" ")
				file.write("proxy_ftp_block")
				file.close()
				self.on_close()
			else :
					self.channel[self.s].send(data)  
        else:
           self.channel[self.s].send(datanew)

if __name__ == '__main__':
        server = TheServer('', 10003)
        try:
            server.main_loop()
        except KeyboardInterrupt:
            print "Ctrl C - Stopping server"
            sys.exit(1)

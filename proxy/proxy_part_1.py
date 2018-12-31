#!/usr/bin/python
# This is a simple port-forward / proxy, written using only the default python
# library. If you want to make a suggestion or fix something you can contact-me
# at voorloop_at_gmail.com
# Distributed over IDC(I Don't Care) license
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
	print(dstIp)
	file.close()
	return None

def get_content_length(DATA):
	ret=""
	if (DATA.find("Content-Length:") > 0):
		temp = DATA.split("Content-Length:")[1]
		
		for i in temp:
			if ((i == " ") or (i=="\r")) and (ret!=""):
				break
			if i!= " ":
				ret=ret+str(i)
		return int(ret)
		
	return None

def is_Magic_Office(DATA):
	str1="";
	if len(DATA) < 8:
		return -1
	for x in range (8):
		str1+=binascii.hexlify(DATA[x])
	if str1 == "d0cf11e0a1b11ae1":
		return 1;
	return -1


# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 100000
delay = 0.0001
future_ftp_val=220

class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.bind(('',10002))
            self.forward.connect((host, port))
            print self.forward
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
        print clientsock
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
        global future_ftp_val
        data = self.data
        is_office=0
        myMap = {211:"System_status",200:"request_complete",125:"transfer_starting",120:"service_ready",110:"restart_marker",100:"request_initiated",426:"transfer_aborted",213:"request_completed", 220: "Ftp_ready", 331:"need_password",230:"User_logged_in",215: "NAME_system_type",200: "request_completed" ,150:"File_status_okay" ,226:"Close_data_conn" ,257:"PATHNAME_created",550:"Request_not_taken",421:"close_control_conn",221:"close_control_conn",430:"Invalid_pass",250:"completed"}
        FtpMap = {220:331,331:230,230:215,215:-1,-1:-1}
        # here we can parse and/or modify the data before send forward
        if self.s.getpeername()[1] == 80 :
			end_of_header= (data.find("\r\n\r\n"))
			if (end_of_header) > 0 :
				data_witout_header=data[end_of_header+4:]
				if is_Magic_Office(data_witout_header) != -1:
					print("It's a office File")
					is_office=1
			res =get_content_length(data.rstrip())
			if (res)>2000 or is_office==1 :
				file = open("/sys/class/fw/fw/proxy_conn", "w") 
				file.write(" "+str(self.s.getpeername()[0])+" ")
				file.write(str(self.channel[self.s].getpeername()[0])+" ")
				file.write(str(self.s.getpeername()[1])+" ")
				file.write(str(self.channel[self.s].getpeername()[1])+" ")
				file.write("proxy_http_block")
				file.close()
			else :
				if (data[0]=='H') :					
					self.channel[self.s].send(data)
				if res!=None:
					self.channel[self.s].send(data) 
				if res==None:
					file = open("/sys/class/fw/fw/proxy_conn", "w") 
					file.write(" "+str(self.s.getpeername()[0])+" ")
					file.write(str(self.channel[self.s].getpeername()[0])+" ")
					file.write(str(self.s.getpeername()[1])+" ")
					file.write(str(self.channel[self.s].getpeername()[1])+" ")
					file.write("proxy_http_block")
					file.close() 
        elif self.s.getpeername()[1] == 21 :
	
			ftp_num=data.partition(' ')[0]
			file = open("/sys/class/fw/fw/proxy_conn", "w") 
			file.write(" "+str(self.s.getpeername()[0])+" ")
			file.write(str(self.channel[self.s].getpeername()[0])+" ")
			file.write(str(self.s.getpeername()[1])+" ")
			file.write(str(self.channel[self.s].getpeername()[1])+" ")
			if int(ftp_num) in myMap:
				if (int(ftp_num)==future_ftp_val )or (future_ftp_val==-1) :
					file.write(myMap[int(ftp_num)])
					self.channel[self.s].send(data)
				if future_ftp_val!=-1:
					future_ftp_val=FtpMap[int(ftp_num)]				
			else :
				if future_ftp_val != -1 :
					file.write("proxy_ftp_block")
				else:
					file.write("ftp_status")
					self.channel[self.s].send(data)
			file.close()	
			
        else:
           self.channel[self.s].send(data)

if __name__ == '__main__':
        server = TheServer('', 10001)
        try:
            server.main_loop()
        except KeyboardInterrupt:
            print "Ctrl C - Stopping server"
            sys.exit(1)

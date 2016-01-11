#!usr/bin/python
#Np-scanner v-1.0
#A python based port scanner/network scanner.

#-----------------------------------------------------------------------------
# Copyright (c) 2015-2016, Shubham Dubey(sdubey504@gmail.com)
#
# Distributed under the terms of the GNU General Public License with exception
# for distributing bootloader.
#
# The full license is in the file LICENCE.txt, distributed with this software.
#-----------------------------------------------------------------------------

# This utility is primary meant to be used for network scanning or port scanning
# since it is in beginning phase so does'nt gurantee for correct info given.



import socket
import commands
import optparse
from optparse import OptionParser
from optparse import OptionGroup


socket.setdefaulttimeout(4)

#this funtion will select the ips to scan according to user argument.
def sys_cheker(args):


		#if no ip is given as argument.
		if args==[]:
				ip=raw_input("Enter the ip of the target machine:")
				open_ports=scanning(ip)
				final_result(open_ports)

		else:

				#if single ip is given
				if len(args)==1:
						arg_ip=args[0]

						#if ip is not like 192.168.122.0/24
						if arg_ip.find('/')==-1:
								ip=args[0]
								print ("\033[91mScanning ports on ip:\033[0m"+ip)
								print
								open_ports=scanning(ip)
								if open_ports=='closed':
										print ("###################################################")
								else:
										final_result(open_ports)

						#if ip is something like 192.168.122.0/24
						else:

								#if /24 is the range to scan for
								if arg_ip[-1]=='4' and arg_ip[-2]=='2':
										x=arg_ip.split('/')

										#if the ip is invalid bcuz of to much /
										if len(x)>2:
												print ("\n\033[91mInvalid range given..Please give correct range.\033[0m")
												exit()

										#will take 192.168.122.0 from 192.168.122.0/24
										ip_part=x[0]

										#checking ip part for correct ip
										blocks=ip_part.split('.')

										#if the ip is invalid bcuz of more then 4 blocks
										if len(blocks)!=4:
												print ("\n\033[91mInvalid ip address..!!!!\033[0m")
												exit()
										elif int(blocks[0])>254 or int(blocks[1])>254 or int(blocks[2])>254 or int(blocks[3])>254:
												print ("\n\033[91mInvalid ip address..!!!!\033[91m")
												exit()

										#wheather if ip is like 192.168.122.0/24
										if ip_part[-1]=='0' and ip_part[-2]=='.':

												#loop for scanning from range 192.168.122.0 to 192.168.122.254
												for system in range(0,255):
														ip=ip_part[:-1]+str(system)
														print ("\033[91mScanning ports on ip:\033[0m"+ip)
														open_ports=scanning(ip)
														if open_ports=='closed':
																print ("###################################################")
														else:
																final_result(open_ports)
																print ("###################################################")


										#if ip is like 192.168.122.45/24 (in that case program will scan
										#from 192.168.122.45 to 192.168.122.254)
										else:
												scan_from=blocks[3]
												for system in range(int(scan_from),255):
														ip=blocks[0]+'.'+blocks[1]+'.'+blocks[2]+'.'+str(system)
														print ("\033[91mScanning ports on ip:\033[0m"+ip)
														open_ports=scanning(ip)
														if open_ports=='closed':
																print ("###################################################")
														else:
																final_result(open_ports)
																print ("###################################################")

								#if ips are in range /48
								elif arg_ip[-1]=='8' and arg_ip[-2]=='4':
										print "\033[91m/48 support yet to come.\033[0m:)"

								else:
										print "\033[91mInvalid range given..Please give correct range.\033[0m"
										exit()

				else:

						#if lots of single ips are given as argument
						for i in range(0,len(args)):
								ip=args[i]
								print ("\033[91mScanning ports on ip:\033[0m"+ip)
								open_ports=scanning(ip)
								if open_ports=='closed':
										print ("###################################################")
								else:
										final_result(open_ports)
										print ("###################################################")


#will give the total no of open port
def final_result(open):

		if str(open)=='0':
				print
				print
				print ("Total open port found:\033[91m"+str(open)+"\033[0m")
				print "\n[\033[91mEither all ports are closed or system Blocking all requests.\033[0m]"
				print

		else:
				print
				print
				print("Total open port found:\033[91m"+str(open)+"\033[0m")
				print


#this function will do the scanning of ports in particular system.
def scanning(ip):



		show_open=1
		#hostname search
		try:
				hostname=socket.gethostbyaddr(ip)
		except:
				print "[\033[91mHostname\033[0m]: Not found!\n"
		else:
				print '[\033[91mHostname\033[0m]:'+hostname[0]
				print


		#port scanning started here.
		open=0

		for port in range(1,1000):
				s=socket.socket()

				try:

						#connecting to port
						#if error occur(connection refused!) then port is closed

						#if connect successfully then port is open

						s.connect((ip,int(port)))
				except socket.error as er:


						#error code 101 is happen bcuz of no route to host (means no system at that ip)
						if er.errno==101:
								show_open=0
								print "\033[91mHost seems down!!\033[0m"
								break

						#error code 111 happens bcuz of closed port on system.
						elif er.errno==111:
								do_nothing='1'


						else:
								show_open=0
								print "\033[91mHost seems down!!\033[0m"
								break

				#any other error simply means host is down.
				except:
						show_open=0
						print "\033[91mHost seems down!!\033[0m"
						break
				else:


						try:
									#if connect successfully then in return banner is reacieved(recv)

								ans=s.recv(1024)


						except socket.timeout as e:

								print ("Port \033[91m"+str(port)+" \033[0m is open.!")
								#expected_port=commands.getoutput("cat  /etc/services |grep  "+str(port)+" |head -1")
								expected_port=socket.getservbyport(port)

								print ("\033[33mExpected Service:\033[0m")
								print (expected_port)
								print ("\033[33mDescription(banner/Version):-\033[0m")
								print ("No Further Description avaliable")
								print ("\033[91m*****************************************************************\033[0m")
								open=open+1


						else:
								print ("Port \033[91m"+str(port)+"\033[0m is open.!")

								#expected_port=commands.getoutput("cat  /etc/services |grep  "+str(port)+" |head -1")
								expected_port=socket.getservbyport(port)

								print ("\033[33mExpected Service:\033[0m")
								print (expected_port)

								print ("\033[33mDescription(banner/Version):-\033[0m")
								print ans
								print ("\033[91m*****************************************************************\033[0m")
								open=open+1
								s.close()


		if show_open==0:
				return 'closed'
		else:
				return open


#main starts here
def main():

		usage = "usage: %prog [option] [ip|ips|ip/24]"
		parser=OptionParser(usage,version="%prog v1.0")

		parser.add_option("-o","--output",dest='output_file',metavar="OUTPUT_FILE",help="output file to save result on.")
		parser.add_option("-p","--port",dest='port',metavar="QUERY_PORT",help="check only on this port.")

		(options, args) = parser.parse_args()
		#all ips given by command argument get saved in args list.

		if options.port==None:
				sys_cheker(args)
		else:
				scanning_port=options.port
				print ("particular port scanning yet to come.:)")
				fix_port_scanner(args,scanning_port)


if __name__=='__main__':
		main()

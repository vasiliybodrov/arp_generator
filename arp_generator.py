#! /usr/bin/env python

# ******************************************************************************
# Program name: arp_generator
# Description: ARP packet generator for IPv4
# Version: 0.1 (Sable)
# Author: Vasiliy V. Bodrov aka Bodro (mailto:mobile.ipbsoftware@gmail.com)
# Date: 29.09.2015
# Programming language: Python
# Commenting language: English
# ******************************************************************************
# The MIT License (MIT)
#
# Copyright (c) 2015 IPB Software (Vasiliy V. Bodrov aka Bodro)
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
# OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
# THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# ******************************************************************************

#
# TODO: сделать вывод отправляемого пакета в HEX, OCT, DEC и BIN, BASE64 виде.
#

# ******************************************************************************
# Import
# ******************************************************************************

import getopt, sys
from struct import *
from socket import socket, inet_aton, htons, AF_PACKET, SOCK_RAW

# ******************************************************************************
# Global variable
# ******************************************************************************

# Self variable
version_num_str = '0.1'
version_name = 'Sable'

# Common variable
common_interface = "eth0"

# Layer 2 (Ethernet)
l2_header = 0x00;

l2_src_addr1 = 0x00
l2_src_addr2 = 0x00
l2_src_addr3 = 0x00
l2_src_addr4 = 0x00
l2_src_addr5 = 0x00
l2_src_addr6 = 0x00

l2_dst_addr1 = 0xff
l2_dst_addr2 = 0xff
l2_dst_addr3 = 0xff
l2_dst_addr4 = 0xff
l2_dst_addr5 = 0xff
l2_dst_addr6 = 0xff

l2_ether_type = 0x0806

# Layer 3 (ARP)
l3_arp_data = 0x00

l3_arp_htype = 0x0001
l3_arp_ptype = 0x0800
l3_arp_hlen = 0x06
l3_arp_plen = 0x04
l3_arp_oper = 0x0001

l3_arp_sha_1 = 0x00
l3_arp_sha_2 = 0x00
l3_arp_sha_3 = 0x00
l3_arp_sha_4 = 0x00
l3_arp_sha_5 = 0x00
l3_arp_sha_6 = 0x00

l3_arp_spa_1 = 0x00
l3_arp_spa_2 = 0x00
l3_arp_spa_3 = 0x00
l3_arp_spa_4 = 0x00

l3_arp_tha_1 = 0xff
l3_arp_tha_2 = 0xff
l3_arp_tha_3 = 0xff
l3_arp_tha_4 = 0xff
l3_arp_tha_5 = 0xff
l3_arp_tha_6 = 0xff

l3_arp_tpa_1 = 0xff
l3_arp_tpa_2 = 0xff
l3_arp_tpa_3 = 0xff
l3_arp_tpa_4 = 0xff


# ******************************************************************************
# Code
# ******************************************************************************

# ------------------------------------------------------------------------------
# Function: version
# Description: show version info
# ------------------------------------------------------------------------------
def version():
    print("Program: " + sys.argv[0])
    print("version " + version_num_str + ' (' + version_name + ')')
    print("ARP packet generator for IPv4")

# ------------------------------------------------------------------------------
# Function: authors
# Description: show authors
# ------------------------------------------------------------------------------
def authors():
    version()
    print("Author: Vasiliy V. Bodrov aka Bodro (mailto:mobile.ipbsoftware@gmail.com)");
    
# ------------------------------------------------------------------------------
# Function: license
# Description: show license
# ------------------------------------------------------------------------------
def license():
    version()
    print("")
    print("The MIT License (MIT)")
    print("")
    print("Copyright (c) 2015 IPB Software (Vasiliy V. Bodrov aka Bodro)")
    print("")
    print("Permission is hereby granted, free of charge, to any person obtaining a")
    print("copy of this software and associated documentation files (the \"Software\"),")
    print("Software is furnished to do so, subject to the following conditions:")
    print("")
    print("The above copyright notice and this permission notice shall be included")
    print("in all copies or substantial portions of the Software.")
    print("")
    print("THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS")
    print("OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF")
    print("MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.")
    print("IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY")
    print("CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT")
    print("OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR")
    print("THE USE OR OTHER DEALINGS IN THE SOFTWARE.")

# ------------------------------------------------------------------------------
# Function: usage
# Description:
# ------------------------------------------------------------------------------
def usage():
    print("Use --help or -h for help")
    print("Example: " + sys.argv[0] + " --help")

# ------------------------------------------------------------------------------
# Function: help
# Description:
# ------------------------------------------------------------------------------
def help():
    version();
    print("");
    print(sys.argv[0] + " [OPTIONS]");
    print("");
    print("-h,\t--help\t\t\t- show this help and exit");
    print("-v,\t--version\t\t- show version and exit");
    print("-a,\t--authors\t\t- show authors and exit");
    print("-l,\t--license\t\t- show license and exit");
    print("\t--mac-src=MAC\t\t- source MAC-address (default: " + format(l2_src_addr1, '02x') + ":" + format(l2_src_addr2, '02x') + ":" + format(l2_src_addr3, '02x') + ":" + format(l2_src_addr4, '02x') + ":" + format(l2_src_addr5, '02x') + ":" + format(l2_src_addr6, '02x') + ")");
    print("\t--mac-dst=MAC\t\t- destination MAC-address (default: " + format(l2_dst_addr1, '02x') + ":" + format(l2_dst_addr2, '02x') + ":" + format(l2_dst_addr3, '02x') + ":" + format(l2_dst_addr4, '02x') + ":" + format(l2_dst_addr5, '02x') + ":" + format(l2_dst_addr6, '02x') + ")");
    print("\t--operation=NUM\t\t- ARP: operation: 1-request; 2-reply (default: " + format(l3_arp_oper, 'd') + ")");
    print("\t--arp-sha=MAC\t\t- ARP: sender hardware address (default: " + format(l3_arp_sha_1, '02x') + ":" + format(l3_arp_sha_2, '02x') + ":" + format(l3_arp_sha_3, '02x') + ":" + format(l3_arp_sha_4, '02x') + ":" + format(l3_arp_sha_5, '02x') + ":" + format(l3_arp_sha_6, '02x') + ")");
    print("\t--arp-spa=IP\t\t- ARP: sender protocol address (default: " + format(l3_arp_spa_1, 'd') + "." + format(l3_arp_spa_2, 'd') + "." + format(l3_arp_spa_3, 'd') + "." + format(l3_arp_spa_4, 'd') + ")");
    print("\t--arp-tha=MAC\t\t- ARP: target hardware address (default: " + format(l3_arp_tha_1, '02x') + ":" + format(l3_arp_tha_2, '02x') + ":" + format(l3_arp_tha_3, '02x') + ":" + format(l3_arp_tha_4, '02x') + ":" + format(l3_arp_tha_5, '02x') + ":" + format(l3_arp_tha_6, '02x') + ")");
    print("\t--arp-tpa=IP\t\t- ARP: target protocol address (default: " + format(l3_arp_tpa_1, 'd') + "." + format(l3_arp_tpa_2, 'd') + "." + format(l3_arp_tpa_3, 'd') + "." + format(l3_arp_tpa_4, 'd') + ")");
    print("")
    print("Example: " + "\n\t# " + sys.argv[0] + " \\\n\t\t\
--interface=eth0 \\\n\t\t\
--mac-src=\"02:A1:A2:A3:A4:A5\" \\\n\t\t\
--mac-dst=\"FF:FF:FF:FF:FF:FF\" \\\n\t\t\
--operation=1 \\\n\t\t\
--arp-sha=\"02:A1:A2:A3:A4:A5\" \\\n\t\t\
--arp-spa=\"192.168.2.1\" \\\n\t\t\
--arp-tha=\"00:00:00:00:00:00\" \\\n\t\t\
--arp-tpa=\"192.168.2.224\"")

# ------------------------------------------------------------------------------
# Function: data_send
# Description:
# ------------------------------------------------------------------------------
def data_send():
    global version_num_str
    global version_name

    global common_interface

    global l2_header

    global l2_src_addr1
    global l2_src_addr2
    global l2_src_addr3
    global l2_src_addr4
    global l2_src_addr5
    global l2_src_addr6

    global l2_dst_addr1
    global l2_dst_addr2
    global l2_dst_addr3
    global l2_dst_addr4
    global l2_dst_addr5
    global l2_dst_addr6

    global l2_ether_type

    global l3_arp_data

    global l3_arp_htype
    global l3_arp_ptype
    global l3_arp_hlen
    global l3_arp_plen
    global l3_arp_oper

    global l3_arp_sha_1
    global l3_arp_sha_2
    global l3_arp_sha_3
    global l3_arp_sha_4
    global l3_arp_sha_5
    global l3_arp_sha_6

    global l3_arp_spa_1
    global l3_arp_spa_2
    global l3_arp_spa_3
    global l3_arp_spa_4

    global l3_arp_tha_1
    global l3_arp_tha_2
    global l3_arp_tha_3
    global l3_arp_tha_4
    global l3_arp_tha_5
    global l3_arp_tha_6

    global l3_arp_tpa_1
    global l3_arp_tpa_2
    global l3_arp_tpa_3
    global l3_arp_tpa_4

    l2_header = pack('!BBBBBBBBBBBBH',\
    		 l2_dst_addr1,\
		 l2_dst_addr2,\
		 l2_dst_addr3,\
		 l2_dst_addr4,
		 l2_dst_addr5,
		 l2_dst_addr6,
		 l2_src_addr1,
		 l2_src_addr2,
		 l2_src_addr3,
		 l2_src_addr4,
		 l2_src_addr5,
		 l2_src_addr6,
		 l2_ether_type)

    l3_arp_data = pack('!HHBBHBBBBBBBBBBBBBBBBBBBB',\
    		 l3_arp_htype,\
		 l3_arp_ptype,\
		 l3_arp_hlen,\
		 l3_arp_plen,\
		 l3_arp_oper,\
		 l3_arp_sha_1,\
		 l3_arp_sha_2,\
		 l3_arp_sha_3,\
		 l3_arp_sha_4,\
		 l3_arp_sha_5,\
		 l3_arp_sha_6,\
		 l3_arp_spa_1,\
		 l3_arp_spa_2,\
		 l3_arp_spa_3,\
		 l3_arp_spa_4,\
		 l3_arp_tha_1,\
		 l3_arp_tha_2,\
		 l3_arp_tha_3,\
		 l3_arp_tha_4,\
		 l3_arp_tha_5,\
		 l3_arp_tha_6,\
		 l3_arp_tpa_1,\
		 l3_arp_tpa_2,\
		 l3_arp_tpa_3,\
		 l3_arp_tpa_4)

    # Send data via socket

    s = socket(AF_PACKET, SOCK_RAW)
    
    s.bind((common_interface, 0))

    s.send(l2_header + l3_arp_data)

# ------------------------------------------------------------------------------
# Function: main
# Description:
# ------------------------------------------------------------------------------
def main():
    global common_interface

    global l2_src_addr1
    global l2_src_addr2
    global l2_src_addr3
    global l2_src_addr4
    global l2_src_addr5
    global l2_src_addr6

    global l2_dst_addr1
    global l2_dst_addr2
    global l2_dst_addr3
    global l2_dst_addr4
    global l2_dst_addr5
    global l2_dst_addr6

    global l3_arp_htype
    global l3_arp_ptype
    global l3_arp_hlen
    global l3_arp_plen
    global l3_arp_oper

    global l3_arp_sha_1
    global l3_arp_sha_2
    global l3_arp_sha_3
    global l3_arp_sha_4
    global l3_arp_sha_5
    global l3_arp_sha_6

    global l3_arp_spa_1
    global l3_arp_spa_2
    global l3_arp_spa_3
    global l3_arp_spa_4

    global l3_arp_tha_1
    global l3_arp_tha_2
    global l3_arp_tha_3
    global l3_arp_tha_4
    global l3_arp_tha_5
    global l3_arp_tha_6

    global l3_arp_tpa_1
    global l3_arp_tpa_2
    global l3_arp_tpa_3
    global l3_arp_tpa_4

    global l2_ether_type

    try:
	opts, args = getopt.getopt(sys.argv[1:], "hvali:",\
	      ["help",\
	      "version",\
	      "authors",\
	      "license",\
	      "interface=",\
	      "mac-src=",\
	      "mac-dst=",\
	      "operation=",\
	      "arp-sha=",\
	      "arp-spa=",\
	      "arp-tha=",\
	      "arp-tpa="])
    except getopt.GetoptError as err:
        print(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    for o, a in opts:
        if o == "-v":
            version()
	    sys.exit()
        elif o in ("-a", "--authors"):
            authors()
            sys.exit()
	elif o in ("-h", "--help"):
            help()
            sys.exit()
        elif o in ("-v", "--version"):
            version()
            sys.exit()
        elif o in ("-l", "--license"):
	    license()
            sys.exit()
	elif o in ("-i", "--interface"):
            common_interface = a
	elif o in ("--mac-src"):
	    mac_src = a.split(':')

	    l2_src_addr1 = int(mac_src[0], 16)
	    l2_src_addr2 = int(mac_src[1], 16)
	    l2_src_addr3 = int(mac_src[2], 16)
	    l2_src_addr4 = int(mac_src[3], 16)
	    l2_src_addr5 = int(mac_src[4], 16)
	    l2_src_addr6 = int(mac_src[5], 16)
	elif o in ("--mac-dst"):
	    mac_dst = a.split(":")

    	    l2_dst_addr1 = int(mac_dst[0], 16)
    	    l2_dst_addr2 = int(mac_dst[1], 16)
    	    l2_dst_addr3 = int(mac_dst[2], 16)
    	    l2_dst_addr4 = int(mac_dst[3], 16)
    	    l2_dst_addr5 = int(mac_dst[4], 16)
    	    l2_dst_addr6 = int(mac_dst[5], 16)
	elif o in ("--operation"):
	    l3_arp_oper = int(a, 10)
	elif o in ("--arp-sha"):
	    mac_sha = a.split(':')

	    l3_arp_sha_1 = int(mac_sha[0], 16)
	    l3_arp_sha_2 = int(mac_sha[1], 16)
	    l3_arp_sha_3 = int(mac_sha[2], 16)
	    l3_arp_sha_4 = int(mac_sha[3], 16)
	    l3_arp_sha_5 = int(mac_sha[4], 16)
	    l3_arp_sha_6 = int(mac_sha[5], 16)
	elif o in ("--arp-spa"):
	    ip_spa = a.split(".")

	    l3_arp_spa_1 = int(ip_spa[0], 10)
	    l3_arp_spa_2 = int(ip_spa[1], 10)
	    l3_arp_spa_3 = int(ip_spa[2], 10)
	    l3_arp_spa_4 = int(ip_spa[3], 10)
	elif o in ("--arp-tha"):
	    mac_tha = a.split(':')

	    l3_arp_tha_1 = int(mac_tha[0], 16)
	    l3_arp_tha_2 = int(mac_tha[1], 16)
	    l3_arp_tha_3 = int(mac_tha[2], 16)
	    l3_arp_tha_4 = int(mac_tha[3], 16)
	    l3_arp_tha_5 = int(mac_tha[4], 16)
	    l3_arp_tha_6 = int(mac_tha[5], 16)
	elif o in ("--arp-tpa"):
	    ip_tpa = a.split(".")

	    l3_arp_tpa_1 = int(ip_tpa[0], 10)
	    l3_arp_tpa_2 = int(ip_tpa[1], 10)
	    l3_arp_tpa_3 = int(ip_tpa[2], 10)
	    l3_arp_tpa_4 = int(ip_tpa[3], 10)
        else:
            assert False, "unhandled option"

    data_send()

# ------------------------------------------------------------------------------
# Run
# ------------------------------------------------------------------------------
main()

# ******************************************************************************
# End of file
# ******************************************************************************

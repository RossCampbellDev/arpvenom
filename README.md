# arpvenom
ARP poisoning using Python and Scapy

## args
-t  the IP address of the target whose ARP cache we want to poison
-m  the MAC address we're giving the target
-g  the IP address of the gateway who we're messing with

## spoof the target
send the target the poisonous MAC address but pretend that it's being sent from the genuine other party
in the ARP layer of the scapy packet:
- pdst: <target''s IP>
- psrc: <DHCP server etc IP>
- hwsrc: <MITM''s MAC address>

## spoof the other party
we reverse the above process:
- pdst: <other party''s IP>
- psrc: <target''s IP>
- hwsrc:  <MITM''s MAC address>

## maintain the poisoning
in order for it to actually work, it needs to be repeatedly established by doing both the above steps persistently

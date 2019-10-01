from scapy.all import sniff
import sys
import time
print("start the main")
print("start scanning")
print("don't close me i'm sniffing ")
sys.stdout = open('textout.txt', 'a')
a = sniff(iface="wlan0",timeout=10)
a.show()

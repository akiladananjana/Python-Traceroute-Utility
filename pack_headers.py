import socket
import struct
import array
import os

#ICMP Checksum Calculation
def chksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet)) 
    res = (res >> 16) + (res & 0xffff)
    res = res + (res >> 16)
    
    return ((~res) & 0xffff)

#Generate ICMP Packet
def ICMP_header(checksum=0):
    icmp_type = 8 #8 bits
    icmp_code = 0 #8 bits
    icmp_chsum= checksum #16 bits
    icmp_pid  = os.getpid()
    icmp_seq  = 0

    packet = struct.pack("!BBHHH", icmp_type, icmp_code, int(icmp_chsum), icmp_pid, icmp_seq)

    #Set some dummy data
    icmp_data = "6162636465666768696a6b6c6d6e6f7071727374757677616263646566676869"

    return (packet + icmp_data.encode())


#icmp_checksum = chksum(ICMP_header(0))
#print(ICMP_header(icmp_checksum))



def IP_Header(ip_src, ip_dst):
    
    ip_ver  =   4
    ip_hlen =   5
    ip_tos  =   0
    ip_tlen =   50
    ip_id   =   0
    ip_flag =   0
    ip_fofs =   0
    ip_ttl  =   128
    ip_prot =   1 #1 for ICMP
    ip_cksum=   0
    ip_src  =   socket.inet_aton(str(ip_src))
    ip_dst  =   socket.inet_aton(str(ip_dst))

    ip_ver_hlen = (ip_ver << 4) + ip_hlen
    ip_flag_offset = (ip_flag << 13) + ip_fofs
    ip_packet   = struct.pack("!BBHHHBBH4s4s", ip_ver_hlen, ip_tos, ip_tlen, ip_id, ip_flag_offset, ip_ttl, ip_prot, ip_cksum, ip_src, ip_dst)

    return ip_packet


#print(IP_Header('192.168.1.10', '8.8.8.8'))
















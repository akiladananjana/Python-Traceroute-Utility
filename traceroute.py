import socket
import pack_headers
import unpack_headers
import sys
import os
import struct
import array
import binascii
import datetime
import time
import netifaces
import signal

#Create a Socket that able to access ICMP headers
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

#For trace-route we need to include IP header with different TTL values
#Then we need to write & insert IP header ourself. Without following line, kernel automatically generate the IP header for ICMP Packet. 
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

interface_name = sys.argv[2]
interface_ip = netifaces.ifaddresses(interface_name)[2][0]['addr']

sock.bind((interface_ip, 0))

#for ICMP Checksum
def checksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res = res + (res >> 16)

    return ((~res) & 0xffff)



#Generate IP Packet
def IP_Header(ip_src, ip_dst, ttl=64):
    
    ip_ver  =   4
    ip_hlen =   5
    ip_tos  =   0
    ip_tlen =   50
    ip_id   =   0
    ip_flag =   0
    ip_fofs =   0
    ip_ttl  =   ttl
    ip_prot =   1 #1 for ICMP
    ip_cksum=   0
    ip_src  =   socket.inet_aton(str(ip_src))
    ip_dst  =   socket.inet_aton(str(ip_dst))

    ip_ver_hlen = (ip_ver << 4) + ip_hlen
    ip_flag_offset = (ip_flag << 13) + ip_fofs
    ip_packet   = struct.pack("!BBHHHBBH4s4s", ip_ver_hlen, ip_tos, ip_tlen, ip_id, ip_flag_offset, ip_ttl, ip_prot, ip_cksum, ip_src, ip_dst)

    return ip_packet



#Generate ICMP Packet
def build_icmp_header(checksum=0, data='', seq_number=0):
    icmp_type = 8 #8 bits
    icmp_code = 0 #8 bits
    icmp_chsum= checksum #16 bits
    icmp_pid  = os.getpid() #2bytes
    icmp_seq  = seq_number #2bytes

    packet = struct.pack("BBHHH", icmp_type, icmp_code, int(icmp_chsum), icmp_pid, icmp_seq)
    
    if(data):
        icmp_data = data 
        return (packet + icmp_data)

    return (packet)



#unpack ICMP Packet
def unpack_icmp_header(packet_buffer):
    icmp_data = ""
    icmp_data = struct.unpack("1s1s2s2s2s", packet_buffer)
    icmp_data_list = []
    #print(icmp_data)

    for x in icmp_data:
        icmp_data_list.append(binascii.hexlify(x).decode())
    
    #Append recved PID as raw data
    icmp_data_list.append(icmp_data[3])

    return icmp_data_list #[['0b', '00', 'fb82', '0000', '0000', b'\x00\x00'], 253, '172.20.13.2']



#Send ICMP echo request packet
def send_icmp_packet(dst_ip, seq_number, socket_handler, interface_ip, ttl):

    #Generate a dummy packet for ICMP Header checksum
    icmp_packet_for_checksum  = build_icmp_header(0, '', seq_number)
    sample_data = ("----Hello World----").encode()
    
    icmp_checksum = checksum(icmp_packet_for_checksum + sample_data)
    
    #Generate a new packet with ICMP Checksum
    icmp_packet = build_icmp_header(icmp_checksum, sample_data, seq_number)
    
    #Generate a new IP packet
    ip_packet = IP_Header(interface_ip, dst_ip, ttl)
    
    packet = ip_packet + icmp_packet

    #Send the ping request
    socket_handler.sendto(packet, (dst_ip, 1))
    


#Recv ICMP echo reply
def recv_icmp_ping(socket_handler):
    try:
    	frame = socket_handler.recv(65535)
    except KeyboardInterrupt:
    	sys.exit(1)
    ip_raw_data = frame[:20] #Extract the IP Packet
    ip_packet = unpack_headers.IP_Header(ip_raw_data)

    icmp_raw_data = frame[20:28]
    icmp_packet_in_header = unpack_icmp_header(icmp_raw_data) #Extract the ICMP Packet

    icmp_type = icmp_packet_in_header[0]
    ttl = ip_packet.ttl_val
    src_ip = ip_packet.src_address

    if(icmp_type == '00'):
        #print(src_ip)
        #sys.exit(1)
        return [icmp_packet_in_header, ttl, src_ip, icmp_type]

    icmp_raw_data = frame[48:56] #Extract the ICMP time exceeded Packet
    icmp_packet_in_option_field = unpack_icmp_header(icmp_raw_data)

    return [icmp_packet_in_option_field, ttl, src_ip, icmp_type]


def send_ping(interface_ip, dst_ip, ttl):

    start_time = datetime.datetime.now()
    send_icmp_packet(dst_ip, 1, sock, interface_ip, ttl)

    response = recv_icmp_ping(sock) #eg:- [['08', '00', '7cdb', '73a1', '0100', b's\xa1'], <icmp_ip_packet_ttl>, <icmp_packet_ip_address>, <icmp_type>]
    #print(response)
    end_time = datetime.datetime.now()

    time_diff = round(((end_time - start_time).microseconds /1000), 2)
    icmp_type = response[3]
    router_ip = response[2]

    #Get current program process IP
    process_pid = str(os.getpid())

    #Get receved packet process ID
    packet_pid = str(struct.unpack("<H", response[0][5])[0])

    return [time_diff, icmp_type, router_ip, process_pid, packet_pid] #eg:- [69.19, '0b', '103.87.124.93', '3943', '3943']


def main(dst_ip, interface_ip):

    global ttl
    ttl = 1

    if(dst_ip == interface_ip):
        print("Enter another IP!")
        sys.exit(1)


    while(True):

        #def ping_timeout(signum, sigstack):
        #    print(ttl, "****")

        #If timeout the ping, then alarm triggered and signal method catches the SIGALRM signal and execute the ping_timeout function.
        #signal.signal(signal.SIGALRM, ping_timeout)
        
        #Set timeout to 2 seconds
        #signal.alarm(2)

        icmp_response = send_ping(interface_ip, dst_ip, ttl)
        #print(icmp_response)

        #icmp_response[3] = ping program process_id
        #icmp_response[4] =  the process_id in recevied ping reply packet

        # TO VALIDATE PING PACKET, THE PING PROGRAM PID == RECVED PING PACKET'S PID 
        if(icmp_response[2] == dst_ip):
            print(ttl, icmp_response[2])
            sys.exit(1)
        elif(ttl>30):
            sys.exit(1)

            
        if((icmp_response[1] == '0b') and (icmp_response[3] == icmp_response[4])):
            print(ttl, icmp_response[2], end= "\t")
            i = 1
            while(i<=3):
                icmp_response = send_ping(interface_ip, dst_ip, ttl)
                print(str(icmp_response[0]) + "ms", end="  ")
                i+=1
            print("")
        else:
            print("****")

        #time.sleep(1)

        ttl+=1



dst_ip = socket.gethostbyname(sys.argv[1])

main(dst_ip, interface_ip)

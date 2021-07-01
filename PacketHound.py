import sys
import socket
import struct
import textwrap
import os

# Gives out instructions on how to use the application


def Instructions():
    instructions = '''
    THIS ONLY WORKS IN LINUX SYSTEMS AS OF NOW
          _______              _________ _______                  _______  _______     _____  
|\     /|(  ___  )|\     /|    \__   __/(  ___  )       |\     /|(  ____ \(  ____ \   / ___ \ 
| )   ( || (   ) || )   ( |       ) (   | (   ) |       | )   ( || (    \/| (    \/  ( (   ) )
| (___) || |   | || | _ | | _____ | |   | |   | | _____ | |   | || (_____ | (__       \/  / / 
|  ___  || |   | || |( )| |(_____)| |   | |   | |(_____)| |   | |(_____  )|  __)         ( (  
| (   ) || |   | || || || |       | |   | |   | |       | |   | |      ) || (            | |  
| )   ( || (___) || () () |       | |   | (___) |       | (___) |/\____) || (____/\      (_)  
|/     \|(_______)(_______)       )_(   (_______)       (_______)\_______)(_______/       _   
                                                                                         (_)  
## Read from file (Option:1)
Provide a .phf (created from this application) to read all the packet data stored from a previous session.
This is specially usefull when some important information is stored in the .phf file of that session
To delete the data simply delete the .phf file from the "files" directory from within the main directory.

## Start new capture(Option:2)
To start capturing the data packets of a network simply select this option and let it run as long as you want.
Make sure that you run this application in root privileges or it won\'t work.
'''
    return instructions

# Unpack Ethernet Frame


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Returns properly formatted MAC address (ie AA:BB:CC:DD:EE:FF)


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack the IPv4 packet


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Returns properly formatted IPv4 address


def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpacks ICMP packet


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks TCP segment


def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement,
     offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpacks UDP segment


def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

# Formats multi-line data


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


# TAB CONSTANTS
TAB_1 = '\t '
TAB_2 = '\t\t '
TAB_3 = '\t\t\t '
DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '

# Function to write to file (for storing)


def writeData(data):
    with open("./temp/temp.phf", 'a') as f:
        f.write(data+"\n")
    print(data)


# Process data
def processData(raw_data, addr):
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    data_out = f'\nEthernet Frame: ===> {addr}\n{TAB_1}Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}'
    writeData(data_out)
    # 8 for IPv4
    if eth_proto == 8:
        (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
        writeData(f'{TAB_1}IPv4 Packet:\n{TAB_2}Version: {version}, Header Length: {header_length}, TTL: {ttl}\n{TAB_2}Protocol: {proto}, Source: {src}, Target: {target}')
        # ICMP
        if proto == 1:
            icmp_type, code, checksum, data = icmp_packet(data)
            writeData(
                f'{TAB_1}ICMP Packet:\n{TAB_2}Type: {icmp_type}, Code: {code}, Checksum: {checksum}\n{TAB_2}Data:\n{format_multi_line(DATA_TAB_3, data)}')
        # TCP
        elif proto == 6:
            (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack,
                flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
            writeData(TAB_1 + 'TCP Segment:')
            writeData(
                TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}')
            writeData(
                TAB_2 + f'Sequence: {sequence}, Acknowledgement: {acknowledgement}')
            writeData(TAB_2 + 'Flags:')
            writeData(
                TAB_3 + f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN:{flag_syn}, FIN: {flag_fin}')
            writeData(TAB_2 + f'Data:\n{format_multi_line(DATA_TAB_3, data)}')
        # UDP
        elif proto == 17:
            src_port, dest_port, length, data = udp_segment(data)
            writeData(TAB_1 + 'UDP Segment:')
            writeData(
                TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
        # Other
        else:
            writeData(TAB_1 + 'Data:')
            writeData(TAB_2 + format_multi_line(DATA_TAB_2, data))
    else:
        writeData(f'Data:\n{format_multi_line(DATA_TAB_1, data)}')

# NEW CAPTURE


def work():
    connection = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        try:
            raw_data, addr = connection.recvfrom(65536)
            processData(raw_data, addr)
        except KeyboardInterrupt:
            save = input("\nSave all this packet data? (y/n): \n>> ")
            if save.lower() == "y":
                name = input(
                    "Enter name for the file (without extension):\n>> ")
                if not os.path.exists("data"):
                    os.mkdir("data")
                os.rename("./temp/temp.phf", f"./data/{name}.phf")
                print(f"File saved as {name}.phf")
            elif save.lower() == "n":
                os.remove("./temp/temp.phf")
            break

# READ FROM FILE


def readFromFile():
    fileName = input("Enter file name:\n>> ")
    if os.path.exists(fileName):
        with open(fileName, 'r') as f:
            for i in f.readlines():
                print(i.strip("\n"))
    else:
        print("No such file exists")


# MAIN MENU
mainMenu = f'''

 /$$$$$$$                     /$$                   /$$           /$$   /$$                                     /$$
| $$__  $$                   | $$                  | $$          | $$  | $$                                    | $$
| $$  \ $$ /$$$$$$   /$$$$$$$| $$   /$$  /$$$$$$  /$$$$$$        | $$  | $$  /$$$$$$  /$$   /$$ /$$$$$$$   /$$$$$$$
| $$$$$$$/|____  $$ /$$_____/| $$  /$$/ /$$__  $$|_  $$_/        | $$$$$$$$ /$$__  $$| $$  | $$| $$__  $$ /$$__  $$
| $$____/  /$$$$$$$| $$      | $$$$$$/ | $$$$$$$$  | $$          | $$__  $$| $$  \ $$| $$  | $$| $$  \ $$| $$  | $$
| $$      /$$__  $$| $$      | $$_  $$ | $$_____/  | $$ /$$      | $$  | $$| $$  | $$| $$  | $$| $$  | $$| $$  | $$
| $$     |  $$$$$$$|  $$$$$$$| $$ \  $$|  $$$$$$$  |  $$$$/      | $$  | $$|  $$$$$$/|  $$$$$$/| $$  | $$|  $$$$$$$
|__/      \_______/ \_______/|__/  \__/ \_______/   \___/        |__/  |__/ \______/  \______/ |__/  |__/ \_______/

                                                                                                                   
1.  Read from file (.phf)
2.  Start new capture
3.  How-to-use Packet Hound?
4.  Exit

'''
option = input(f"{mainMenu}\n>> ")

if (option == "1"):
    readFromFile()
elif (option == "2"):
    if not os.path.exists("./temp/"):
        os.mkdir("temp")
    open("./temp/temp.phf", 'wb').close()
    work()
elif (option == "3"):
    print(Instructions())
elif (option == "4"):
    print("="*5+" Exiting the application " + "="*5)
    sys.exit()
else:
    print("Wrong input. Exiting....")

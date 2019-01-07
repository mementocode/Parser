import socket
import numpy as np
import struct
import bitstring
import time
import bitstream
from crccheck.crc import Crc16Cdma2000, Crc16CcittFalse

# socket init
addr = '127.0.0.1'
port = 5000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((addr, port))
# bitstream init
stream = bitstream.BitStream()

'''frame byte fields
[0:3] preamble
[4:8] sync marker
[8:14] header
[14:16] header crc
[16:18] MPDU First Header Pointer
'''
''' internal MPDU header/divider
\x20
\x03\x33\xdb\x33\x00\xe6
'''


def receive_data(packet_len=512):
    return sock.recv(packet_len)


def get_binary(data):
    stream.write(data)
    return stream.read(len(data) * 8)


def check_header_crc(data):
    # crc = Crc16Cdma2000.calc(data[8:14]) #CDMA2000
    crc = hex(Crc16CcittFalse.calc(data[8:14]))  # CCITT False
    crc = crc[4] + crc[5] + crc[2] + crc[3]  # revers due to HARD realization
    return bytes.fromhex(crc) == data[14:16]


def get_idle_channel(data):
    if bytes.fromhex('BF') == data[9:10]:
        return True
    else:
        return False


def get_space_craft_id(data):
    return str(data)[66:74], str(data)[74:80]


def first_header_pointer_handler(data):
    if bytes.fromhex('0000') == data[16:18]:
        pass
    elif bytes.fromhex('07FF') == data[16:18]:
        pass


def get_header(packet_data):
    return str(packet_data)[64:112], len(str(packet_data)[64:112]), str(packet_data)[0:64], len(str(packet_data)[0:64])


#packet = receive_data()
#print(packet[16:18])
# print(check_header_crc(packet), get_idle_channel(packet))


while True:
    packet = receive_data()
    if check_header_crc(packet):
        if get_idle_channel(packet):
            continue

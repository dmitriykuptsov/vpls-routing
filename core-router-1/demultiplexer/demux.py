#!/usr/bin/python3

# Copyright (C) 2024 strangebit
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Threading
import threading
# Tunneling interfaces
from networking import tun
# IPv4 packet structure
from packets import IPv4
# Sockets
import socket
import traceback
# Utilities
from utils.misc import Misc

class Demultiplexer():

    def __init__(self, interfaces, own_ip):
        self.interfaces = interfaces
        self.demux_table = {}

        self.own_ip = own_ip

        self.tuns = []

        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.socket.bind(("r2-eth1", 0x0800))
        #self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);

        self.socket_raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket_raw.bind((own_ip, 0))
        self.socket_raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);

        for interface in self.interfaces:
            demux_tun = tun.Tun(address=interface["address"], mtu=interface["mtu"], name=interface["name"]);
            
            network = Misc.ipv4_address_to_int(interface["address"]) & Misc.ipv4_address_to_int(interface["mask"])
            self.demux_table[Misc.bytes_to_ipv4_string(Misc.int_to_ipv4_address(network))] = demux_tun;
            thread = threading.Thread(target=self.read_from_tun, args=(demux_tun, self.socket_raw, interface["destination"], interface["mtu"]), daemon=True)
            thread.start()

        thread = threading.Thread(target=self.read_from_public, args=(self.socket, ), daemon=True)
        thread.start()
        

    def read_from_public(self, sockfd, mtu = 1500):
        while True:
            try:
                print("+++++++++++++++++++++++++" + self.own_ip)
                print(self.own_ip)
                buf = sockfd.recv(mtu)
                print(list(buf[14:]))
                outer = IPv4.IPv4Packet(bytearray(buf[14:]))
                source = outer.get_source_address()
                destination = outer.get_destination_address()
                inner = IPv4.IPv4Packet(outer.get_payload())
                print("GOT PACKET ON PUBLIC INTERFACE")
                print(list(inner.get_buffer()))
                print(Misc.bytes_to_ipv4_string(source))
                print(Misc.bytes_to_ipv4_string(destination))
                source = inner.get_source_address()
                destination = inner.get_destination_address()
                print(Misc.bytes_to_ipv4_string(source))
                print(Misc.bytes_to_ipv4_string(destination))
                print(Misc.ipv4_address_to_int(Misc.bytes_to_ipv4_string(source)))
                print(Misc.ipv4_address_to_int("255.255.255.0"))
                network = Misc.ipv4_address_to_int(Misc.bytes_to_ipv4_string(destination)) & Misc.ipv4_address_to_int("255.255.255.0")
                print(network)
                tun = self.demux_table[Misc.bytes_to_ipv4_string(Misc.int_to_ipv4_address(network))]
                print("0000000000")
                print(Misc.bytes_to_ipv4_string(Misc.int_to_ipv4_address(network)))
                print("0000000000")
                tun.write(inner.get_buffer())
            except Exception as e:
                print(traceback.format_exc())
                print(e)

    
    def read_from_tun(self, tunfd, sockfd, destination, mtu = 1500):
        while True:
            try:
                print(".....GOT PACKET ON TUN INTERFACE.....")
                buf = tunfd.read(mtu);
                
                print("$$$$$$$$$$$$$$$$$$$$$$$$")
                print(list(buf))
                print("$$$$$$$$$$$$$$$$$$$$$$$$")
                inner = IPv4.IPv4Packet(bytearray(buf))

                ttl = inner.get_ttl()

                print(Misc.bytes_to_ipv4_string(inner.get_source_address()))
                print(Misc.bytes_to_ipv4_string(inner.get_destination_address()))

                outer = IPv4.IPv4Packet()
                outer.set_source_address(Misc.ipv4_address_to_bytes(self.own_ip))
                outer.set_destination_address(Misc.ipv4_address_to_bytes(destination))
                outer.set_protocol(4)
                outer.set_ttl(128)
                outer.set_ihl(5)
                outer.set_payload(inner.get_buffer())

                print("SENDING PACKET TO " + destination)
                
                outer.set_total_length(len(bytearray(outer.get_buffer())))
                print(list(outer.get_buffer()))

                sockfd.sendto(outer.get_buffer(), (destination, 0))
                #sockfd.send(outer.get_buffer())
            except Exception as e:
                
                print(e)

                raise e
        

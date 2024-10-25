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
# Utilities
from utils.misc import Misc

class Demultiplexer():

    def __init__(self, interfaces, own_ip):
        self.interfaces = interfaces
        self.demux_table = {}

        self.own_ip = own_ip

        self.tuns = []

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket.bind((own_ip, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);
        
        for interface in self.interfaces:
            demux_tun = tun.Tun(address=interface["address"], mtu=interface["mtu"], name=interface["name"]);
            self.demux_table[interface["destination"]] = demux_tun;
            thread = threading.Thread(target=self.read_from_tun, args=(demux_tun, self.socket, interface["destination"], interface["mtu"]), daemon=True)
            thread.start()

        thread = threading.Thread(target=self.read_from_public, args=(self.socket, ), daemon=True)
        thread.start()
        

    def read_from_public(self, sockfd, mtu = 1500):
        while True:
            try:
                buf = sockfd.recv(mtu)
                print(list(buf))
                outer = IPv4.IPv4Packet(bytearray(buf))
                source = outer.get_source_address()
                inner = outer.get_payload()
                print("GOT PACKET ON PUBLIC INTERFACE")
                print(Misc.bytes_to_ipv4_string(source))
                tun = self.demux_table[Misc.bytes_to_ipv4_string(source)]
                tun.write(inner)
            except Exception as e:
                print(e)

    
    def read_from_tun(self, tunfd, sockfd, destination, mtu = 1500):
        while True:
            try:
                buf = tunfd.read(mtu);
                print(list(buf))
                inner = IPv4.IPv4Packet(bytearray(buf))

                ttl = inner.get_ttl()

                print(inner.get_source_address())
                print(inner.get_destination_address())
                
                ttl -= 1
                
                if ttl <= 0:
                    continue

                inner.set_ttl(ttl)

                outer = IPv4.IPv4Packet()
                outer.set_source_address(Misc.ipv4_address_to_bytes(self.own_ip))
                outer.set_destination_address(Misc.ipv4_address_to_bytes(destination))
                outer.set_protocol(4)
                outer.set_ttl(128)
                outer.set_payload(inner.get_buffer())
                
                outer.set_total_length(len(bytearray(outer.get_buffer())))
                print(list(outer.get_buffer()))

                sockfd.sendto(outer.get_buffer(), (destination, 0))
            except Exception as e:
                
                print(e)
                raise e
        

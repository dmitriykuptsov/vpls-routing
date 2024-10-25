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

    def __init__(self, public_ip, private_ip, hub_ip):
        self.public_ip = public_ip
        self.private_ip = private_ip
        self.hub_ip = hub_ip

        self.socket_private = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket_private.bind((private_ip, 0))
        self.socket_private.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);

        self.socket_public = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket_private.bind((public_ip, 0))
        self.socket_public.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);
        
        thread = threading.Thread(target=self.read_from_public, args=(self.socket_private, self.socket_public, ), daemon=True)
        thread.start()

        thread = threading.Thread(target=self.read_from_private, args=(self.socket_private, self.socket_public, self.public_ip, self.hub_ip), daemon=True)
        thread.start()
        

    def read_from_public(self, pubfd, privfd, private_ip, mtu=1500):
        while True:
            try:
                buf = pubfd.recv(mtu)
                outer = IPv4.IPv4Packet(buf)
                inner = outer.get_payload()
                privfd.sendto(inner, (private_ip, 0))
            except Exception as e:
                print(e)

    def read_from_private(self, pubfd, privfd, public_ip, hub_ip, mtu=1500):
        while True:
            try:
                buf = privfd.recv(mtu)
                inner = IPv4.IPv4Packet(buf)
                packet = IPv4.IPv4Packet()
                packet.set_destination_address(Misc.ipv4_address_to_bytes(hub_ip))
                packet.set_source_address(Misc.ipv4_address_to_bytes(public_ip))
                packet.set_ttl(128)
                packet.set_payload(inner)
                packet.set_total_length(len(packet.get_buffer()))
                pubfd.sendto(packet.get_buffer(), (Misc.bytes_to_ipv4_string(public_ip), 0))
            except Exception as e:
                print(e)

   

        

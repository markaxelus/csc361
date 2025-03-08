#!/usr/bin/env python3

import struct
import socket
import sys

class IPv4Header:
    src_ip = None  
    dst_ip = None  
    header_length = None  
    total_length = None  

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.header_length = 0
        self.total_length = 0

    def set_ip_addresses(self, source_ip, destination_ip):
        self.src_ip = source_ip
        self.dst_ip = destination_ip

    def set_header_length(self, length):
        self.header_length = length

    def set_total_length(self, length):
        self.total_length = length

    def parse_ip_addresses(self, src_buffer, dst_buffer):
        src_parts = struct.unpack('BBBB', src_buffer)
        dst_parts = struct.unpack('BBBB', dst_buffer)
        source_ip_str = f"{src_parts[0]}.{src_parts[1]}.{src_parts[2]}.{src_parts[3]}"
        destination_ip_str = f"{dst_parts[0]}.{dst_parts[1]}.{dst_parts[2]}.{dst_parts[3]}"
        self.set_ip_addresses(source_ip_str, destination_ip_str)

    def parse_header_length(self, value):
        byte_value = struct.unpack('B', value)[0]
        length = (byte_value & 15) * 4
        self.set_header_length(length)

    def parse_total_length(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = (buffer[1] & 15)
        length = num1 + num2 + num3 + num4
        self.set_total_length(length)


class TCPHeader:
    source_port = 0
    destination_port = 0
    sequence_number = 0
    acknowledgment_number = 0
    header_length = 0
    flag_values = {}
    window_size = 0
    checksum = 0
    ugp = 0

    def __init__(self):
        self.source_port = 0
        self.destination_port = 0
        self.sequence_number = 0
        self.acknowledgment_number = 0
        self.header_length = 0
        self.flag_values = {}
        self.window_size = 0
        self.checksum = 0
        self.ugp = 0

    def set_source_port(self, port):
        self.source_port = port

    def set_destination_port(self, port):
        self.destination_port = port

    def set_sequence_number(self, seq):
        self.sequence_number = seq

    def set_acknowledgment_number(self, ack):
        self.acknowledgment_number = ack

    def set_header_length(self, length):
        self.header_length = length

    def set_flags(self, ack, rst, syn, fin):
        self.flag_values["ACK"] = ack
        self.flag_values["RST"] = rst
        self.flag_values["SYN"] = syn
        self.flag_values["FIN"] = fin

    def set_window_size(self, size):
        self.window_size = size

    def parse_source_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = (buffer[1] & 15)
        port = num1 + num2 + num3 + num4
        self.set_source_port(port)

    def parse_destination_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = (buffer[1] & 15)
        port = num1 + num2 + num3 + num4
        self.set_destination_port(port)

    def parse_sequence_number(self, buffer):
        seq = struct.unpack(">I", buffer)[0]
        self.set_sequence_number(seq)

    def parse_acknowledgment_number(self, buffer):
        ack = struct.unpack('>I', buffer)[0]
        self.set_acknowledgment_number(ack)

    def parse_flags(self, buffer):
        value = struct.unpack("B", buffer)[0]
        fin = value & 1
        syn = (value & 2) >> 1
        rst = (value & 4) >> 2
        ack = (value & 16) >> 4
        self.set_flags(ack, rst, syn, fin)

    def parse_window_size(self, buffer1, buffer2):
        combined_buffer = buffer2 + buffer1
        size = struct.unpack('H', combined_buffer)[0]
        self.set_window_size(size)

    def parse_header_data_offset(self, buffer):
        value = struct.unpack("B", buffer)[0]
        length = ((value & 240) >> 4) * 4
        self.set_header_length(length)

    def adjust_relative_sequence_number(self, original_number):
        if self.sequence_number >= original_number:
            self.set_sequence_number(self.sequence_number - original_number)

    def adjust_relative_acknowledgment_number(self, original_number):
        if self.acknowledgment_number >= original_number:
            self.set_acknowledgment_number(self.acknowledgment_number - original_number + 1)


class EthernetHeader:
    destination_mac = 0
    source_mac = 0
    ether_type = None

    def __init__(self):
        self.destination_mac = 0
        self.source_mac = 0
        self.ether_type = None

    def set_destination_mac(self, addr):
        mac_str = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", addr)
        self.destination_mac = mac_str

    def set_source_mac(self, addr):
        mac_str = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", addr)
        self.source_mac = mac_str

    def set_ether_type(self, t):
        type_num = struct.unpack('H', t)[0]
        self.ether_type = type_num


class GlobalHeader:
    magic_number = 0
    version_major = 0
    version_minor = 0
    timezone = 0
    sigfigs = 0
    snaplen = 0
    network = 0

    def __init__(self):
        self.magic_number = 0
        self.version_major = 0
        self.version_minor = 0
        self.timezone = 0
        self.sigfigs = 0
        self.snaplen = 0
        self.network = 0

    def set_magic_number(self, num):
        self.magic_number = num

    def set_version_major(self, version):
        self.version_major = version

    def set_version_minor(self, version):
        self.version_minor = version

    def set_timezone(self, zone):
        self.timezone = zone

    def set_sigfigs(self, sigfigs):
        self.sigfigs = sigfigs

    def set_snaplen(self, num):
        self.snaplen = num

    def set_network(self, network):
        self.network = network


class Packet:
    ethernet_header = None
    ip_header = None
    tcp_header = None
    timestamp = 0
    packet_number = 0
    rtt_value = 0
    rtt_flag = False
    raw_buffer = None
    packet_size = 0
    included_length = 0

    def __init__(self):
        self.ethernet_header = EthernetHeader()
        self.ip_header = IPv4Header()
        self.tcp_header = TCPHeader()
        self.timestamp = 0
        self.packet_number = 0
        self.rtt_value = 0.0
        self.rtt_flag = False
        self.raw_buffer = None
        self.packet_size = 0
        self.included_length = 16

    def set_timestamp(self, buffer1, buffer2, original_time, micro):
        seconds = struct.unpack('I', buffer1)[0]
        microseconds = struct.unpack('<I', buffer2)[0]
        base_time = struct.unpack('I', original_time)[0]
        base_micro = struct.unpack('<I', micro)[0]
        time_val = base_time + base_micro * 0.000001
        self.timestamp = round(seconds + microseconds * 0.000001 - time_val, 6)

    def set_packet_number(self, number):
        self.packet_number = number

    def set_packet_size(self, size):
        length = struct.unpack('I', size)[0]
        self.packet_size = length

    def set_included_length(self, length):
        size = struct.unpack('I', length)[0]
        self.included_length = size

    def get_payload_length(self):
        ip_header_length = self.ip_header.header_length
        ip_total_length = self.ip_header.total_length
        tcp_header_length = self.tcp_header.header_length
        return ip_total_length - ip_header_length - tcp_header_length


def compute_connection_id(buffer):
    source_ip, source_port, destination_ip, destination_port = buffer
    key = struct.unpack("!I", socket.inet_aton(source_ip))[0] + \
          struct.unpack("!I", socket.inet_aton(destination_ip))[0] + \
          source_port + destination_port
    return key


def compute_rtt(packet1, packet2):
    rtt = packet2.timestamp - packet1.timestamp
    return round(rtt, 8)


def parse_global_header(data):
    global_header = GlobalHeader()
    global_header.set_magic_number(data[0:4])
    global_header.set_version_major(data[4:6])
    global_header.set_version_minor(data[6:8])
    global_header.set_timezone(data[8:12])
    global_header.set_sigfigs(data[12:16])
    global_header.set_snaplen(data[16:20])
    global_header.set_network(data[20:24])
    return global_header


def parse_packet_header(packet_index, data, orig_time, orig_micro):
    pkt = Packet()
    buff1 = data[0:4]
    buff2 = data[4:8]
    incl_length = data[8:12]
    orig_length = data[12:16]
    pkt.set_packet_number(packet_index)
    pkt.set_timestamp(buff1, buff2, orig_time, orig_micro)
    pkt.set_included_length(incl_length)
    pkt.set_packet_size(orig_length)
    pkt.raw_buffer = data
    return pkt


def parse_ethernet_header(data):
    eth_header = EthernetHeader()
    eth_header.set_destination_mac(data[0:6])
    eth_header.set_source_mac(data[6:12])
    eth_header.set_ether_type(data[12:14])
    return eth_header


def parse_ipv4_header(data):
    ip_header = IPv4Header()
    src = data[26:30]
    dst = data[30:34]
    total_len = data[16:18]
    header_len = data[14:15]
    ip_header.parse_ip_addresses(src, dst)
    ip_header.parse_total_length(total_len)
    ip_header.parse_header_length(header_len)
    return ip_header


def parse_tcp_header(data):
    tcp_header = TCPHeader()
    src_port = data[34:36]
    dst_port = data[36:38]
    seq_num = data[38:42]
    ack_num = data[42:46]
    data_offset = data[46:47]
    flags = data[47:48]
    win1 = data[48:49]
    win2 = data[49:50]
    tcp_header.parse_source_port(src_port)
    tcp_header.parse_destination_port(dst_port)
    tcp_header.parse_sequence_number(seq_num)
    tcp_header.parse_acknowledgment_number(ack_num)
    tcp_header.parse_header_data_offset(data_offset)
    tcp_header.parse_window_size(win1, win2)
    tcp_header.parse_flags(flags)
    return tcp_header


def update_connection_with_packet(packet_obj, connections):
    src_ip = packet_obj.ip_header.src_ip
    dst_ip = packet_obj.ip_header.dst_ip
    src_port = packet_obj.tcp_header.source_port
    dst_port = packet_obj.tcp_header.destination_port
    connection_tuple = (src_ip, src_port, dst_ip, dst_port)
    connection_key = compute_connection_id(connection_tuple)
    if connection_key not in connections:
        conn = Connection(src_ip, src_port, dst_ip, dst_port)
        conn.add_packet(packet_obj)
        connections[connection_key] = conn
    else:
        connections[connection_key].add_packet(packet_obj)


def print_connection_details_summary(connections):
    connection_index = 1
    complete_conn_count = 0
    reset_conn_count = 0
    open_conn_count = 0
    established_before_count = 0
    total_packets = 0
    min_duration = float('inf')
    total_duration = 0
    max_duration = float('-inf')
    min_packets = float('inf')
    total_packets_complete = 0
    max_packets = float('-inf')
    min_rtt = float('inf')
    total_rtt = 0
    max_rtt = float('-inf')
    total_rtt_sum = 0
    min_window = float('inf')
    total_window_sum = 0
    max_window = float('-inf')

    print("A) Total Number of connections: ", len(connections))
    print("--------------------------------------------------")
    print("B) Connection Details:")
    for conn in connections.values():
        start_time, end_time, duration = conn.get_connection_time()
        if conn.is_complete():
            complete_conn_count += 1
            total_packets += conn.get_num_packets()
            min_duration = min(duration, min_duration)
            total_duration += duration
            max_duration = max(duration, max_duration)
            min_packets = min(conn.get_num_packets(), min_packets)
            total_packets_complete += conn.get_num_packets()
            max_packets = max(conn.get_num_packets(), max_packets)
            rtt_list = conn.calculate_rtt()
            if rtt_list:
                min_rtt = min(min(rtt_list), min_rtt)
                total_rtt_sum += sum(rtt_list)
                max_rtt = max(max(rtt_list), max_rtt)
                total_rtt += conn.get_rtt_count()
            min_window = min(conn.min_window, min_window)
            total_window_sum += conn.total_window
            max_window = max(conn.max_window, max_window)
        if conn.is_reset():
            reset_conn_count += 1
        if conn.is_open():
            open_conn_count += 1
        if conn.established_before_capture():
            established_before_count += 1

        print(f"Connection {connection_index}:")
        print("Source Address: ", conn.connection_address[0])
        print("Source Port: ", conn.connection_address[1])
        print("Destination Address: ", conn.connection_address[2])
        print("Destination Port: ", conn.connection_address[3])
        print("Status: ", conn.check_connection_state())
        if conn.is_complete():
            print("Start Time: ", start_time)
            print("End Time: ", end_time)
            print("Duration: ", round(duration, 6))
            print("Number of packets sent from Source to Destination: ", conn.get_source_packet_count())
            print("Number of packets sent from Destination to Source: ", conn.get_destination_packet_count())
            print("Total number of packets: ", conn.get_num_packets())
            print("Number of data bytes sent from Source to Destination: ", conn.get_source_bytes())
            print("Number of data bytes sent from Destination to Source: ", conn.get_destination_bytes())
            print("Total number of bytes sent: ", conn.get_total_bytes())
        print("END")
        print("++++++++++++++++++++++++++++++++")
        connection_index += 1

    print("C) General\n")
    print("Total number of complete TCP connections: ", complete_conn_count)
    print("Number of reset TCP connections: ", reset_conn_count)
    print("Number of TCP connections that were still open when the trace capture ended: ", open_conn_count)
    print("Number of TCP connections established before the capture start: ", established_before_count)
    print("--------------------------------------------------")
    print("D) Complete TCP connections:\n")
    print("Minimum time duration: %2f seconds" % min_duration)
    if complete_conn_count > 0:
        print("Mean time duration: %2f seconds" % float(total_duration / complete_conn_count))
    print("Maximum time duration: %2f seconds" % max_duration)
    print("")
    print("Minimum RTT value: ", min_rtt)
    if total_rtt > 0:
        print("Mean RTT value: ", round(total_rtt_sum / total_rtt, 6))
    print("Maximum RTT value: ", max_rtt)
    print("")
    print("Minimum number of packets sent/received: ", min_packets)
    if complete_conn_count > 0:
        print("Mean number of packets sent/received: ", float(total_packets_complete / complete_conn_count))
    print("Maximum number of packets sent/received: ", max_packets)
    print("")
    print("Minimum receive window size including sent/received: ", str(min_window) + " bytes")
    if total_packets > 0:
        print("Mean receive window size including sent/received: %2f " % float(total_window_sum / total_packets), "bytes")
    print("Maximum receive window size including sent/received: ", str(max_window) + " bytes")


def main():
    file_name = sys.argv[1]
    f = open(file_name, "rb")
    packets = []
    connections = {}
    data = f.read(24)
    global_header = parse_global_header(data)
    data = f.read(16)
    orig_time = data[0:4]
    orig_micro = data[4:8]
    packet_index = 0
    packets.append(parse_packet_header(packet_index, data, orig_time, orig_micro))
    data = f.read(packets[packet_index].included_length)
    packets[packet_index].ethernet_header = parse_ethernet_header(data)
    packets[packet_index].ip_header = parse_ipv4_header(data)
    packets[packet_index].tcp_header = parse_tcp_header(data)
    update_connection_with_packet(packets[packet_index], connections)
    while True:
        try:
            data = f.read(16)
            packet_index += 1
            packets.append(parse_packet_header(packet_index, data, orig_time, orig_micro))
            data = f.read(packets[packet_index].included_length)
            packets[packet_index].ethernet_header = parse_ethernet_header(data)
            packets[packet_index].ip_header = parse_ipv4_header(data)
            packets[packet_index].tcp_header = parse_tcp_header(data)
            update_connection_with_packet(packets[packet_index], connections)
        except struct.error:
            break
    print_connection_details_summary(connections)


class Utils:
    @staticmethod
    def compute_connection_id(buffer):
        return compute_connection_id(buffer)
    @staticmethod
    def compute_rtt(packet1, packet2):
        return compute_rtt(packet1, packet2)
    @staticmethod
    def GlobalHeader():
        return GlobalHeader()
    @staticmethod
    def Packet():
        return Packet()


class Structs:
    @staticmethod
    def Packet():
        return Packet()
    @staticmethod
    def EthernetHeader():
        return EthernetHeader()
    @staticmethod
    def IPv4Header():
        return IPv4Header()
    @staticmethod
    def TCPHeader():
        return TCPHeader()
    @staticmethod
    def PcapHeader():
        return PcapHeader()


class PcapHeader(GlobalHeader):
    pass


class Connection:
    connection_address = None
    packet_list = None
    flag_counters = None
    connection_state = None
    packets_sent = None
    bytes_sent = None
    start_time = None
    end_time = None
    total_window = None
    min_window = None
    max_window = None
    rtt_values = None
    connection_id = None

    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.connection_address = (src_ip, src_port, dst_ip, dst_port)
        self.packet_list = []
        self.connection_id = Utils.compute_connection_id(self.connection_address)
        self.packets_sent = {}
        self.bytes_sent = {}
        self.flag_counters = {}
        self.connection_state = "S0F0"
        self.start_time = float("inf")
        self.end_time = float("-inf")
        self.total_window = 0
        self.min_window = float("inf")
        self.max_window = float("-inf")
        self.rtt_values = []

    def add_packet(self, packet):
        self.packet_list.append(packet)
        self.update_flags(packet)
        self.update_packet_counts(packet)
        self.update_connection_time(packet)
        self.update_window_size(packet)

    def update_flags(self, packet):
        try:
            self.flag_counters["ACK"] += packet.tcp_header.flag_values["ACK"]
            self.flag_counters["RST"] += packet.tcp_header.flag_values["RST"]
            self.flag_counters["SYN"] += packet.tcp_header.flag_values["SYN"]
            self.flag_counters["FIN"] += packet.tcp_header.flag_values["FIN"]
        except KeyError:
            self.flag_counters["ACK"] = packet.tcp_header.flag_values["ACK"]
            self.flag_counters["RST"] = packet.tcp_header.flag_values["RST"]
            self.flag_counters["SYN"] = packet.tcp_header.flag_values["SYN"]
            self.flag_counters["FIN"] = packet.tcp_header.flag_values["FIN"]

    def update_packet_counts(self, packet):
        key = packet.ip_header.src_ip
        try:
            self.packets_sent[key] += 1
            self.bytes_sent[key] += packet.get_payload_length()
        except KeyError:
            self.packets_sent[key] = 1
            self.bytes_sent[key] = packet.get_payload_length()

    def update_connection_time(self, packet):
        if packet.tcp_header.flag_values["SYN"] == 1 and packet.tcp_header.flag_values["ACK"] == 0:
            self.start_time = min(packet.timestamp, self.start_time)
        if packet.tcp_header.flag_values["FIN"] == 1 and packet.tcp_header.flag_values["ACK"] == 1:
            self.end_time = max(packet.timestamp, self.end_time)

    def update_window_size(self, packet):
        self.total_window += packet.tcp_header.window_size
        self.min_window = min(packet.tcp_header.window_size, self.min_window)
        self.max_window = max(packet.tcp_header.window_size, self.max_window)

    def is_connection_finished(self):
        return self.flag_counters["FIN"] > 0

    def check_connection_state(self):
        ack = self.flag_counters["ACK"]
        rst = self.flag_counters["RST"]
        syn = self.flag_counters["SYN"]
        fin = self.flag_counters["FIN"]
        self.connection_state = "S" + str(syn) + "F" + str(fin)
        if rst > 0:
            self.connection_state += "/R"
        return self.connection_state

    def calculate_rtt(self):
        for src_packet in self.packet_list:
            if src_packet.ip_header.src_ip != self.connection_address[0]:
                continue
            ip_header_len = src_packet.ip_header.header_length
            tcp_offset = src_packet.tcp_header.header_length
            payload_length = src_packet.included_length - ip_header_len - tcp_offset - 14
            src_seq = src_packet.tcp_header.sequence_number
            src_flags = src_packet.tcp_header.flag_values
            for dst_packet in self.packet_list:
                if dst_packet.ip_header.src_ip != self.connection_address[2]:
                    continue
                ack_num = dst_packet.tcp_header.acknowledgment_number
                if payload_length > 0:
                    if ack_num == src_seq + payload_length:
                        rtt = Utils.compute_rtt(src_packet, dst_packet)
                        self.rtt_values.append(rtt)
                        break
                elif payload_length == 0:
                    if src_seq + 1 == ack_num:
                        if src_flags["SYN"] == 1 or src_flags["FIN"] == 1:
                            rtt = Utils.compute_rtt(src_packet, dst_packet)
                            self.rtt_values.append(rtt)
                            break
        return self.rtt_values

    def is_complete(self):
        return self.flag_counters["SYN"] > 0 and self.flag_counters["FIN"] > 0

    def is_reset(self):
        return self.flag_counters["RST"] > 0

    def is_open(self):
        return (self.flag_counters["SYN"] > 0 and 
                self.flag_counters["FIN"] == 0 and 
                self.flag_counters["RST"] == 0)

    def established_before_capture(self):
        if not self.packet_list:
            return False
        first_packet = self.packet_list[0]
        flags = first_packet.tcp_header.flag_values
        if (flags['SYN'] == 1 and flags['ACK'] == 1 and
            first_packet.ip_header.src_ip == self.connection_address[2] and
            first_packet.tcp_header.source_port == self.connection_address[3]):
            return True
        return False

    def get_connection_time(self):
        if self.end_time == float('-inf'):
            self.end_time = self.packet_list[-1].timestamp
        return self.start_time, self.end_time, self.end_time - self.start_time

    def get_source_packet_count(self):
        return self.packets_sent[self.connection_address[0]]

    def get_destination_packet_count(self):
        return self.packets_sent[self.connection_address[2]]

    def get_source_bytes(self):
        return self.bytes_sent[self.connection_address[0]]

    def get_destination_bytes(self):
        return self.bytes_sent[self.connection_address[2]]

    def get_total_bytes(self):
        return self.bytes_sent[self.connection_address[0]] + self.bytes_sent[self.connection_address[2]]

    def get_rtt_count(self):
        return len(self.rtt_values)

    def get_num_packets(self):
        return len(self.packet_list)


first_packet_flag = True
initial_timestamp = 0

def parse_pcap_global_header(global_header_bytes):
    pcap_global_header = Structs.PcapHeader()
    pcap_global_header.set_magic_number(global_header_bytes[0:4])
    pcap_global_header.set_version_major(global_header_bytes[4:6])
    pcap_global_header.set_version_minor(global_header_bytes[6:8])
    pcap_global_header.set_timezone(global_header_bytes[8:12])
    pcap_global_header.set_sigfigs(global_header_bytes[12:16])
    pcap_global_header.set_snaplen(global_header_bytes[16:20])
    pcap_global_header.set_network(global_header_bytes[20:24])
    return pcap_global_header

def parse_packet(f):
    packet_header_bytes = f.read(16)
    global first_packet_flag
    global initial_timestamp
    if first_packet_flag:
        orig_time_seconds = packet_header_bytes[0:4]
        orig_time_micro = packet_header_bytes[4:8]
        seconds = struct.unpack('I', orig_time_seconds)[0]
        microseconds = struct.unpack('I', orig_time_micro)[0]
        initial_timestamp = seconds + microseconds / 1000000
        first_packet_flag = False
    pkt = Structs.Packet()
    buffer1 = packet_header_bytes[0:4]
    buffer2 = packet_header_bytes[4:8]
    incl_length = packet_header_bytes[8:12]
    orig_length = packet_header_bytes[12:16]
    pkt.set_timestamp(buffer1, buffer2, struct.pack("I", int(initial_timestamp)),
                      struct.pack("I", int((initial_timestamp * 1000000) % 1000000)))
    pkt.set_included_length(incl_length)
    print("TIME: ", pkt.timestamp)
    print("INCLUDED LENGTH: ", pkt.included_length)
    packet_data = f.read(pkt.included_length)
    ethernet_header = Structs.EthernetHeader()
    dest_mac = packet_data[0:6]
    src_mac = packet_data[6:12]
    ether_type = packet_data[12:14]
    ipv4_header = Structs.IPv4Header()
    header_length = packet_data[14:15]
    total_length = packet_data[16:18]
    src_addr = packet_data[26:30]
    dst_addr = packet_data[30:34]
    ipv4_header.parse_ip_addresses(src_addr, dst_addr)
    ipv4_header.parse_total_length(total_length)
    ipv4_header.parse_header_length(header_length)
    print("SRC IP: ", ipv4_header.src_ip)
    print("DEST IP: ", ipv4_header.dst_ip)
    print("Total Length: ", ipv4_header.total_length)
    print("Header Length: ", ipv4_header.header_length)
    tcp_header = Structs.TCPHeader()
    src_port = packet_data[34:36]
    dst_port = packet_data[36:38]
    seq_number = packet_data[38:42]
    ack_number = packet_data[42:46]
    data_offset = packet_data[46:47]
    flags = packet_data[47:48]
    win1 = packet_data[48:49]
    win2 = packet_data[49:50]
    tcp_header.parse_source_port(src_port)
    tcp_header.parse_destination_port(dst_port)
    tcp_header.parse_sequence_number(seq_number)
    tcp_header.parse_acknowledgment_number(ack_number)
    tcp_header.parse_header_data_offset(data_offset)
    tcp_header.parse_flags(flags)
    tcp_header.parse_window_size(win1, win2)
    print("SRC PORT: ", tcp_header.source_port)
    print("DEST PORT: ", tcp_header.destination_port)
    print("SEQ: ", tcp_header.sequence_number)
    print("ACK: ", tcp_header.acknowledgment_number)
    print("DATA OFFSET: ", tcp_header.header_length)
    print("WINDOW SIZE: ", tcp_header.window_size)
    print("FLAGS: ", tcp_header.flag_values)
    pkt.ip_header = ipv4_header
    pkt.tcp_header = tcp_header
    return pkt

def main_inspect_mode():
    file_path = sys.argv[1]
    f = open(file_path, "rb")
    global_header_bytes = f.read(24)
    pcap_global_header = parse_pcap_global_header(global_header_bytes)
    for _ in range(2):
        pkt = parse_packet(f)
        print("--------------------------------------------------")


if __name__ == '__main__':
    if len(sys.argv) > 2 and sys.argv[2] == "inspect":
        main_inspect_mode()
    else:
        main()
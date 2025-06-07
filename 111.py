import struct
import socket
import os
import csv 

# PcapNG Block Types
BLOCK_TYPE_SHB = 0x0A0D0D0A
BLOCK_TYPE_IDB = 0x00000001
BLOCK_TYPE_EPB = 0x00000006
BLOCK_TYPE_SPB = 0x00000003

# EtherTypes
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

# IP Protocols
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# TLS Content Types
TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20
TLS_CONTENT_TYPE_ALERT = 21
TLS_CONTENT_TYPE_HANDSHAKE = 22
TLS_CONTENT_TYPE_APPLICATION_DATA = 23
TLS_CONTENT_TYPE_HEARTBEAT = 24

# TLS Versions
TLS_VERSION_MAP = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3"
}

# CSV output related constants
DEFAULT_NUM_FEATURES = 20  # Number of packet length sequence features (n)
CSV_OUTPUT_FILENAME = 'dataset.csv'
# Updated CSV_HEADER with English names
CSV_HEADER = ['Application', 'PcapFile', 'FlowID'] # Feature columns will be added dynamically

class PcapNgParser:
    def __init__(self, filepath):
        self.filepath = os.path.abspath(filepath)
        self.filename = os.path.basename(self.filepath)
        self.app_name = self._extract_app_name_from_path(self.filepath)
        self.endian_format = ''
        self.link_type = -1
        self.streams = {}
        self.packet_count_in_file = 0
        self.parsed_packet_count = 0
        self.flow_counter = 0

    def _extract_app_name_from_path(self, file_path):
        try:
            parts = file_path.split(os.sep)

            last_td_index = -1
            for i in range(len(parts) - 1, -1, -1):
                if parts[i].lower() == 'traffic-dataset': # Case-insensitive check for directory name
                    last_td_index = i
                    break
            
            if last_td_index != -1 and last_td_index + 1 < len(parts) -1:
                # The directory after the last 'traffic-dataset' is considered the app name
                potential_app_name = parts[last_td_index + 1]
                # Basic sanity check: avoid taking 'file.pcapng' as app name if structure is flatter
                if not potential_app_name.lower().endswith('.pcapng'):
                    return potential_app_name

            # Fallback: if 'traffic-dataset' logic doesn't yield a result,
            # take the parent directory of the pcap file as the app name.
            if len(parts) >= 2:
                parent_dir_name = parts[-2]
                if not parent_dir_name.lower().endswith('.pcapng'): # Another sanity check
                    return parent_dir_name
                    
        except Exception as e:
            print(f"Warning: Could not auto-detect app name from path '{file_path}': {e}")
        return "UnknownApp"

    def _read_block_header(self, f):
        try:
            block_type_raw = f.read(4)
            if not block_type_raw: return None, None, None
            block_type = struct.unpack('<I', block_type_raw)[0]
            if block_type == BLOCK_TYPE_SHB and not self.endian_format:
                block_total_length_raw = f.read(4)
                block_total_length = struct.unpack('<I', block_total_length_raw)[0]
                current_pos = f.tell(); byte_order_magic_raw = f.read(4)
                if not byte_order_magic_raw or len(byte_order_magic_raw) < 4: raise ValueError("No byte_order_magic")
                if struct.unpack('<I', byte_order_magic_raw)[0] == 0x1A2B3C4D: self.endian_format = '<'
                elif struct.unpack('>I', byte_order_magic_raw)[0] == 0x1A2B3C4D:
                    self.endian_format = '>'; block_total_length = struct.unpack(self.endian_format + 'I', block_total_length_raw)[0]
                else:
                    magic_sw_l = struct.unpack('<I', byte_order_magic_raw)[0]; magic_sw_b = struct.unpack('>I', byte_order_magic_raw)[0]
                    if magic_sw_l == 0x4D3C2B1A: self.endian_format = '>'; block_total_length = struct.unpack(self.endian_format + 'I', block_total_length_raw)[0]
                    elif magic_sw_b == 0x4D3C2B1A: self.endian_format = '<'
                    else: raise ValueError(f"Invalid SHB Magic: {hex(magic_sw_l)} or {hex(magic_sw_b)}")
                f.seek(current_pos); block_body_len = block_total_length - 12
                return block_type, block_total_length, block_body_len
            fmt = self.endian_format if self.endian_format else '<'
            block_type = struct.unpack(fmt + 'I', block_type_raw)[0]
            block_total_length_raw = f.read(4)
            if not block_total_length_raw: return None, None, None
            block_total_length = struct.unpack(fmt + 'I', block_total_length_raw)[0]
            if block_total_length < 12: raise ValueError(f"Invalid block length: {block_total_length}")
            block_body_len = block_total_length - 12
            return block_type, block_total_length, block_body_len
        except (struct.error, Exception): return None, None, None

    def _parse_shb(self, f, body_len):
        shb_body = f.read(body_len)
        if len(shb_body) < body_len: raise EOFError("EOF in SHB")
        # No critical info needed beyond endianness setting from _read_block_header for this task

    def _parse_idb(self, f, body_len):
        idb_body = f.read(body_len)
        if len(idb_body) < body_len: raise EOFError("EOF in IDB")
        self.link_type = struct.unpack(self.endian_format + 'H', idb_body[0:2])[0]

    def _parse_epb(self, f, body_len):
        epb_body = f.read(body_len)
        if len(epb_body) < body_len: raise EOFError("EOF in EPB")
        fmt_prefix = self.endian_format
        captured_len = struct.unpack(fmt_prefix + 'I', epb_body[12:16])[0]
        original_len = struct.unpack(fmt_prefix + 'I', epb_body[16:20])[0]
        packet_data = epb_body[20 : 20 + captured_len]
        self.packet_count_in_file += 1
        self._parse_packet(packet_data, captured_len, original_len, self.packet_count_in_file)

    def _parse_tls_header(self, data):
        if len(data) < 5: return None
        try:
            content_type = data[0]
            version_raw = struct.unpack('>H', data[1:3])[0]
            record_length = struct.unpack('>H', data[3:5])[0]
            return {'content_type': content_type, 'version_raw': version_raw,
                    'version_str': TLS_VERSION_MAP.get(version_raw, f"Unknown (0x{version_raw:04X})"),
                    'length': record_length}
        except (struct.error, IndexError): return None

    def _parse_packet(self, data, captured_len, original_len, global_packet_num):
        if self.link_type != 1: return # Only Ethernet for now
        if captured_len < 14: return
        ethertype = struct.unpack('>H', data[12:14])[0]

        if ethertype == ETHERTYPE_IPV4:
            if captured_len < 14 + 20: return # Min Eth + IPv4 header
            ip_header_data = data[14:]
            ihl_byte = ip_header_data[0]; ip_version = ihl_byte >> 4
            ip_header_length = (ihl_byte & 0x0F) * 4
            if ip_version != 4 or captured_len < 14 + ip_header_length: return

            total_ip_len = struct.unpack('>H', ip_header_data[2:4])[0]
            protocol = ip_header_data[9]
            src_ip = socket.inet_ntoa(ip_header_data[12:16])
            dst_ip = socket.inet_ntoa(ip_header_data[16:20])
            self.parsed_packet_count += 1

            packet_info = {
                'src_ip': src_ip, 'dst_ip': dst_ip,
                'protocol_num': protocol, 'protocol_name': 'Unknown',
                'src_port': None, 'dst_port': None,
                'transport_payload_length': 0,
                'ip_total_length': total_ip_len,
            }
            transport_layer_data_start = 14 + ip_header_length
            transport_layer_data = data[transport_layer_data_start:]

            if protocol == IPPROTO_TCP:
                packet_info['protocol_name'] = 'TCP'
                if len(transport_layer_data) < 20: return # Min TCP header
                src_port = struct.unpack('>H', transport_layer_data[0:2])[0]
                dst_port = struct.unpack('>H', transport_layer_data[2:4])[0]
                data_offset_byte = transport_layer_data[12]
                tcp_header_length = ((data_offset_byte & 0xF0) >> 4) * 4
                if len(transport_layer_data) < tcp_header_length: return

                packet_info['src_port'] = src_port; packet_info['dst_port'] = dst_port
                tcp_payload_len = total_ip_len - ip_header_length - tcp_header_length
                packet_info['transport_payload_length'] = max(0, tcp_payload_len)

                stream_key = (src_ip, dst_ip, src_port, dst_port)
                if stream_key not in self.streams:
                    self.flow_counter += 1
                    self.streams[stream_key] = {
                        'flow_id': f"{self.app_name}_{self.filename}_flow_{self.flow_counter}",
                        'packets': []
                    }
                self.streams[stream_key]['packets'].append(packet_info)

            elif protocol == IPPROTO_UDP:
                packet_info['protocol_name'] = 'UDP'
                if len(transport_layer_data) < 8: return # UDP header size
                src_port = struct.unpack('>H', transport_layer_data[0:2])[0]
                dst_port = struct.unpack('>H', transport_layer_data[2:4])[0]
                udp_length_field = struct.unpack('>H', transport_layer_data[4:6])[0]
                packet_info['src_port'] = src_port; packet_info['dst_port'] = dst_port
                packet_info['transport_payload_length'] = udp_length_field - 8 # UDP data length

                stream_key = (src_ip, dst_ip, src_port, dst_port)
                if stream_key not in self.streams:
                    self.flow_counter += 1
                    self.streams[stream_key] = {
                        'flow_id': f"{self.app_name}_{self.filename}_flow_{self.flow_counter}_UDP",
                        'packets': []
                    }
                self.streams[stream_key]['packets'].append(packet_info)

    def parse(self):
        print(f"Starting to parse file: {self.filepath} (App: {self.app_name})")
        self.packet_count_in_file = 0; self.parsed_packet_count = 0
        self.flow_counter = 0; self.streams = {}
        parse_status_message = "Parsing finished (reached EOF)."

        try:
            with open(self.filepath, 'rb') as f:
                while True:
                    current_block_offset = f.tell()
                    block_type, block_total_length, body_len = self._read_block_header(f)
                    if block_type is None: break
                    if block_total_length == 0 or body_len < 0:
                        parse_status_message = f"Warning: Invalid block at offset {current_block_offset} (type: {hex(block_type if block_type else 0)}). Stopping."
                        break
                    if block_type == BLOCK_TYPE_SHB: self._parse_shb(f, body_len)
                    elif block_type == BLOCK_TYPE_IDB:
                        if not self.endian_format: raise ValueError("IDB before SHB")
                        self._parse_idb(f, body_len)
                    elif block_type == BLOCK_TYPE_EPB:
                        if not self.endian_format: raise ValueError("EPB before SHB")
                        if self.link_type == -1: print(f"Warning: EPB before IDB for file {self.filename}.")
                        self._parse_epb(f, body_len)
                    else: # Unknown or unhandled block type
                        f.seek(current_block_offset + 8 + body_len) # Skip block body
                    f.seek(current_block_offset + block_total_length) # Move to the start of the next block
        except FileNotFoundError: parse_status_message = f"Error: File not found at {self.filepath}"; return # Exit parse if file not found
        except EOFError as e: parse_status_message = f"Parsing stopped due to EOFError: {e}"
        except ValueError as e: parse_status_message = f"Parsing stopped due to ValueError: {e}"
        except Exception as e:
            import traceback
            traceback.print_exc()
            parse_status_message = f"Parsing stopped due to unexpected error: {e}"

        print(parse_status_message)
        print(f"Packets found in EPBs: {self.packet_count_in_file}")
        print(f"Packets successfully parsed (L2-L4): {self.parsed_packet_count}")
        print(f"Total flows identified: {len(self.streams)}")

    def get_flow_features_for_csv(self, num_features=DEFAULT_NUM_FEATURES):
        rows = []
        if not self.streams:
            return rows

        for _stream_key_tuple, stream_data in self.streams.items():
            # Ensure we only process flows that have packets and are likely TCP/UDP
            if not stream_data['packets']:
                continue
            
            first_packet_protocol = stream_data['packets'][0].get('protocol_name', 'Unknown')
            if first_packet_protocol not in ['TCP', 'UDP']:
                 # print(f"Skipping flow {stream_data['flow_id']} as it is not TCP/UDP (protocol: {first_packet_protocol}) for feature extraction.")
                continue # Skip non-TCP/UDP flows for packet length sequence

            packet_lengths = []
            for pkt in stream_data['packets']:
                # Use 'transport_payload_length' as the primary feature for packet length
                length = pkt.get('transport_payload_length', 0) # Default to 0 if missing
                packet_lengths.append(length)

            if len(packet_lengths) < num_features:
                packet_lengths.extend([0] * (num_features - len(packet_lengths)))
            else:
                packet_lengths = packet_lengths[:num_features]

            row = [
                self.app_name,
                self.filename,
                stream_data['flow_id']
            ] + packet_lengths
            rows.append(row)
        return rows

def process_pcapng_and_save_to_csv(pcapng_file_path, csv_writer_obj, num_features=DEFAULT_NUM_FEATURES, is_first_file=False):
    parser = PcapNgParser(pcapng_file_path)
    parser.parse()
    flow_feature_rows = parser.get_flow_features_for_csv(num_features)

    if is_first_file:
        # Use updated CSV_HEADER with English names
        header = CSV_HEADER + [f'Feature{i+1}' for i in range(num_features)]
        csv_writer_obj.writerow(header)

    if flow_feature_rows:
        csv_writer_obj.writerows(flow_feature_rows)
        print(f"Appended {len(flow_feature_rows)} flows from {parser.filename} to '{CSV_OUTPUT_FILENAME}'")
    else:
        print(f"No processable (TCP/UDP) flows with features extracted from {parser.filename}")



if __name__ == '__main__':
    base_traffic_dataset_dir = r"D:\网络智能技术与应用综合实践相关\traffic-dataset\traffic-dataset"
    num_fsnet_features = DEFAULT_NUM_FEATURES

    all_pcapng_files = []
    if not os.path.isdir(base_traffic_dataset_dir):
        print(f"Error: Base directory '{base_traffic_dataset_dir}' not found. Please check the path.")
        # Fallback to dummy file creation was here, ensure it's what you want if base dir is invalid
        # For now, let's assume if base_dir is invalid, we exit or rely on dummy file below
        # ... (dummy file logic might still trigger if all_pcapng_files remains empty later)
    else: # base_traffic_dataset_dir IS a directory
        print(f"Scanning for app folders in: {base_traffic_dataset_dir}")
        for app_folder_name in os.listdir(base_traffic_dataset_dir):
            app_folder_path = os.path.join(base_traffic_dataset_dir, app_folder_name)
            print(f"  Checking entry: {app_folder_path}")
            if os.path.isdir(app_folder_path):
                print(f"    '{app_folder_name}' is a directory. Scanning for pcapng files...")
                for item_in_app_folder in os.listdir(app_folder_path):
                    item_path = os.path.join(app_folder_path, item_in_app_folder) # Get full path for item
                    print(f"      Checking item in app folder: {item_path}")
                    if item_in_app_folder.lower().endswith('.pcapng'):
                        # Ensure it's a file, not a directory ending with .pcapng (unlikely but good check)
                        if os.path.isfile(item_path):
                            all_pcapng_files.append(item_path) # Store full path
                            print(f"        Found pcapng: {item_path}")
                        else:
                            print(f"        Skipping directory-like entry ending with .pcapng: {item_path}")

    if not all_pcapng_files:
        print(f"No .pcapng files found in the subdirectories of '{base_traffic_dataset_dir}'.")
        print("Attempting to create and use a dummy 'example.pcapng' for testing.")
        dummy_pcapng_file_path = 'example.pcapng'
        try:
            # ... (dummy file creation code as in the previous response) ...
            with open(dummy_pcapng_file_path, 'wb') as f:
                shb_data = struct.pack('<I', BLOCK_TYPE_SHB); shb_len = 28; shb_data += struct.pack('<I', shb_len); shb_data += struct.pack('<I', 0x1A2B3C4D); shb_data += struct.pack('<H', 1); shb_data += struct.pack('<H', 0); shb_data += struct.pack('<q', -1); shb_data += struct.pack('<I', shb_len); f.write(shb_data)
                idb_data = struct.pack('<I', BLOCK_TYPE_IDB); idb_len = 20; idb_data += struct.pack('<I', idb_len); idb_data += struct.pack('<H', 1); idb_data += struct.pack('<H', 0); idb_data += struct.pack('<I', 65535); idb_data += struct.pack('<I', idb_len); f.write(idb_data)
                eth_dst_mac1 = b'\x00\x01\x02\x03\x04\x05'; eth_src_mac1 = b'\x0A\x0B\x0C\x0D\x0E\x01'; eth_type_ipv4 = struct.pack('>H', ETHERTYPE_IPV4); ethernet_header1 = eth_dst_mac1 + eth_src_mac1 + eth_type_ipv4
                ip_header1 = b'\x45'; ip_header1 += b'\x00'; ip_header1 += struct.pack('>H', 20+20+10); ip_header1 += b'\x00\x01'; ip_header1 += b'\x00\x00'; ip_header1 += b'\x40'; ip_header1 += struct.pack('B', IPPROTO_TCP); ip_header1 += b'\x00\x00'; ip_header1 += socket.inet_aton('10.0.0.1'); ip_header1 += socket.inet_aton('10.0.0.2')
                tcp_header1 = struct.pack('>H', 12345); tcp_header1 += struct.pack('>H', 443); tcp_header1 += struct.pack('>I', 1000); tcp_header1 += struct.pack('>I', 0); tcp_header1 += struct.pack('>H', (5 << 12) | 0x02 ); tcp_header1 += struct.pack('>H', 1024); tcp_header1 += b'\x00\x00'; tcp_header1 += b'\x00\x00'
                payload1 = b'helloworld'
                packet_data1 = ethernet_header1 + ip_header1 + tcp_header1 + payload1; captured_len1 = len(packet_data1); padded_captured_len1 = (captured_len1 + 3) & ~3
                epb_total_len1 = 12 + (20 + padded_captured_len1)
                epb_data1 = struct.pack('<I', BLOCK_TYPE_EPB); epb_data1 += struct.pack('<I', epb_total_len1); epb_data1 += struct.pack('<I', 0); epb_data1 += struct.pack('<I', 0); epb_data1 += struct.pack('<I', 0); epb_data1 += struct.pack('<I', captured_len1); epb_data1 += struct.pack('<I', captured_len1); epb_data1 += packet_data1; epb_data1 += b'\x00' * (padded_captured_len1 - captured_len1); epb_data1 += struct.pack('<I', epb_total_len1); f.write(epb_data1)
            print(f"Dummy pcapng file '{dummy_pcapng_file_path}' created for testing.")
            all_pcapng_files.append(os.path.abspath(dummy_pcapng_file_path))
        except Exception as e_create:
            print(f"Could not create dummy pcapng file '{dummy_pcapng_file_path}': {e_create}")
            # If dummy creation fails, and we had no other files, we should probably exit
            if not all_pcapng_files: # Check again, just in case
                exit()

    print(f"Found {len(all_pcapng_files)} pcapng files to process.") # This line will now reflect if dummy was added

    try:
        with open(CSV_OUTPUT_FILENAME, 'w', newline='', encoding='utf-8') as csvfile: 
            csv_writer = csv.writer(csvfile)

            if not all_pcapng_files: # If still no files (e.g. dummy creation also failed or was skipped)
                print(f"No pcapng files to process. '{CSV_OUTPUT_FILENAME}' will be empty or only have a header if it was the first attempt.")
                # Write header even if no data, so the file structure is clear
                header = CSV_HEADER + [f'Feature{i+1}' for i in range(num_fsnet_features)]
                csv_writer.writerow(header)
            else:
                for index, pcap_file in enumerate(all_pcapng_files):
                    print(f"\nProcessing file {index + 1}/{len(all_pcapng_files)}: {pcap_file}")
                    process_pcapng_and_save_to_csv(
                        pcap_file, 
                        csv_writer, 
                        num_features=num_fsnet_features,
                        is_first_file=(index == 0)
                    )
        print(f"\nDataset generation complete. Output saved to '{CSV_OUTPUT_FILENAME}'")
    # ... (except blocks) ...
    except IOError as e:
        print(f"Error opening or writing to CSV file '{CSV_OUTPUT_FILENAME}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred during CSV generation: {e}")
        import traceback
        traceback.print_exc()
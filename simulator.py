"""
simulator.py — Attack Simulation Module
Uses Scapy to simulate Port Scanning and ICMP Flood attacks.
REQUIRES root/administrator privileges to send raw packets.
"""
import time
from scapy.all import IP, TCP, ICMP, send

def run_port_scan(target_ip, start_port, end_port, log_queue) :

    """
    Simulate a TCP SYN port scan on target_ip.
    Sends a SYN packet to each port and checks the response.
    Puts log messages into log_queue for the Flask SSE stream.
    Returns a list of open port numbers.
    """

    open_ports = []
    log_queue.put(f"[Scan] Starting port scan on {target_ip} ")
    log_queue.put(f"[Scan] Scanning ports {start_port} to {end_port}...")  

    """
    The code loops through each port, builds a "Hello" packet, sends it,
    and then categorizes the result: did they answer,
    or did they ignore us?
    """

    for current_port in range(start_port, end_port + 1) :
        log_queue.put(f"[SCAN] Probing port {current_port} on {target_ip}...")
    
        syn_packet = IP(dst=target_ip) / TCP(dport=current_port, flags="S")
        try:
            # Send packet and wait 1 second for a response
            response_packet = sr1(syn_packet, timeout=1, verbose=0)
            if response_packet is None:
                # No response — port is filtered or host unreachable
                log_queue.put(f"[SCAN] No response from port {current_port} : Filtered (possible firewall)")
            elif response_packet.haslayer(TCP):
                tcp_flags = response_packet[TCP].flags
                if tcp_flags == 0x12:  # SYN-ACK
                    open_ports.append(current_port)
                    log_queue.put(f"[ALERT] Port {current_port} is OPEN (SYN-ACK received) on {target_ip}")
                elif tcp_flags == 0x14:  # RST-ACK
                    log_queue.put(f"[SCAN] Port {current_port} is CLOSED (RST-ACK received)")

        except PermissionError:
            error_message = f"[ERROR] Permission denied: Root privileges required to send raw packets."  
            log_queue.put(error_message)
            return open_ports
    
        except Exception as general_error:
            log_queue.put(f"[ERROR] An error occurred while scanning port {current_port} : {str(general_error)}")


    log_queue.put(f"[SCAN] Port scan completed. Open ports: {open_ports}")
    return open_ports

"""
def run_icmp_flood(target_ip, packet_count, log_queue) :

packet_sent=0
log_queue.put(f"[flood] Starting ICMP flood attack on {target_ip} )
log_queue.put(f"[flood] Sending {packet_count} ICMP Echo Request packets to {target_ip}...")

for packet_number in range(packet_count) :
    icmp_packet = IP(dst=target_ip) / ICMP()
    send(icmp_packet, verbose=0)
    packet_sent += 1

    if packet_sent % 10 == 0 :
        log_queue.put(f"[flood] Sent {packet_sent}/{packet_count} ICMP packets to {target_ip}...")
"""

def run_icmp_flood(target_ip, packet_count, log_queue) :

    """
    Simulate an ICMP Flood attack on target_ip.
    Sends a specified number of ICMP Echo Request packets in rapid succession.
    Puts log messages into log_queue for the Flask SSE stream.
    """

    packet_sent = 0
    log_queue.put(f"[FLOOD] Starting ICMP flood attack on {target_ip} ")
    log_queue.put(f"[FLOOD] Sending {packet_count} ICMP Echo Request packets to {target_ip}...")

    for packet_number in range(packet_count) :
        icmp_packet = IP(dst=target_ip) / ICMP()
        try:
            send(icmp_packet, verbose=0)
            packet_sent += 1

            if packet_sent % 10 == 0 :
                log_queue.put(f"[FLOOD] Sent {packet_sent}/{packet_count} ICMP packets to {target_ip}...")

        except PermissionError:
            error_message = f"[ERROR] Permission denied: Root privileges required to send raw packets."  
            log_queue.put(error_message)
            return
    
        except Exception as general_error:
            log_queue.put(f"[ERROR] An error occurred while sending ICMP packet {packet_number + 1} : {str(general_error)}")

    log_queue.put(f"[FLOOD] ICMP flood attack completed. Total packets sent: {packet_sent}")
    return packet_sent
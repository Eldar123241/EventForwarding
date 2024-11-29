import pyshark

def process_packet(packet):
    print("Обработан пакет: ", packet.tcp.data)  # Отладочный вывод
    if 'TCP' in packet and int(packet.tcp.len) > 1000:
        with open('captured_packets.txt', 'a') as f:
            f.write(f'Packet captured: {packet.tcp.data}\n')


capture = pyshark.LiveCapture(interface='Adapter for loopback traffic capture', display_filter='tcp.port == 9999 and ip.src == 127.0.0.1 and ip.dst == 127.0.0.1')

print("Starting packet capture...")

capture.apply_on_packets(process_packet)

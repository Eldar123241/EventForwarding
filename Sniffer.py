import pyshark

def extract_event_message(text):
    # Находим значение EventMessage
    event_message_start = human_readable.find(text)
    
    if event_message_start == -1:
        return None  # Если EventMessage не найден, возвращаем None
    
    event_message_start += len(text)
    event_message_end = human_readable.find('\\"', event_message_start)

    # # Проверяем, найден ли конец строки
    # if event_message_end == -1:
    #     return None  # Если конец не найден, возвращаем None

    # Извлекаем значение
    event_message = human_readable[event_message_start:event_message_end]
    
    # Заменяем escape-последовательности на соответствующие символы
    event_message = event_message.encode().decode('unicode_escape')
    
    return event_message


capture = pyshark.LiveCapture(interface='Adapter for loopback traffic capture', display_filter='tcp.port == 9999')
for packet in capture:
   lenght = int(packet.tcp.len)
   if lenght > 1000:
        payload = packet.tcp.payload
        hex_split = payload.split(':')
        hex_as_chars = map(lambda hex: chr(int(hex, 16)), hex_split)
        human_readable = ''.join(hex_as_chars)
        # print(f'Decoded payload: {human_readable}')
    
        print('DataTime - ' ,extract_event_message('DataTime=\\"'), '\n')
        print('EventMessage - ' ,extract_event_message('EventMessage=\\"'), '\n')
        print('Description - ' ,extract_event_message('Description=\\"'), '\n')
        print(human_readable)







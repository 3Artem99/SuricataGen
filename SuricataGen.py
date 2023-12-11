import os
import requests
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dns import DNS
import os
from scapy.layers.http import HTTPRequest
import socket
 
REMOTE_SERVER = "www.google.com" 
suricata_rules = set() 
 
def check_internet_connection(): 
    try: 
        # Создаем объект сокета 
        socket.create_connection((REMOTE_SERVER, 80)) 
        return True 
    except OSError: 
        pass 
    return False 
 
if check_internet_connection(): 
    print("Подключение к интернету есть.")

    API_KEY = "ef33adc4827366c9ddacadc3b30ff3342eae471b1abcd60a13c65bd44c8b5e92"
    suricata_rules = set()
    sid_counter_dns = 1000
    sid_counter_http = 2000
    def process_packet(packet):
        global sid_counter_dns, sid_counter_http
        if DNS in packet and packet[DNS].qr == 0:
            domain = packet[DNS].qd.qname.decode("utf-8")[:-1]
            if check_domain(domain) == True:
                rule = f'alert dns any any -> any 53 (msg:"Detected malicious domain {domain}"; dns; content:"{domain}"; classtype:bad-activity; sid:{sid_counter_dns}; rev:1;)'
                suricata_rules.add(rule)
                sid_counter_dns += 1
                print(sid_counter_dns)
        if HTTPRequest in packet:
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            host = packet[HTTPRequest].Host.decode("utf-8")
            if check_domain(host):
                rule = f'alert http any any -> {dst_ip} {dst_port} (msg:"HTTP Request to strange site host <<{host}>>"; sid:{sid_counter_http}; rev:1;)'
                suricata_rules.add(rule)
                sid_counter_http += 1
                print(sid_counter_http)
    def check_domain(domain):
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "x-apikey": API_KEY,
        }

        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                data = result.get("data", {})
                attributes = data.get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                malicious = last_analysis_stats.get("malicious", 0)
            
            # Проверяем, если есть антивирусы, которые отметили домен как вредоносный
                if malicious > 0:
                    return True
        except requests.RequestException as e:
            print(f"Ошибка при запросе к VirusTotal API: {e}")
    
        return False

    dir_path = input("Введите путь к директории с файлами pcap: ")

    if not os.path.isdir(dir_path):
        print("Указанной директории не существует.")
    else:
        files = os.listdir(dir_path)
        for file_name in files:
            file_path = os.path.join(dir_path, file_name)
            if file_name.endswith(".pcap"):
                packets = rdpcap(file_path)
                for packet in packets:
                    process_packet(packet)

        for rule in suricata_rules:
            print(rule)
        if not suricata_rules:
            print("Нет правил для записи в файл")   
        else:
            dir2_path = input("Введите путь к директории для сохранения файла suricata_rules.txt: ") 
 
        if not os.path.isdir(dir2_path): 
            print("Указанной директории не существует.") 
        else: 
            rules_file_path = os.path.join(dir_path, "suricata_rules.txt") 
     
            with open(rules_file_path, "w") as file: 
                for rule in suricata_rules: 
                    file.write(rule + "\n") 
     
            print(f"Файл suricata_rules.txt сохранен в директории {dir2_path}")
    
else:
    print("Нет подключения к интернету. Проверьте ваше соединение и попробуйте снова.")

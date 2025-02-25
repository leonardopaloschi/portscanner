import sys
import socket
import multiprocessing
import json
import subprocess
import re

def load_well_known_ports():
    try:
        with open("wkports.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print("Arquivo wkports.json não encontrado.")
        sys.exit(1)
    except json.JSONDecodeError:
        print("Erro ao decodificar o arquivo wkports.json.")
        sys.exit(1)

WELL_KNOWN_PORTS = load_well_known_ports()

def port_scan(host, porta):
    s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    if s.connect_ex((host, porta)) == 0:
        service = "Desconhecido"
        for item in WELL_KNOWN_PORTS:
            if item["port"] == porta and item["protocol"] == "tcp":
                service = item["name"]
                break
        print(f"Porta {porta} [TCP] aberta - Serviço: {service}")
    s.close()

def udp_scan(host, porta):
    s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    try:
        s.sendto(b"\x00", (host, porta))
        s.recvfrom(1024)
    except socket.timeout:
        service = "Desconhecido"
        for item in WELL_KNOWN_PORTS:
            if item["port"] == porta and item["protocol"] == "udp":
                service = item["name"]
                break
        print(f"Porta {porta} [UDP] possivelmente aberta - Serviço: {service}")
    except Exception:
        pass
    s.close()

def multi_process(host, porta, scan_func, processes):
    p = multiprocessing.Process(target=scan_func, args=(host, porta))
    p.start()
    processes.append(p)

def full_scan(host, scan_func):
    print(f"Iniciando varredura completa no host {host}...")
    processes = []
    for porta in range(1, 65536):
        multi_process(host, porta, scan_func, processes)
    for p in processes:
        p.join()

def range_scan(host, start_port, end_port, scan_func):
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Range de portas inválido. As portas devem estar entre 1 e 65535.")
        return
    print(f"Iniciando varredura no host {host} para as portas {start_port}-{end_port}...")
    processes = []
    for porta in range(start_port, end_port + 1):
        multi_process(host, porta, scan_func, processes)
    for p in processes:
        p.join()

def find_connected_devices():
    print("Procurando dispositivos na rede...")
    try:
        result = subprocess.check_output(["arp", "-a"], universal_newlines=True)
        ips = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}", result)
        return list(set(ips))
    except subprocess.CalledProcessError:
        print("Erro ao buscar dispositivos na rede.")
        return []

def main():
    while True:
        print("\n--- Port Scanner ---")
        print("1. Escanear portas TCP")
        print("2. Escanear portas UDP")
        print("3. Encontrar dispositivos conectados à rede Wi-Fi")
        print("4. Sair")
        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            protocolo = "TCP"
            scan_func = port_scan
        elif opcao == "2":
            protocolo = "UDP"
            scan_func = udp_scan
        elif opcao == "3":
            devices = find_connected_devices()
            if not devices:
                print("Nenhum dispositivo encontrado.")
                continue
            print("Dispositivos encontrados:")
            for device in devices:
                print(device)
            continue
        elif opcao == "4":
            print("Saindo...")
            sys.exit(0)
        else:
            print("Opção inválida. Tente novamente.")
            continue

        host = input("Digite o endereço IP ou domínio: ")
        try:
            family = socket.AF_INET6 if ':' in host else socket.AF_INET
            host_ip = socket.getaddrinfo(host, None, family)[0][4][0]
            portas = input(f"Digite a porta ou um range para escaneamento {protocolo} (ex: 80 ou 20-25),'all' para todas ou 'wk' para portas conhecidas(Well-Known): ")
            processes = []
            if portas == "all":
                full_scan(host_ip, scan_func)
            elif "-" in portas:
                start_port, end_port = map(int, portas.split("-"))
                range_scan(host_ip, start_port, end_port, scan_func)
            elif portas == "wk":
                for item in WELL_KNOWN_PORTS:
                    multi_process(host_ip, item["port"], scan_func, processes)
                for p in processes:
                    p.join()
            else:
                porta = int(portas)
                scan_func(host_ip, porta)
        except ValueError:
            print("Entrada inválida. Digite um número ou um intervalo válido.")
        except socket.gaierror:
            print("Host inválido, tente novamente.")

if __name__ == "__main__":
    main()

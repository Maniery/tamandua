#!/usr/-bin/env python3
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP

# --- Funções de Verificação de Checksum ---

def verificar_checksum_udp(packet):
    if IP not in packet or UDP not in packet:
        return None
    ip_layer = packet[IP]
    udp_layer = packet[UDP]
    tmp_pkt = IP(src=ip_layer.src, dst=ip_layer.dst) / UDP(
        sport=udp_layer.sport,
        dport=udp_layer.dport,
        len=udp_layer.len
    ) / bytes(udp_layer.payload)
    checksum_calculado = tmp_pkt[UDP].chksum
    checksum_original = udp_layer.chksum
    if checksum_original is None:
        return None
    return checksum_calculado == checksum_original


def verificar_checksum_tcp(packet):
    if IP not in packet or TCP not in packet:
        return None
    ip_layer = packet[IP]
    tcp_layer = packet[TCP]
    tmp_pkt = IP(src=ip_layer.src, dst=ip_layer.dst) / TCP(
        sport=tcp_layer.sport,
        dport=tcp_layer.dport,
        seq=tcp_layer.seq,
        ack=tcp_layer.ack,
        flags=tcp_layer.flags,
        window=tcp_layer.window
    ) / bytes(tcp_layer.payload)
    checksum_calculado = tmp_pkt[TCP].chksum
    checksum_original = tcp_layer.chksum
    if checksum_original is None:
        return None
    return checksum_calculado == checksum_original

# --- Funções de Impressão Formatada ---

def imprimir_pacote_udp(packet):
    udp = packet[UDP]
    resultado_checksum = verificar_checksum_udp(packet)
    if resultado_checksum is True:
        status_checksum = "OK"
    elif resultado_checksum is False:
        status_checksum = "ERRO"
    else:
        status_checksum = "N/A"
    checksum_str = f"0x{udp.chksum:04x}" if udp.chksum is not None else "None"

    print("\nPACOTE UDP")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"| Porta origem: {udp.sport:<5} | Porta destino: {udp.dport:<5} |")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"| Tamanho: {udp.len:<10} | Checksum: {checksum_str} ({status_checksum}) |")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")


def imprimir_pacote_tcp(packet):
    tcp = packet[TCP]
    resultado_checksum = verificar_checksum_tcp(packet)
    if resultado_checksum is True:
        status_checksum = "OK"
    elif resultado_checksum is False:
        status_checksum = "ERRO"
    else:
        status_checksum = "N/A"
    checksum_str = f"0x{tcp.chksum:04x}" if tcp.chksum is not None else "None"
    offset = tcp.dataofs
    flags_str = str(tcp.flags)
    def flag(letra):
        return letra if letra in flags_str else " "
    c, e, u, a, p, r, s, f = flag("C"), flag("E"), flag("U"), flag("A"), flag("P"), flag("R"), flag("S"), flag("F")

    print("\nPACOTE TCP")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"| Porta origem: {tcp.sport:<5} | Porta destino: {tcp.dport:<5} |")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"| Número sequência: {tcp.seq:<10} |")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"| Número de ACK: {tcp.ack:<10} |")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"| Offset: {offset:<3} |{c}|{e}|{u}|{a}|{p}|{r}|{s}|{f}| Janela: {tcp.window:<6} |")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"| Checksum: {checksum_str} ({status_checksum}) |")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")

# --- Função Principal  ---

def main():
    print("Iniciando a captura de pacotes. Aperte Ctrl+C para interromper.\n")
    
    try:
        # 1. Capturando pacotes (guarda todos na lista 'packets')
        packets = scapy.sniff()

    except KeyboardInterrupt:
        print("\nCaptura interrompida.")
        # Se o usuário apertar Ctrl+C antes de capturar algo, saímos
        if 'packets' not in locals():
            print("Nenhum pacote foi capturado.")
            return
    except Exception as e:
        print(f"Ocorreu um erro: {e}")
        print("Verifique se você executou o script com 'sudo'.")
        return

    qtd_udp = 0
    qtd_tcp = 0

    print("\n--- Análise dos Pacotes Capturados ---")

    # 2. Looping em todos os pacotes capturados (APÓS a captura)
    for packet in packets:
        
        # Verificando um cabeçalho UDP
        if packet.haslayer(UDP) and packet.haslayer(IP):
            imprimir_pacote_udp(packet)
            qtd_udp += 1
        
        # Verificando um cabeçalho TCP
        if packet.haslayer(TCP) and packet.haslayer(IP):
            imprimir_pacote_tcp(packet)
            qtd_tcp += 1

    # 3. Imprimindo as estatísticas
    print("\n" + "=" * 34)
    print("  Estatísticas de Pacotes Analisados")
    print("=" * 34)
    print(f"  Total de cabeçalhos UDP: {qtd_udp}")
    print(f"  Total de cabeçalhos TCP: {qtd_tcp}")
    print("=" * 34)
    print("Fim da execução.")


if __name__ == "__main__":
    main()

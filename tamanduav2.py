#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP

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

    print("PACOTE UDP")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"| Porta origem: {udp.sport:<5} | Porta destino: {udp.dport:<5} |")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print(f"| Tamanho: {udp.len:<10} | Checksum: {checksum_str} ({status_checksum}) |")
    print("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
    print()


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

    c = flag("C")
    e = flag("E")
    u = flag("U")
    a = flag("A")
    p = flag("P")
    r = flag("R")
    s = flag("S")
    f = flag("F")

    print("PACOTE TCP")
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
    print()


def main():
    print("Iniciando a captura de pacotes. Aperte Ctrl+C para interromper.\n")
    packets = scapy.sniff()

    qtd_udp = 0
    qtd_tcp = 0

    for packet in packets:
        if packet.haslayer(UDP):
            imprimir_pacote_udp(packet)
            qtd_udp += 1

        if packet.haslayer(TCP):
            imprimir_pacote_tcp(packet)
            qtd_tcp += 1

    print("========== ESTATÍSTICAS ==========")
    print(f"Total de cabeçalhos UDP analisados: {qtd_udp}")
    print(f"Total de cabeçalhos TCP analisados: {qtd_tcp}")
    print("==================================")


if __name__ == "__main__":
    main()

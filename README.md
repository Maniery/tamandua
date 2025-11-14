# Analisador de Pacotes TCP/UDP

Este script em Python foi desenvolvido para a disciplina DCT2102 - Redes de Computadores.

O programa utiliza a biblioteca Scapy para capturar pacotes de rede em tempo real. Ele filtra pacotes TCP e UDP, exibe uma visualização formatada de seus cabeçalhos e verifica a integridade do checksum de cada pacote. 
Ao final, exibe uma estatística com o total de pacotes de cada tipo que foram analisados.

## Autores

* (Laety Maniery)
* (Erick Bezerra)

## ⚙️ Requisitos

* Python 3
* `python3-scapy` (ou a biblioteca Scapy via `pip`)
* `dnsutils` (necessário para o comando `nslookup` usado na etapa de teste)

## 🚀 Como Executar

O script precisa de privilégios de administrador (`sudo`) para acessar o *socket* de rede no modo de captura.

**1. Clone ou baixe os arquivos**
   Coloque o script `tamandua.py` em um diretório de sua escolha.

**2. Instale as dependências (ambiente Debian/Ubuntu)**
   Abra seu terminal e execute:
   ```bash
   sudo apt update
   sudo apt install python3-scapy dnsutils

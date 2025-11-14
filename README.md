# Analisador de Pacotes TCP/UDP (tamandua.py)

Este script em Python foi desenvolvido como atividade para a disciplina DCT2102 - Redes de Computadores (BSI - CERES/UFRN).

O programa utiliza a biblioteca Scapy para capturar pacotes de rede em tempo real. Ele é capaz de filtrar, analisar e exibir os cabeçalhos de pacotes TCP e UDP de forma formatada, conforme especificado nos requisitos da atividade.

Uma funcionalidade central é a verificação da integridade do **Checksum** de cada pacote, indicando "OK" ou "ERRO" ao lado do valor. Ao final da execução (após ser interrompido com `Ctrl+C`), o script exibe uma estatística com o total de pacotes de cada tipo que foram analisados.

## 🧑 Autores

* (Laety Batista)
* (Erick Bezerra)

## ⚙️ Requisitos

* **Ambiente:** WSL (Debian/Ubuntu)
* **Python 3**
* **Bibliotecas Python:** `python3-scapy`
* **Ferramentas de Rede (para teste):** `dnsutils` (para o comando `nslookup`) e `curl` (para gerar tráfego web)

## 🚀 Passo a Passo: Instalação e Execução

Este guia cobre todo o processo, desde a instalação das dependências até a execução do teste de captura no ambiente WSL.

### 1. Instalação das Dependências

Abra seu terminal WSL (Debian) e execute o comando abaixo para garantir que todas as ferramentas necessárias (Scapy, `nslookup` e `curl`) estejam instaladas:

```bash
sudo apt update && sudo apt install python3-scapy dnsutils curl

### Terminal 1 – Parte de Cima
![Terminal 1 Cima](https://github.com/Maniery/tamandua/blob/main/terminal1cima.png?raw=true)

### Terminal 1 – Parte de Baixo
![Terminal 1 Baixo](<img width="958" height="601" alt="image" src="https://github.com/user-attachments/assets/22510854-368e-43f2-b765-6bc96467a153" />
)

### Terminal 2 – Parte de Cima
![Terminal 2 Cima](https://github.com/Maniery/tamandua/blob/main/terminal2cima.jpg?raw=true)

### Terminal 2 – Parte de Baixo
![Terminal 2 Baixo](https://github.com/Maniery/tamandua/blob/main/terminal2baixo.jpg?raw=true)

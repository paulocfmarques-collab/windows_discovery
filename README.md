# Network Discovery Inventory

Ferramenta para descoberta, inventário e enriquecimento de dispositivos em redes locais utilizando **ARP Scan**, **Nmap** e **DNS Reverse Lookup**.

O projeto cria e mantém automaticamente um inventário de dispositivos conectados à rede, armazenando informações como endereço MAC, IP, fabricante, hostname, sistema operacional e datas de detecção.

---

## 🚀 Funcionalidades

✅ Descoberta rápida utilizando arp-scan

✅ Descoberta complementar utilizando Nmap

✅ Inventário persistente em JSON

✅ Histórico de dispositivos encontrados

✅ Descoberta de hostname via DNS reverso

✅ Identificação de fabricante (Vendor)

✅ Detecção de sistema operacional

✅ Processamento paralelo com ThreadPoolExecutor

✅ Atualização incremental do inventário

✅ Registro de primeira e última detecção

---

## 🏗 Arquitetura

```text
                ┌─────────────┐
                │ arp-scan    │
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │ merge       │
                │ devices     │
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │ inventory   │
                │ update      │
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │ nmap -O     │
                │ DNS Lookup  │
                └──────┬──────┘
                       │
                       ▼
                inventory.json
```

---

## 🛠 Tecnologias Utilizadas

- Python 3
- Nmap
- arp-scan
- DNS Reverse Lookup
- JSON
- ThreadPoolExecutor

---

## 📋 Pré-Requisitos

### Linux

O projeto foi desenvolvido e testado em Linux e Windows.

### Dependências do Sistema

Debian / Ubuntu / Raspberry Pi OS:

```bash
sudo apt update

sudo apt install -y \
    python3 \
    python3-pip \
    nmap \
    arp-scan
```

Verificar instalação:

```bash
nmap --version
arp-scan --version
python3 --version
```

---

## 📦 Instalação

Clone o repositório:

```bash
git clone https://github.com/seu_usuario/network-discovery-inventory.git

cd network-discovery-inventory
```

Instale dependências Python:

```bash
pip3 install -r requirements.txt
```

---

## ⚙ Configuração

Crie um arquivo:

```json
{
  "windows": {
    "network": "192.168.1.0/24"
  }
}
```

Salve como:

```text
config.json
```

---

## ▶️ Execução

Modo normal:

```bash
python3 discovery_windows.py
```

Modo verbose:

```bash
python3 discovery_windows.py -v
```

---

## 📂 Arquivos Gerados

### inventory.json

Contém o inventário consolidado da rede.

Exemplo:

```json
{
  "AA:BB:CC:DD:EE:FF": {
    "first_seen": "2026-08-19 08:00:00",
    "last_seen": "2026-08-19 09:00:00",
    "ip": "192.168.1.10",
    "vendor": "Raspberry Pi",
    "hostname": "raspberry.local",
    "device_type": "general purpose",
    "os": "Linux"
  }
}
```

### inventory.log

Arquivo de log de execução da ferramenta.

---

## 🎯 Casos de Uso

- Inventário automático de rede
- Monitoramento residencial
- Laboratórios de ensino
- Raspberry Pi
- Homelab
- Pequenas empresas
- Auditoria de dispositivos

---

## 📈 Roadmap

- [ ] Exportação para PostgreSQL
- [ ] Dashboard Grafana
- [ ] Integração Prometheus
- [ ] API REST
- [ ] Alertas Telegram
- [ ] Histórico completo de mudanças

---

## 👨‍💻 Autor

**Paulo César Furlanetto Marques**

---


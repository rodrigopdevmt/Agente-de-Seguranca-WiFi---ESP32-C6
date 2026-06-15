# &#128737; Agente de Seguranca WiFi - ESP32-C6

Agente de monitoramento e seguranca WiFi para ESP32-C6 com dashboard web em tempo real, deteccao de ataques (deauth/disassoc), portal cativo para configuracao e relatorios detalhados.

---

## &#127968; Funcionalidades

- **Monitoramento em tempo real** de quadros management WiFi (deauth, disassoc)
- **Dashboard web moderno** com tema dark glassmorphism e animacoes
- **Menu drawer** (gaveta de navegacao) com acesso rapido a todas as paginas
- **Portal cativo** para configuracao inicial do WiFi
- **Scan automatico** de redes WiFi disponiveis
- **Modal de senha** ao selecionar rede no portal cativo
- **Relatorios de ataques** com historico de MACs, tipos e quantidades
- **LED NeoPixel** indicando status (azul=boot, verde=conectado, vermelho=ataque, ciano=AP)
- **Modo APSTA** - AP ativo mesmo apos conectar na rede WiFi
- **Gravacao de credenciais** na NVS (sobrevive a reset)
- **Botao BOOT** para limpar configuracao e entrar em modo AP
- **Interface 100% em portugues**

---

## &#128295; Hardware Necessario

| Componente | Descricao |
|------------|-----------|
| ESP32-C6-DevKitC-1 | Placa com ESP32-C6-WROOM-1 |
| LED NeoPixel | WS2812B (conectado ao GPIO 8) |
| USB-C | Para programacao e alimentacao |

---

## &#128640; Instalacao Passo a Passo

### 1. Preparar o Ambiente

#### Instalar PlatformIO

```bash
# Instalar PlatformIO via pip
pip install platformio

# Ou usar VS Code com extensao PlatformIO
# Busque por "PlatformIO IDE" no marketplace
```

#### Instalar ESP-IDF (via PlatformIO)

```bash
# O PlatformIO baixa automaticamente o framework ESP-IDF
# Apenas verifique se esta instalado:
pio pkg list
```

### 2. Clonar o Repositorio

```bash
git clone https://github.com/rodrigopdevmt/Agente-de-Seguranca-WiFi---ESP32-C6.git
cd Agente-de-Seguranca-WiFi---ESP32-C6
```

### 3. Configurar a Placa

O projeto ja vem configurado para `esp32-c6-devkitc-1`. Verifique o `platformio.ini`:

```ini
[env:esp32-c6-devkitc-1]
platform = espressif32
board = esp32-c6-devkitc-1
framework = espidf
monitor_speed = 115200
board_build.flash_size = 4MB
board_build.partitions = default_4MB.csv
```

### 4. Compilar o Firmware

```bash
pio run
```

Aguarde a compilacao. O firmware sera gerado em `.pio/build/esp32-c6-devkitc-1/firmware.bin`.

### 5. Conectar o ESP32-C6

1. Conecte o ESP32-C6 ao computador via USB-C
2. Identifique a porta serial:

```bash
# Linux
ls /dev/ttyACM*
# Geralmente /dev/ttyACM0 ou /dev/ttyACM1

# macOS
ls /dev/cu.usbmodem*

# Windows
# Verifique o Gerenciador de Dispositivos (COMx)
```

### 6. Permissoes da Serial (Linux)

```bash
# Adicione seu usuario ao grupo dialout
sudo usermod -a -G dialout $USER

# Ou permissao temporaria
sudo chmod 666 /dev/ttyACM0
```

> **Nota:** Apos trocar de porta USB, pode ser necessario reaplicar as permissoes.

### 7. Gravar o Firmware

```bash
pio run -t upload
```

### 8. Monitor Serial

```bash
pio device monitor
```

Ou combinar upload + monitor:

```bash
pio run -t upload && pio device monitor
```

---

## &#128246; Uso

### Primeira Vez (Modo AP)

1. Liga o ESP32-C6
2. O LED fica **ciano** (modo AP)
3. No celular/computador, conecte-se a rede **ESP32-Security**
4. Abra o navegador - o portal cativo aparece automaticamente
5. Selecione sua rede WiFi
6. Digite a senha
7. O ESP32 conecta e o LED fica **verde**

### Dashboard

Apos conectar na rede WiFi:

1. Descubra o IP do ESP32 no monitor serial ou roteador
2. Acesse `http://<IP_DO_ESP32>/` no navegador
3. Use o **menu hamburger** (&#9776;) para navegar

### Paginas Disponiveis

| URL | Descricao |
|-----|-----------|
| `/` | Dashboard principal com metricas em tempo real |
| `/relatorio` | Historico detalhado de ataques |
| `/data` | JSON com dados atuais (API) |
| `/ataques` | JSON com log de ataques (API) |
| `/scan` | Lista de redes WiFi disponiveis (API) |
| `/reset_wifi` | Limpa configuracao e reinicia em modo AP |
| `/connect?ssid=REDE` | Pagina para digitar senha da rede |

### Indicacoes do LED

| Cor | Status |
|-----|--------|
| &#128308; Vermelho | Modo AP / Ataque detectado |
| &#128994; Verde | Conectado e operacional |
| &#128309; Azul | Boot / Inicializacao |
| &#128992; Laranja | Trafego intenso (100+ quadros) |
| &#128311; Ciano | Portal cativo ativo |

### Botao BOOT

Mantenha o botao **BOOT** pressionado por **3 segundos** para:
- Limpar credenciais WiFi salvas
- Reiniciar em modo AP

---

## &#128187; Desenvolvimento

### Estrutura do Projeto

```
esp32-seguranca-wifi/
├── platformio.ini              # Configuracao PlatformIO
├── src/
│   ├── main.cpp                # Codigo principal (~1200 linhas)
│   ├── led_strip_encoder.cpp   # Driver NeoPixel via RMT
│   └── led_strip_encoder.h     # Header do driver LED
├── server.py                   # Bridge serial-HTTP (opcional)
├── README.md                   # Esta documentacao
├── LICENSE                     # Licenca Apache 2.0
└── CONTRIBUTING.md             # Guia de contribuicao
```

### Endpoints HTTP

| Metodo | Endpoint | Descricao |
|--------|----------|-----------|
| GET | `/` | Dashboard HTML |
| GET | `/status` | Status JSON (report) |
| GET | `/data` | Dados JSON (alias de /status) |
| GET | `/relatorio` | Pagina de relatorios |
| GET | `/ataques` | Log de ataques JSON |
| GET | `/scan` | Scan de redes JSON |
| GET | `/reset_wifi` | Limpar NVS e reiniciar |
| GET | `/connect?ssid=X` | Pagina de senha |
| POST | `/configure` | Salvar credenciais |

### JSON do Dashboard (`/data`)

```json
{
  "t": "report",
  "mgmt": 150,
  "deauth": 5,
  "disassoc": 2,
  "attackers": 3,
  "wifi": "on",
  "ip": "192.168.1.19",
  "channel": 6
}
```

### JSON de Ataques (`/ataques`)

```json
{
  "total_mgm": 150,
  "total_deauth": 5,
  "total_disassoc": 2,
  "attackers": 3,
  "channel": 6,
  "log": [
    {
      "mac": "AA:BB:CC:DD:EE:FF",
      "type": "deauth",
      "count": 12,
      "channel": 6
    }
  ]
}
```

---

## &#128736; Personalizacao

### Trocar Nome da Rede AP

Em `main.cpp`, busque:

```cpp
#define AP_SSID "ESP32-Security"
```

### Trocar Cor do LED

Em `main.cpp`, as funcoes LED usam RGB:

```cpp
led_set_rgb(0, 255, 0);    // Verde
led_set_rgb(255, 0, 0);    // Vermelho
led_set_rgb(0, 0, 255);    // Azul
led_set_rgb(0, 255, 255);  // Ciano
```

### Ajustar Threshold de Ataque

```cpp
#define DEAUTH_THRESHOLD 3
#define DISASSOC_THRESHOLD 5
```

---

## &#128196; Licenca

Este projeto esta licenciado sob a licenca Apache 2.0. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

## &#129309; Contribuicao

Consulte [CONTRIBUTING.md](CONTRIBUTING.md) para o guia de contribuicao.

---

## &#128241; Autor

**Rodrigo Dev MT** - (66) 99618-4323

---

## &#128279; Links Uteis

- [ESP-IDF Documentacao](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c6/)
- [PlatformIO Documentacao](https://docs.platformio.org/)
- [ESP32-C6 Datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-c6_datasheet_en.pdf)

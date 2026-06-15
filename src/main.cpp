#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "esp_http_server.h"
#include "driver/rmt_tx.h"
#include "driver/gpio.h"
#include "led_strip_encoder.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "esp_system.h"

#define LED_PIN                    8
#define RMT_RESOLUTION_HZ          10000000
#define MAX_ATTACKERS              30
#define CHECK_INTERVAL_MS          2000
#define DEAUTH_THRESHOLD           5
#define DISASSOC_THRESHOLD         8
#define AP_SSID                    "ESP32-Security"
#define AP_MAX_CONN                4
#define STA_TIMEOUT_MS             15000
#define WIFI_NAMESPACE             "wifi_cfg"
#define WIFI_SSID_KEY              "ssid"
#define WIFI_PASS_KEY              "pass"

static const char *TAG = "AGENTE";

// --- ATTACKER DATABASE ---
typedef struct {
    uint8_t mac[6];
    int attackCount;
    uint32_t firstSeen;
    uint32_t lastSeen;
    uint16_t lastReasonCode;
    int channel;
} AttackerInfo;

static AttackerInfo s_attackers[MAX_ATTACKERS];
static int s_attackerCount = 0;

static volatile int s_deauthCount = 0;
static volatile int s_disassocCount = 0;
static volatile int s_totalMgmtCount = 0;
static volatile uint8_t s_lastMAC[6] = {0};
static volatile uint16_t s_lastReason = 0;
static volatile int s_lastChannel = 0;

// --- LED ---
static rmt_channel_handle_t s_led_chan = NULL;
static rmt_encoder_handle_t s_led_encoder = NULL;
static uint8_t s_led_pixels[3];

static SemaphoreHandle_t s_connected = NULL;
static bool s_wifi_online = false;
static httpd_handle_t s_server = NULL;
static bool s_ap_mode = false;
static TaskHandle_t s_dns_task = NULL;
static char s_ip_str[16] = "0.0.0.0";
static char s_report_json[512];
static SemaphoreHandle_t s_report_mutex = NULL;

#define MAX_LOG 20
struct AttackLog { char mac[18]; char type[10]; int count; int channel; uint32_t time; };
static AttackLog s_attack_log[MAX_LOG];
static int s_attack_log_count = 0;

// =========================================================
//  LED
// =========================================================
static void led_set_rgb(uint8_t r, uint8_t g, uint8_t b) {
    s_led_pixels[0] = g;
    s_led_pixels[1] = r;
    s_led_pixels[2] = b;
    rmt_transmit_config_t tx = {};
    tx.loop_count = 0;
    tx.flags.eot_level = 0;
    rmt_transmit(s_led_chan, s_led_encoder, s_led_pixels, 3, &tx);
    rmt_tx_wait_all_done(s_led_chan, portMAX_DELAY);
}

static void led_blink(uint8_t r, uint8_t g, uint8_t b, int ms, int n) {
    for (int i = 0; i < n; i++) {
        led_set_rgb(r, g, b);
        vTaskDelay(pdMS_TO_TICKS(ms));
        led_set_rgb(0, 0, 0);
        vTaskDelay(pdMS_TO_TICKS(ms));
    }
}

static void led_init(void) {
    rmt_tx_channel_config_t cfg = {};
    cfg.clk_src = RMT_CLK_SRC_DEFAULT;
    cfg.gpio_num = (gpio_num_t)LED_PIN;
    cfg.mem_block_symbols = 64;
    cfg.resolution_hz = RMT_RESOLUTION_HZ;
    cfg.trans_queue_depth = 4;
    ESP_ERROR_CHECK(rmt_new_tx_channel(&cfg, &s_led_chan));

    led_strip_encoder_config_t enc = { .resolution = RMT_RESOLUTION_HZ };
    ESP_ERROR_CHECK(rmt_new_led_strip_encoder(&enc, &s_led_encoder));

    ESP_ERROR_CHECK(rmt_enable(s_led_chan));
    led_set_rgb(0, 0, 0);
}

// =========================================================
//  NVS
// =========================================================
static void save_wifi_creds(const char *ssid, const char *pass) {
    nvs_handle_t h;
    if (nvs_open(WIFI_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, WIFI_SSID_KEY, ssid);
        nvs_set_str(h, WIFI_PASS_KEY, pass);
        nvs_commit(h);
        nvs_close(h);
        ESP_LOGI(TAG, "Credenciais salvas na NVS");
    }
}

static bool load_wifi_creds(char *ssid, size_t ssid_len, char *pass, size_t pass_len) {
    nvs_handle_t h;
    if (nvs_open(WIFI_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return false;
    bool ok = nvs_get_str(h, WIFI_SSID_KEY, ssid, &ssid_len) == ESP_OK &&
              nvs_get_str(h, WIFI_PASS_KEY, pass, &pass_len) == ESP_OK;
    nvs_close(h);
    return ok;
}

// =========================================================
//  JSON OUTPUT
// =========================================================
static void print_mac_json(const char *key, const uint8_t *mac) {
    printf("\"%s\":\"", key);
    for (int i = 0; i < 6; i++) printf("%02X%s", mac[i], i < 5 ? ":" : "");
    printf("\"");
}

static void emit_report(int mgmt, int deauth, int disassoc) {
    uint8_t primary;
    wifi_second_chan_t second;
    esp_wifi_get_channel(&primary, &second);
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "{\"t\":\"report\",\"mgmt\":%d,\"deauth\":%d,\"disassoc\":%d,\"attackers\":%d,\"wifi\":\"%s\",\"ip\":\"%s\",\"channel\":%d}\n",
        mgmt, deauth, disassoc, s_attackerCount,
        s_wifi_online ? "on" : "off", s_ip_str, primary);
    if (n > 0) {
        printf("%s", buf);
        if (s_report_mutex) {
            xSemaphoreTake(s_report_mutex, portMAX_DELAY);
            strncpy(s_report_json, buf, sizeof(s_report_json) - 1);
            s_report_json[sizeof(s_report_json) - 1] = 0;
            xSemaphoreGive(s_report_mutex);
        }
    }
}

static void emit_attack(const uint8_t *mac, uint16_t reason, int channel, int count) {
    printf("{\"t\":\"attack\"");
    print_mac_json("mac", mac);
    printf(",\"reason\":%u,\"channel\":%d,\"count\":%d", reason, channel, count);
    printf("}\n");
}

static void emit_attacker_list(void) {
    printf("{\"t\":\"attackers\",\"list\":[");
    uint32_t now = xTaskGetTickCount() * portTICK_PERIOD_MS;
    for (int i = 0; i < s_attackerCount; i++) {
        if (i > 0) printf(",");
        printf("{\"idx\":%d", i + 1);
        print_mac_json("mac", s_attackers[i].mac);
        printf(",\"count\":%d,\"channel\":%d", s_attackers[i].attackCount, s_attackers[i].channel);
        printf(",\"reason\":%u", s_attackers[i].lastReasonCode);
        printf(",\"age\":%lu", (now - s_attackers[i].lastSeen) / 1000);
        printf("}");
    }
    printf("]}\n");
}

// =========================================================
//  PROMISCUOUS CALLBACK
// =========================================================
static void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    wifi_promiscuous_pkt_t *pkt_rw = (wifi_promiscuous_pkt_t *)buf;

    reinterpret_cast<volatile int&>(s_totalMgmtCount) = s_totalMgmtCount + 1;

    uint8_t fc = payload[0];
    uint8_t ftype = (fc >> 2) & 0x03;
    uint8_t fsub  = (fc >> 4) & 0x0F;

    if (ftype != 0 || (fsub != 12 && fsub != 10)) return;

    uint8_t *ta = (uint8_t *)(payload + 10);
    uint16_t reason = payload[24] | (payload[25] << 8);

    memcpy((void *)s_lastMAC, ta, 6);
    reinterpret_cast<volatile uint16_t&>(s_lastReason) = reason;
    reinterpret_cast<volatile int&>(s_lastChannel) = pkt_rw->rx_ctrl.channel;

    if (fsub == 12) reinterpret_cast<volatile int&>(s_deauthCount) = s_deauthCount + 1;
    else reinterpret_cast<volatile int&>(s_disassocCount) = s_disassocCount + 1;

    for (int i = 0; i < s_attackerCount && i < MAX_ATTACKERS; i++) {
        if (memcmp(s_attackers[i].mac, ta, 6) == 0) {
            s_attackers[i].attackCount++;
            s_attackers[i].lastSeen = xTaskGetTickCount() * portTICK_PERIOD_MS;
            s_attackers[i].lastReasonCode = reason;
            s_attackers[i].channel = s_lastChannel;
            return;
        }
    }
    if (s_attackerCount < MAX_ATTACKERS) {
        int idx = s_attackerCount++;
        memcpy(s_attackers[idx].mac, ta, 6);
        s_attackers[idx].attackCount = 1;
        s_attackers[idx].firstSeen = xTaskGetTickCount() * portTICK_PERIOD_MS;
        s_attackers[idx].lastSeen = s_attackers[idx].firstSeen;
        s_attackers[idx].lastReasonCode = reason;
        s_attackers[idx].channel = s_lastChannel;
    }
}

// =========================================================
//  MONITORING TASK
// =========================================================
static void monitor_task(void *pv) {
    uint32_t last = 0;
    for (;;) {
        uint32_t now = xTaskGetTickCount() * portTICK_PERIOD_MS;
        if (now - last < CHECK_INTERVAL_MS) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        last = now;

        int d = s_deauthCount;
        int dis = s_disassocCount;
        int mgmt = s_totalMgmtCount;

        emit_report(mgmt, d, dis);

        if (d >= DEAUTH_THRESHOLD || dis >= DISASSOC_THRESHOLD) {
            emit_attack((const uint8_t *)s_lastMAC, s_lastReason, s_lastChannel, d + dis);
            emit_attacker_list();
            if (s_attack_log_count < MAX_LOG) {
                AttackLog &log = s_attack_log[s_attack_log_count++];
                snprintf(log.mac, sizeof(log.mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                    s_lastMAC[0], s_lastMAC[1], s_lastMAC[2], s_lastMAC[3], s_lastMAC[4], s_lastMAC[5]);
                strncpy(log.type, d > 0 ? "deauth" : "disassoc", sizeof(log.type));
                log.count = d + dis;
                log.channel = s_lastChannel;
                log.time = now;
            }
            led_blink(255, 0, 0, 80, 8);
            if (s_wifi_online) esp_wifi_connect();
            led_set_rgb(255, 0, 0);
        } else if (mgmt > 100) {
            led_set_rgb(255, 165, 0);
        } else if (d > 0 || dis > 0) {
            led_set_rgb(255, 255, 0);
        } else {
            led_set_rgb(0, 255, 0);
        }

        s_deauthCount = 0;
        s_disassocCount = 0;
        s_totalMgmtCount = 0;
    }
}

// =========================================================
//  DNS SERVER (captive portal)
// =========================================================
static void dns_server_task(void *pv) {
    struct sockaddr_in dest;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "DNS socket error");
        vTaskDelete(NULL);
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "DNS bind error");
        close(sock);
        vTaskDelete(NULL);
    }

    ESP_LOGI(TAG, "DNS server rodando na porta 53");

    uint8_t buf[256];
    while (1) {
        socklen_t len = sizeof(dest);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&dest, &len);
        if (n < 12) continue;

        if ((buf[2] & 0x80) != 0) continue;

        buf[2] |= 0x80;
        buf[3] |= 0x84;

        int qcount = (buf[4] << 8) | buf[5];
        buf[6] = 0;
        buf[7] = 1;

        int pos = 12;
        for (int i = 0; i < qcount; i++) {
            while (pos < n && buf[pos] != 0) {
                pos += buf[pos] + 1;
            }
            pos += 5;
        }

        if (pos + 16 > n) {
            buf[7] = 0;
            sendto(sock, buf, n, 0, (struct sockaddr *)&dest, sizeof(dest));
            continue;
        }

        buf[pos++] = 0xC0;
        buf[pos++] = 0x0C;
        buf[pos++] = 0x00;
        buf[pos++] = 0x01;
        buf[pos++] = 0x00;
        buf[pos++] = 0x01;
        buf[pos++] = 0x00;
        buf[pos++] = 0x00;
        buf[pos++] = 0x00;
        buf[pos++] = 0x3C;
        buf[pos++] = 0x00;
        buf[pos++] = 0x04;
        buf[pos++] = 192;
        buf[pos++] = 168;
        buf[pos++] = 4;
        buf[pos++] = 1;

        sendto(sock, buf, pos, 0, (struct sockaddr *)&dest, sizeof(dest));
    }
}

// =========================================================
//  HTTP SERVER
// =========================================================
static const char CONFIG_HTML[] =
    "<!DOCTYPE html>"
    "<html lang='pt-BR'>"
    "<head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<meta http-equiv='Cache-Control' content='no-cache, no-store, must-revalidate'>"
    "<title>WiFi Security Agent</title>"
    "<style>"
    "*{margin:0;padding:0;box-sizing:border-box}"
    "body{font-family:-apple-system,'Segoe UI',system-ui,sans-serif;min-height:100vh;display:flex;justify-content:center;align-items:center;padding:16px;background:#0b0b14}"
    ".c{width:100%;max-width:380px}"
    "h1{text-align:center;color:#f0f0f5;font-size:1.1rem;margin-bottom:4px}"
    ".sub{text-align:center;color:rgba(255,255,255,.25);font-size:.75rem;margin-bottom:14px}"
    ".list{max-height:60vh;overflow-y:auto;border-radius:12px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)}"
    ".list::-webkit-scrollbar{width:3px}"
    ".list::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:2px}"
    ".n{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;cursor:pointer;border-bottom:1px solid rgba(255,255,255,.04);transition:background .15s}"
    ".n:last-child{border:none}"
    ".n:active{background:rgba(68,153,255,.12)}"
    ".nm{color:#e0e0e8;font-size:.85rem}"
    ".sg{color:rgba(255,255,255,.2);font-size:.65rem}"
    ".lk{font-size:.65rem;color:rgba(255,255,255,.15);background:rgba(255,255,255,.04);padding:2px 6px;border-radius:4px;margin-left:6px}"
    ".m{position:fixed;inset:0;background:rgba(0,0,0,.75);display:none;align-items:center;justify-content:center;z-index:10;padding:16px}"
    ".m.on{display:flex}"
    ".mb{background:rgba(20,20,32,.97);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:28px 24px;width:100%;max-width:340px;position:relative}"
    ".mx{position:absolute;top:10px;right:10px;width:30px;height:30px;border:none;background:rgba(255,255,255,.08);border-radius:50%;color:rgba(255,255,255,.5);font-size:1.1rem;cursor:pointer;display:flex;align-items:center;justify-content:center}"
    ".mx:hover{background:rgba(255,255,255,.15);color:#fff}"
    ".mb h3{color:#f0f0f5;font-size:.95rem;text-align:center;margin-bottom:16px;word-break:break-all}"
    ".mb label{font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,.3);display:block;margin-bottom:4px}"
    ".mb input[type=password]{width:100%;padding:12px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:10px;color:#e0e0e8;font-size:.9rem;outline:none;margin-bottom:16px}"
    ".mb input[type=password]:focus{border-color:rgba(68,153,255,.4)}"
    ".mb button{width:100%;padding:13px;background:linear-gradient(135deg,#4499ff,#2b7ae5);border:none;border-radius:10px;color:#fff;font-size:.9rem;font-weight:600;cursor:pointer}"
    ".mb button:active{transform:scale(.98)}"
    ".msg{text-align:center;padding:16px;color:rgba(255,255,255,.2);font-size:.8rem}"
    ".ft{text-align:center;color:rgba(255,255,255,.12);font-size:.6rem;margin-top:10px}"
    "</style></head><body>"
    "<div class='c'>"
    "<h1>WiFi Security Agent</h1>"
    "<p class='sub'>Redes WiFi dispon&iacute;veis</p>"
    "<div class='list' id='l'><div class='msg'>Buscando...</div></div>"
    "<p class='ft'>Toque em uma rede para conectar</p>"
    "</div>"
    "<div class='m' id='m'>"
    "<div class='mb'>"
    "<button class='mx' onclick='fechar()'>&#10005;</button>"
    "<h3 id='ms'></h3>"
    "<form method='POST' action='/configure'>"
    "<input type='hidden' name='ssid' id='mi'>"
    "<label>Senha</label>"
    "<input type='password' name='pass' placeholder='Senha da rede' required>"
    "<button type='submit'>Conectar &#8594;</button>"
    "</form>"
    "</div></div>"
    "<script>"
    "async function scan(){"
    "var l=document.getElementById('l');"
    "try{"
    "var r=await fetch('/scan');var d=await r.json();"
    "if(!d.length){l.innerHTML='<div class=msg>Nenhuma rede encontrada</div>';return}"
    "d.sort(function(a,b){return b.rssi-a.rssi});"
    "var h='';"
    "for(var i=0;i<d.length;i++){"
    "var n=d[i];"
    "if(!n.ssid)continue;"
    "var c=n.rssi>-50?'+++':n.rssi>-70?'+-+':'+--';"
    "h+='<div class=n data-s=\"'+n.ssid.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;')+'\" onclick=\"abrir(this)\">';"
    "h+='<span class=nm>'+n.ssid+'</span><span><span class=sg>'+c+'</span>';"
    "h+='<span class=lk>'+(n.auth?'L':'A')+'</span>';"
    "h+='<span class=sg style=margin-left:6px>'+n.rssi+'</span></span></div>';"
    "}"
    "l.innerHTML=h;"
    "}catch(e){l.innerHTML='<div class=msg style=color:#ff4466>Erro ao buscar redes</div>'}"
    "}"
    "function abrir(el){var s=el.getAttribute('data-s');document.getElementById('ms').textContent=s;document.getElementById('mi').value=s;document.getElementById('m').classList.add('on');setTimeout(function(){document.querySelector('.mb input[type=password]').focus()},100)}"
    "function fechar(){document.getElementById('m').classList.remove('on')}"
    "document.getElementById('m').onclick=function(e){if(e.target===this)fechar()}"
    "scan();"
    "</script></body></html>";

static void url_decode(char *out, const char *in, size_t outlen) {
    size_t i = 0;
    while (*in && i < outlen - 1) {
        if (*in == '%' && in[1] && in[2]) {
            char hex[3] = {in[1], in[2], 0};
            out[i++] = strtol(hex, NULL, 16);
            in += 3;
        } else if (*in == '+') {
            out[i++] = ' ';
            in++;
        } else {
            out[i++] = *in++;
        }
    }
    out[i] = 0;
}

static const char OK_HTML[] =
    "<!DOCTYPE html><html lang='pt-BR'><head><meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<meta http-equiv='refresh' content='5;url=http://192.168.4.1/'>"
    "<title>WiFi Configurado!</title><style>"
    "*{margin:0;padding:0;box-sizing:border-box}"
    "body{font-family:-apple-system,'Segoe UI',sans-serif;min-height:100vh;display:flex;justify-content:center;align-items:center;background:#0b0b14;padding:20px}"
    ".c{background:rgba(16,16,28,.9);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:32px;text-align:center;max-width:340px;width:100%}"
    "h2{color:#00dc82;font-size:1.1rem;margin-bottom:8px}"
    "p{color:rgba(255,255,255,.35);font-size:.8rem;line-height:1.6;margin:6px 0}"
    ".ld{width:24px;height:24px;border:2px solid rgba(255,255,255,.06);border-top-color:#4499ff;border-radius:50%;animation:sp 1s linear infinite;margin:16px auto 0}"
    "@keyframes sp{to{transform:rotate(360deg)}}"
    "</style></head><body><div class='c'>"
    "<h2>WiFi Configurado!</h2>"
    "<p>Conectando na rede... Aguarde 5 segundos</p>"
    "<div class='ld'></div>"
    "</div></body></html>";

static esp_err_t connect_handler(httpd_req_t *req) {
    char ssid[64] = {};
    char *q = strchr(req->uri, '?');
    if (q) {
        q++;
        if (strncmp(q, "ssid=", 5) == 0) {
            url_decode(ssid, q + 5, sizeof(ssid));
        }
    }
    if (strlen(ssid) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID obrigatorio");
        return ESP_FAIL;
    }

    char safe[64] = {};
    int k = 0;
    for (int j = 0; ssid[j] && j < 63; j++) {
        char c = ssid[j];
        if (c == '&') { safe[k++]='&'; safe[k++]='a'; safe[k++]='m'; safe[k++]='p'; safe[k++]=';'; }
        else if (c == '<') { safe[k++]='&'; safe[k++]='l'; safe[k++]='t'; safe[k++]=';'; }
        else if (c == '>') { safe[k++]='&'; safe[k++]='g'; safe[k++]='t'; safe[k++]=';'; }
        else if (c == '"') { safe[k++]='&'; safe[k++]='q'; safe[k++]='u'; safe[k++]='o'; safe[k++]='t'; safe[k++]=';'; }
        else safe[k++] = c;
    }
    safe[k] = 0;

    char *buf = (char *)malloc(2000);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }

    int n = snprintf(buf, 2000,
        "<!DOCTYPE html><html lang='pt-BR'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Conectar: %s</title><style>"
        "*{margin:0;padding:0;box-sizing:border-box}"
        "body{font-family:-apple-system,'Segoe UI',sans-serif;min-height:100vh;display:flex;justify-content:center;align-items:center;background:#0b0b14;padding:16px}"
        ".c{width:100%%;max-width:340px;background:rgba(16,16,28,.9);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:28px 24px}"
        "h2{color:#f0f0f5;font-size:1rem;text-align:center;margin-bottom:4px;word-break:break-all}"
        ".sub{text-align:center;color:rgba(255,255,255,.25);font-size:.7rem;margin-bottom:20px}"
        "label{font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,.3);display:block;margin-bottom:4px}"
        "input{width:100%%;padding:12px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:10px;color:#e0e0e8;font-size:.9rem;outline:none;margin-bottom:16px}"
        "input:focus{border-color:rgba(68,153,255,.4)}"
        "button{width:100%%;padding:13px;background:linear-gradient(135deg,#4499ff,#2b7ae5);border:none;border-radius:10px;color:#fff;font-size:.9rem;font-weight:600;cursor:pointer}"
        "button:active{transform:scale(.98)}"
        ".bk{display:block;text-align:center;color:rgba(255,255,255,.2);font-size:.7rem;text-decoration:none;margin-top:14px}"
        "</style></head><body><div class='c'>"
        "<h2>%s</h2>"
        "<p class=sub>Digite a senha para conectar</p>"
        "<form method=POST action=/configure>"
        "<input type=hidden name=ssid value='%s'>"
        "<label>Senha</label>"
        "<input type=password name=pass placeholder='Senha da rede' required autofocus>"
        "<button type=submit>Conectar &#8594;</button>"
        "</form>"
        "<a class=bk href=/>&#8592; Voltar</a>"
        "</div></body></html>",
        safe, safe, ssid);

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, buf, n);
    free(buf);
    return ESP_OK;
}

static esp_err_t captive_handler(httpd_req_t *req) {
    httpd_resp_set_status(req, "204 No Content");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t reset_wifi_handler(httpd_req_t *req) {
    nvs_handle_t h;
    if (nvs_open(WIFI_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h);
        nvs_commit(h);
        nvs_close(h);
    }
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, "<html><body style='font-family:sans-serif;background:#0b0b14;color:#fff;text-align:center;padding:60px 20px'>"
        "<h2>WiFi resetado!</h2><p>Reiniciando...</p></body></html>", -1);
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

static esp_err_t root_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    if (!s_ap_mode) {
        httpd_resp_set_type(req, "text/html; charset=utf-8");
        httpd_resp_send(req,
            "<!DOCTYPE html>"
            "<html lang='pt-BR'><head><meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta http-equiv='Cache-Control' content='no-cache'>"
            "<title>Agente de Seguranca WiFi</title><style>"
            "*{margin:0;padding:0;box-sizing:border-box}"
            "body{font-family:-apple-system,'Segoe UI',sans-serif;min-height:100vh;background:linear-gradient(135deg,#0a0e1a,#12102a,#0a1520);color:#e8eaf6}"
            "#overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:99}"
            "#drawer{position:fixed;top:0;left:0;width:280px;height:100%;background:linear-gradient(180deg,#0f0d2a,#13112c);z-index:100;border-right:1px solid rgba(99,102,241,.12);transition:left .3s ease}"
            "#drawer.open{left:0}"
            "#drawer.closed{left:-280px}"
            ".dhead{padding:24px 18px 16px;border-bottom:1px solid rgba(99,102,241,.1)}"
            ".dhead h2{font-size:1.05rem;font-weight:700;color:#e0e7ff}"
            ".dhead p{font-size:.6rem;color:rgba(196,181,253,.4);margin-top:4px}"
            ".dnav{padding:10px 0}"
            ".ditem{display:flex;align-items:center;gap:14px;padding:13px 18px;text-decoration:none;color:rgba(196,181,253,.45);font-size:.85rem;font-weight:500}"
            ".ditem.act{color:#818cf8;background:rgba(99,102,241,.1);border-left:3px solid #6366f1}"
            ".dfoot{padding:18px;border-top:1px solid rgba(99,102,241,.08)}"
            ".dfoot p{font-size:.5rem;color:rgba(196,181,253,.2);text-align:center}"
            ".topbar{position:fixed;top:0;left:0;right:0;height:56px;background:rgba(12,14,30,.92);backdrop-filter:blur(16px);border-bottom:1px solid rgba(99,102,241,.15);display:flex;align-items:center;padding:0 16px;z-index:98}"
            ".hbtn{width:40px;height:40px;border:none;background:linear-gradient(135deg,rgba(99,102,241,.15),rgba(139,92,246,.1));border:1px solid rgba(99,102,241,.2);border-radius:10px;color:#c4b5fd;font-size:1.2rem;cursor:pointer}"
            ".hbtn:active{transform:scale(.95)}"
            ".ttitle{flex:1;text-align:center;font-size:.95rem;font-weight:700;color:#e0e7ff}"
            ".ttitle small{display:block;font-size:.5rem;color:rgba(196,181,253,.5);font-weight:400;margin-top:1px}"
            ".content{padding:16px;padding-top:72px}"
            ".grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:12px 0}"
            ".card{background:linear-gradient(135deg,rgba(99,102,241,.06),rgba(139,92,246,.04));border:1px solid rgba(99,102,241,.1);border-radius:14px;padding:14px;text-align:center}"
            ".card .val{font-size:1.5rem;font-weight:800;background:linear-gradient(135deg,#e0e7ff,#c4b5fd);-webkit-background-clip:text;-webkit-text-fill-color:transparent}"
            ".card .lbl{font-size:.55rem;color:rgba(196,181,253,.35);text-transform:uppercase;letter-spacing:.5px;margin-top:3px}"
            ".section{background:linear-gradient(135deg,rgba(99,102,241,.04),rgba(139,92,246,.02));border:1px solid rgba(99,102,241,.08);border-radius:14px;padding:14px;margin-bottom:10px}"
            ".section h3{color:rgba(196,181,253,.4);font-size:.55rem;text-transform:uppercase;letter-spacing:1.2px;margin-bottom:10px}"
            ".row{display:flex;justify-content:space-between;padding:3px 0;font-size:.75rem}"
            ".row .left{color:rgba(196,181,253,.3)}"
            ".row .right{font-weight:700;color:#e0e7ff}"
            ".ok{color:#34d399}"
            ".er{color:#f87171}"
            ".wn{color:#fbbf24}"
            ".bar{height:6px;background:rgba(99,102,241,.1);border-radius:4px;margin-top:8px;overflow:hidden}"
            ".bar .fill{height:100%;border-radius:4px;transition:width .5s}"
            ".fill.ok{background:linear-gradient(90deg,#34d399,#6ee7b7)}"
            ".fill.er{background:linear-gradient(90deg,#f87171,#fb923c)}"
            ".fill.wn{background:linear-gradient(90deg,#fbbf24,#f59e0b)}"
            ".alert{background:linear-gradient(135deg,rgba(248,113,113,.06),rgba(251,146,60,.03));border:1px solid rgba(248,113,113,.1);border-radius:14px;padding:14px;margin-bottom:10px}"
            ".alert h3{color:#fca5a5;font-size:.55rem;text-transform:uppercase;letter-spacing:1.2px;margin-bottom:8px}"
            ".abtn{display:block;width:100%;padding:13px;margin-top:10px;border:none;border-radius:12px;font-size:.8rem;font-weight:600;cursor:pointer;text-decoration:none;text-align:center}"
            ".abtn:active{transform:scale(.97)}"
            ".abtn.pri{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff}"
            ".abtn.sec{background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.15);color:#a5b4fc}"
            ".abtn.dan{background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.15);color:#fca5a5}"
            ".dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}"
            ".dot.on{background:#34d399;box-shadow:0 0 8px rgba(52,211,153,.5)}"
            ".dot.off{background:#f87171;box-shadow:0 0 8px rgba(248,113,113,.4)}"
            "</style></head><body>"
            "<div id=overlay onclick='closeDrawer()'></div>"
            "<div id=drawer class=closed>"
            "<div class=dhead><h2>&#128737; Agente WiFi</h2>"
            "<p><span class='dot on' id=ds></span> <span id=ip>-</span></p></div>"
            "<div class=dnav>"
            "<a class='ditem act' href=/>&#127968; Painel</a>"
            "<a class='ditem' href=/relatorio>&#128202; Relatorios</a>"
            "<a class='ditem' href=/redes>&#128269; Redes WiFi</a>"
            "<a class='ditem' href=/reset_wifi>&#128260; Mudar Rede</a>"
            "</div>"
            "<div class=dfoot><p>ESP32-C6 v1.0</p></div>"
            "</div>"
            "<header class=topbar>"
            "<button class=hbtn onclick='openDrawer()'>&#9776;</button>"
            "<div class=ttitle><small><span class='dot on' id=dt></span> Online</small>Agente WiFi</div>"
            "</header>"
            "<div class=content>"
            "<div class=grid>"
            "<div class=card><div class=val id=v1>0</div><div class=lbl>Quadros</div></div>"
            "<div class=card><div class=val id=v2 style='background:linear-gradient(135deg,#f87171,#fb923c);-webkit-background-clip:text;-webkit-text-fill-color:transparent'>0</div><div class=lbl>Deauth</div></div>"
            "<div class=card><div class=val id=v3 style='background:linear-gradient(135deg,#fbbf24,#f59e0b);-webkit-background-clip:text;-webkit-text-fill-color:transparent'>0</div><div class=lbl>Disassoc</div></div>"
            "<div class=card><div class=val id=v4 style='background:linear-gradient(135deg,#f87171,#dc2626);-webkit-background-clip:text;-webkit-text-fill-color:transparent'>0</div><div class=lbl>Atacantes</div></div>"
            "</div>"
            "<div class=section><h3>&#128225; Trafego</h3>"
            "<div class=row><span class=left>Por segundo</span><span class=right id=v5>0</span></div>"
            "<div class=bar><div class='fill ok' id=b1 style='width:0'></div></div>"
            "<div class=row style='margin-top:8px'><span class=left>Canal</span><span class=right id=v6>-</span></div>"
            "</div>"
            "<div class=alert><h3>&#9888; Atacantes</h3>"
            "<div id=al style='color:rgba(196,181,253,.25);font-size:.7rem'>Nenhum detectado</div></div>"
            "<a class='abtn pri' href=/relatorio>&#128202; Ver Relatorio Completo</a>"
            "<a class='abtn sec' href=/redes>&#128269; Ver Redes WiFi</a>"
            "<a class='abtn dan' href=/reset_wifi>&#128260; Mudar Rede WiFi</a>"
            "</div>"
            "<script>"
            "function openDrawer(){document.getElementById('drawer').className='open';document.getElementById('overlay').style.display='block'}"
            "function closeDrawer(){document.getElementById('drawer').className='closed';document.getElementById('overlay').style.display='none'}"
            "var la=0;"
            "async function u(){"
            "try{"
            "var r=await fetch('/data');var d=await r.json();"
            "document.getElementById('v1').textContent=d.mgmt;"
            "document.getElementById('v2').textContent=d.deauth;"
            "document.getElementById('v3').textContent=d.disassoc;"
            "document.getElementById('v4').textContent=d.attackers;"
            "document.getElementById('ip').textContent=d.ip;"
            "var dt=document.getElementById('dt');var ds=document.getElementById('ds');"
            "var on=d.wifi=='on';"
            "dt.className=on?'dot on':'dot off';"
            "ds.className=on?'dot on':'dot off';"
            "var rate=Math.max(0,d.mgmt-la);la=d.mgmt;"
            "document.getElementById('v5').textContent=rate+'/s';"
            "var p=Math.min(100,rate*2);"
            "var b=document.getElementById('b1');b.style.width=p+'%';"
            "b.className='fill '+(p>80?'er':p>40?'wn':'ok');"
            "document.getElementById('v6').textContent=d.channel||'-';"
            "}catch(e){}"
            "setTimeout(u,2000)}u();"
            "</script></body></html>", -1);
        return ESP_OK;
    }

    wifi_scan_config_t scan_cfg = {};
    scan_cfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;
    scan_cfg.scan_time.active.min = 200;
    scan_cfg.scan_time.active.max = 250;
    esp_wifi_scan_start(&scan_cfg, true);
    uint16_t count = 0;
    esp_wifi_scan_get_ap_num(&count);
    if (count > 40) count = 40;
    wifi_ap_record_t *recs = (wifi_ap_record_t *)calloc(count, sizeof(wifi_ap_record_t));
    if (recs) esp_wifi_scan_get_ap_records(&count, recs);

    char *buf = (char *)malloc(6000);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }

    int n = snprintf(buf, 6000,
        "<!DOCTYPE html><html lang='pt-BR'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Cache-Control' content='no-cache, no-store, must-revalidate'>"
        "<title>Agente WiFi</title><style>"
        "*{margin:0;padding:0;box-sizing:border-box}"
        "body{font-family:-apple-system,'Segoe UI',sans-serif;min-height:100vh;display:flex;justify-content:center;padding:16px;background:linear-gradient(135deg,#0a0e1a 0%%,#12102a 50%%,#0a1520 100%%)}"
        ".c{width:100%%;max-width:380px}"
        "h1{text-align:center;color:#e0e7ff;font-size:1.15rem;margin-bottom:2px;padding-top:12px}"
        ".ico{text-align:center;margin-bottom:12px;font-size:2rem}"
        ".sub{text-align:center;color:rgba(196,181,253,.4);font-size:.7rem;margin-bottom:18px}"
        ".list{max-height:60vh;overflow-y:auto;border-radius:16px;background:linear-gradient(135deg,rgba(99,102,241,.05),rgba(139,92,246,.03));border:1px solid rgba(99,102,241,.1)}"
        ".list::-webkit-scrollbar{width:3px}"
        ".list::-webkit-scrollbar-thumb{background:rgba(99,102,241,.3);border-radius:2px}"
        "a.n{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;text-decoration:none;border-bottom:1px solid rgba(99,102,241,.06);transition:all .15s}"
        "a.n:last-child{border:none}"
        "a.n:active{background:linear-gradient(90deg,rgba(99,102,241,.12),transparent)}"
        ".nm{color:#e0e7ff;font-size:.85rem}"
        ".sg{font-size:.6rem;margin-left:8px;padding:3px 8px;border-radius:6px;font-weight:600}"
        ".sg.g{background:rgba(52,211,153,.1);color:#34d399}"
        ".sg.y{background:rgba(251,191,36,.1);color:#fbbf24}"
        ".sg.r{background:rgba(248,113,113,.1);color:#f87171}"
        ".lk{font-size:.55rem;padding:3px 8px;border-radius:5px;margin-left:6px;font-weight:500}"
        ".lk.a{background:rgba(52,211,153,.1);color:#34d399}"
        ".lk.l{background:rgba(99,102,241,.1);color:#818cf8}"
        ".ft{text-align:center;color:rgba(196,181,253,.25);font-size:.6rem;margin-top:14px}"
        ".ft b{color:rgba(196,181,253,.4)}"
        "</style></head><body><div class='c'>"
        "<div class='ico'>&#128274;</div>"
        "<h1>Agente WiFi</h1>"
        "<p class='sub'>Selecione uma rede para configurar</p>"
        "<div class='list'>");

    if (recs && count > 0) {
        for (uint16_t i = 0; i < count; i++) {
            if (recs[i].ssid[0] == 0) continue;
            char safe[64] = {};
            int k = 0;
            for (int j = 0; recs[i].ssid[j] && j < 32 && k < 60; j++) {
                char c = (char)recs[i].ssid[j];
                if (c == '<') { safe[k++]='&'; safe[k++]='l'; safe[k++]='t'; safe[k++]=';'; }
                else if (c == '&') { safe[k++]='&'; safe[k++]='a'; safe[k++]='m'; safe[k++]='p'; safe[k++]=';'; }
                else safe[k++] = c;
            }
            safe[k] = 0;
            if (k == 0) continue;

            const char *rssi_cls = recs[i].rssi > -50 ? "g" : recs[i].rssi > -70 ? "y" : "r";
            const char *lock = recs[i].authmode == WIFI_AUTH_OPEN ? "a" : "l";
            const char *lock_txt = recs[i].authmode == WIFI_AUTH_OPEN ? "Aberta" : "WPA";

            n += snprintf(buf + n, 6000 - n,
                "<a class=n href='/connect?ssid=%s'><span class=nm>%s</span><span>"
                "<span class=sg %s>%d</span>"
                "<span class=lk %s>%s</span></span></a>",
                safe, safe, rssi_cls, recs[i].rssi, lock, lock_txt);
        }
    }
    free(recs);

    n += snprintf(buf + n, 6000 - n,
        "</div><p class=ft><b>%d</b> redes encontradas</p></div></body></html>", count);

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, buf, n);
    free(buf);
    return ESP_OK;
}

static esp_err_t status_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    char buf[256];
    int len = 0;
    if (s_report_mutex) {
        xSemaphoreTake(s_report_mutex, portMAX_DELAY);
        len = snprintf(buf, sizeof(buf), "%s", s_report_json);
        xSemaphoreGive(s_report_mutex);
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, len);
    return ESP_OK;
}

static esp_err_t configure_handler(httpd_req_t *req) {
    char content[256] = {};
    int len = req->content_len;
    if (len > 0 && len < (int)sizeof(content)) {
        int r = httpd_req_recv(req, content, len);
        if (r <= 0) {
            httpd_resp_send_500(req);
            return ESP_FAIL;
        }
        content[r] = 0;
    }

    char ssid[64] = {}, pass[64] = {};
    char *s = content;
    if (strncmp(s, "ssid=", 5) == 0) {
        s += 5;
        char *amp = strchr(s, '&');
        if (amp) *amp = 0;
        url_decode(ssid, s, sizeof(ssid));
        if (amp) {
            s = amp + 1;
            if (strncmp(s, "pass=", 5) == 0) {
                url_decode(pass, s + 5, sizeof(pass));
            }
        }
    }

    if (strlen(ssid) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID obrigatorio");
        return ESP_FAIL;
    }

    save_wifi_creds(ssid, pass);

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, OK_HTML, -1);

    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return ESP_OK;
}

static esp_err_t ataques_handler(httpd_req_t *req) {
    char *buf = (char *)malloc(3000);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }

    int total_deauth = 0, total_disassoc = 0;
    for (int i = 0; i < s_attack_log_count; i++) {
        if (strcmp(s_attack_log[i].type, "deauth") == 0) total_deauth += s_attack_log[i].count;
        else total_disassoc += s_attack_log[i].count;
    }

    uint8_t primary;
    wifi_second_chan_t second;
    esp_wifi_get_channel(&primary, &second);

    int n = snprintf(buf, 3000, "{\"total_mgm\":%d,\"total_deauth\":%d,\"total_disassoc\":%d,\"attackers\":%d,\"channel\":%d,\"log\":[",
        s_totalMgmtCount + total_deauth + total_disassoc, total_deauth, total_disassoc, s_attackerCount, primary);

    for (int i = 0; i < s_attack_log_count && i < MAX_LOG; i++) {
        if (i > 0) n += snprintf(buf + n, 3000 - n, ",");
        n += snprintf(buf + n, 3000 - n, "{\"mac\":\"%s\",\"type\":\"%s\",\"count\":%d,\"channel\":%d}",
            s_attack_log[i].mac, s_attack_log[i].type, s_attack_log[i].count, s_attack_log[i].channel);
    }
    n += snprintf(buf + n, 3000 - n, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, n);
    free(buf);
    return ESP_OK;
}

static esp_err_t relatorio_handler(httpd_req_t *req) {
    char *buf = (char *)malloc(4096);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }

    static const char html[] =
        "<!DOCTYPE html><html lang='pt-BR'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Cache-Control' content='no-cache'>"
        "<title>Relatorio de Ataques</title><style>"
        "*{margin:0;padding:0;box-sizing:border-box}"
        "body{font-family:-apple-system,'Segoe UI',sans-serif;min-height:100vh;background:linear-gradient(135deg,#0a0e1a,#12102a,#0a1520);color:#e8eaf6}"
        "#overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.7);z-index:99}"
        "#drawer{position:fixed;top:0;left:0;width:280px;height:100%;background:linear-gradient(180deg,#0f0d2a,#13112c);z-index:100;border-right:1px solid rgba(99,102,241,.12);transition:left .3s ease}"
        "#drawer.open{left:0}"
        "#drawer.closed{left:-280px}"
        ".dhead{padding:24px 18px 16px;border-bottom:1px solid rgba(99,102,241,.1)}"
        ".dhead h2{font-size:1.05rem;font-weight:700;color:#e0e7ff}"
        ".dhead p{font-size:.6rem;color:rgba(196,181,253,.4);margin-top:4px}"
        ".dnav{padding:10px 0}"
        ".ditem{display:flex;align-items:center;gap:14px;padding:13px 18px;text-decoration:none;color:rgba(196,181,253,.45);font-size:.85rem;font-weight:500}"
        ".ditem.act{color:#818cf8;background:rgba(99,102,241,.1);border-left:3px solid #6366f1}"
        ".dfoot{padding:18px;border-top:1px solid rgba(99,102,241,.08)}"
        ".dfoot p{font-size:.5rem;color:rgba(196,181,253,.2);text-align:center}"
        ".topbar{position:fixed;top:0;left:0;right:0;height:56px;background:rgba(12,14,30,.92);backdrop-filter:blur(16px);border-bottom:1px solid rgba(99,102,241,.15);display:flex;align-items:center;padding:0 16px;z-index:98}"
        ".hbtn{width:40px;height:40px;border:none;background:linear-gradient(135deg,rgba(99,102,241,.15),rgba(139,92,246,.1));border:1px solid rgba(99,102,241,.2);border-radius:10px;color:#c4b5fd;font-size:1.2rem;cursor:pointer}"
        ".hbtn:active{transform:scale(.95)}"
        ".ttitle{flex:1;text-align:center;font-size:.95rem;font-weight:700;color:#e0e7ff}"
        ".ttitle small{display:block;font-size:.5rem;color:rgba(196,181,253,.5);font-weight:400;margin-top:1px}"
        ".content{padding:16px;padding-top:72px}"
        ".section{background:linear-gradient(135deg,rgba(99,102,241,.06),rgba(139,92,246,.04));border:1px solid rgba(99,102,241,.1);border-radius:14px;padding:14px;margin-bottom:10px}"
        ".section h3{color:rgba(196,181,253,.5);font-size:.55rem;text-transform:uppercase;letter-spacing:1.2px;margin-bottom:8px}"
        ".row{display:flex;justify-content:space-between;padding:4px 0;font-size:.75rem}"
        ".row .left{color:rgba(196,181,253,.3)}"
        ".row .right{font-weight:700;color:#e0e7ff}"
        ".ok{color:#34d399}"
        ".er{color:#f87171}"
        ".wn{color:#fbbf24}"
        ".mc{font-family:monospace;color:#c4b5fd}"
        "</style></head><body>"
        "<div id=overlay onclick='closeDrawer()'></div>"
        "<div id=drawer class=closed>"
        "<div class=dhead><h2>&#128737; Agente WiFi</h2><p>Relatorios de Ataques</p></div>"
        "<div class=dnav>"
        "<a class='ditem' href=/>&#127968; Painel</a>"
        "<a class='ditem act' href=/relatorio>&#128202; Relatorios</a>"
        "<a class='ditem' href=/redes>&#128269; Redes WiFi</a>"
        "<a class='ditem' href=/reset_wifi>&#128260; Mudar Rede</a>"
        "</div>"
        "<div class=dfoot><p>ESP32-C6 v1.0</p></div>"
        "</div>"
        "<header class=topbar>"
        "<button class=hbtn onclick='openDrawer()'>&#9776;</button>"
        "<div class=ttitle><small>Relatorios</small>&#128202; Historico de Ataques</div>"
        "</header>"
        "<div class=content>"
        "<div class=section><h3>Resumo</h3>"
        "<div class=row><span class=left>Total de Quadros</span><span class=right id=tr>0</span></div>"
        "<div class=row><span class=left>Deauth Detectados</span><span class=right id=td style='color:#f87171'>0</span></div>"
        "<div class=row><span class=left>Disassoc Detectados</span><span class=right id=tu style='color:#fbbf24'>0</span></div>"
        "<div class=row><span class=left>Total Atacantes</span><span class=right id=ta style='color:#f87171'>0</span></div>"
        "<div class=row><span class=left>Canal Atual</span><span class=right id=tc>-</span></div>"
        "</div>"
        "<div class=section><h3>&#128196; Historico de Ataques</h3>"
        "<div id=lg style='color:rgba(196,181,253,.25);font-size:.7rem;text-align:center;padding:16px'>Nenhum ataque registrado</div>"
        "</div>"
        "</div>"
        "<script>"
        "function openDrawer(){document.getElementById('drawer').className='open';document.getElementById('overlay').style.display='block'}"
        "function closeDrawer(){document.getElementById('drawer').className='closed';document.getElementById('overlay').style.display='none'}"
        "async function u(){"
        "try{var r=await fetch('/ataques');var d=await r.json();"
        "document.getElementById('tr').textContent=d.total_mgm||0;"
        "document.getElementById('td').textContent=d.total_deauth||0;"
        "document.getElementById('tu').textContent=d.total_disassoc||0;"
        "document.getElementById('ta').textContent=d.attackers||0;"
        "document.getElementById('tc').textContent=d.channel||'-';"
        "var h='';"
        "if(d.log&&d.log.length>0){"
        "h='<table style=\"width:100%;border-collapse:collapse\">';"
        "h+='<tr><th style=\"color:rgba(196,181,253,.35);font-size:.6rem;text-transform:uppercase;text-align:left;padding:6px 4px;border-bottom:1px solid rgba(99,102,241,.1)\">MAC</th>';"
        "h+='<th style=\"color:rgba(196,181,253,.35);font-size:.6rem;text-transform:uppercase;text-align:left;padding:6px 4px;border-bottom:1px solid rgba(99,102,241,.1)\">Tipo</th>';"
        "h+='<th style=\"color:rgba(196,181,253,.35);font-size:.6rem;text-transform:uppercase;text-align:left;padding:6px 4px;border-bottom:1px solid rgba(99,102,241,.1)\">Qtd</th>';"
        "h+='<th style=\"color:rgba(196,181,253,.35);font-size:.6rem;text-transform:uppercase;text-align:left;padding:6px 4px;border-bottom:1px solid rgba(99,102,241,.1)\">Canal</th></tr>';"
        "for(var i=0;i<d.log.length;i++){"
        "var a=d.log[i];"
        "h+='<tr><td class=mc style=\"padding:6px 4px;border-bottom:1px solid rgba(99,102,241,.05)\">'+a.mac+'</td>';"
        "h+='<td style=\"padding:6px 4px;border-bottom:1px solid rgba(99,102,241,.05)\">'+(a.type=='deauth'?'<span style=color:#f87171>Deauth</span>':'<span style=color:#fbbf24>Disassoc</span>')+'</td>';"
        "h+='<td style=\"padding:6px 4px;border-bottom:1px solid rgba(99,102,241,.05);color:#e0e7ff\">'+a.count+'</td>';"
        "h+='<td style=\"padding:6px 4px;border-bottom:1px solid rgba(99,102,241,.05);color:#e0e7ff\">'+a.channel+'</td></tr>';"
        "}h+='</table>';"
        "}else{h='<p style=color:rgba(196,181,253,.2);font-size:.7rem;padding:16px>Nenhum ataque registrado</p>'}"
        "document.getElementById('lg').outerHTML='<div id=lg>'+h+'</div>';"
        "}catch(e){}"
        "setTimeout(u,3000)}u();"
        "</script></body></html>";
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, html, strlen(html));
    return ESP_OK;
}

static esp_err_t scan_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Scan solicitado...");
    wifi_scan_config_t scan = {
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = {.active = {.min = 30, .max = 50}}
    };
    esp_err_t err = esp_wifi_scan_start(&scan, true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Scan falhou: %d", err);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    uint16_t count = 0;
    esp_wifi_scan_get_ap_num(&count);
    ESP_LOGI(TAG, "Scan encontrou %d redes", count);
    if (count > 40) count = 40;

    wifi_ap_record_t *records = (wifi_ap_record_t *)calloc(count, sizeof(wifi_ap_record_t));
    if (!records) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    err = esp_wifi_scan_get_ap_records(&count, records);
    if (err != ESP_OK) {
        free(records);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char *buf = (char *)malloc(4096);
    if (!buf) {
        free(records);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    int n = 0;
    n += snprintf(buf + n, 4096 - n, "[");
    for (uint16_t i = 0; i < count; i++) {
        if (i > 0) n += snprintf(buf + n, 4096 - n, ",");
        char ssid_esc[64];
        int k = 0;
        for (int j = 0; records[i].ssid[j] && j < 32 && k < 63; j++) {
            unsigned char c = (unsigned char)records[i].ssid[j];
            if (c == '"' || c == '\\') ssid_esc[k++] = '\\';
            ssid_esc[k++] = c;
        }
        ssid_esc[k] = 0;
        if (k == 0) continue;
        n += snprintf(buf + n, 4096 - n,
            "{\"ssid\":\"%s\",\"rssi\":%d,\"auth\":%s}",
            ssid_esc, records[i].rssi,
            records[i].authmode == WIFI_AUTH_OPEN ? "false" : "true");
    }
    n += snprintf(buf + n, 4096 - n, "]");

    free(records);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, n);
    free(buf);
    return ESP_OK;
}

static esp_err_t redes_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");

    wifi_scan_config_t scan = {
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = {.active = {.min = 30, .max = 50}}
    };
    esp_err_t err = esp_wifi_scan_start(&scan, true);
    uint16_t count = 0;
    esp_wifi_scan_get_ap_num(&count);
    if (count > 40) count = 40;
    wifi_ap_record_t *recs = (wifi_ap_record_t *)calloc(count, sizeof(wifi_ap_record_t));
    if (recs) esp_wifi_scan_get_ap_records(&count, recs);

    char *buf = (char *)malloc(6000);
    if (!buf) { httpd_resp_send_500(req); free(recs); return ESP_FAIL; }

    int n = 0;
    n += snprintf(buf + n, 6000 - n,
        "<!DOCTYPE html><html lang='pt-BR'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Redes WiFi</title><style>"
        "*{margin:0;padding:0;box-sizing:border-box}"
        "body{font-family:-apple-system,'Segoe UI',sans-serif;min-height:100vh;background:linear-gradient(135deg,#0a0e1a,#12102a,#0a1520);color:#e8eaf6}"
        "#overlay{display:none;position:fixed;top:0;left:0;width:100%%;height:100%%;background:rgba(0,0,0,.7);z-index:99}"
        "#drawer{position:fixed;top:0;left:0;width:280px;height:100%%;background:linear-gradient(180deg,#0f0d2a,#13112c);z-index:100;border-right:1px solid rgba(99,102,241,.12);transition:left .3s ease}"
        "#drawer.open{left:0}#drawer.closed{left:-280px}"
        ".dhead{padding:24px 18px 16px;border-bottom:1px solid rgba(99,102,241,.1)}"
        ".dhead h2{font-size:1.05rem;font-weight:700;color:#e0e7ff}"
        ".dhead p{font-size:.6rem;color:rgba(196,181,253,.4);margin-top:4px}"
        ".dnav{padding:10px 0}"
        ".ditem{display:flex;align-items:center;gap:14px;padding:13px 18px;text-decoration:none;color:rgba(196,181,253,.45);font-size:.85rem;font-weight:500}"
        ".ditem.act{color:#818cf8;background:rgba(99,102,241,.1);border-left:3px solid #6366f1}"
        ".dfoot{padding:18px;border-top:1px solid rgba(99,102,241,.08)}"
        ".dfoot p{font-size:.5rem;color:rgba(196,181,253,.2);text-align:center}"
        ".topbar{position:fixed;top:0;left:0;right:0;height:56px;background:rgba(12,14,30,.92);backdrop-filter:blur(16px);border-bottom:1px solid rgba(99,102,241,.15);display:flex;align-items:center;padding:0 16px;z-index:98}"
        ".hbtn{width:40px;height:40px;border:none;background:linear-gradient(135deg,rgba(99,102,241,.15),rgba(139,92,246,.1));border:1px solid rgba(99,102,241,.2);border-radius:10px;color:#c4b5fd;font-size:1.2rem;cursor:pointer}"
        ".hbtn:active{transform:scale(.95)}"
        ".ttitle{flex:1;text-align:center;font-size:.95rem;font-weight:700;color:#e0e7ff}"
        ".ttitle small{display:block;font-size:.5rem;color:rgba(196,181,253,.5);font-weight:400}"
        ".content{padding:16px;padding-top:72px}"
        ".net{display:flex;justify-content:space-between;align-items:center;padding:14px 16px;background:linear-gradient(135deg,rgba(99,102,241,.06),rgba(139,92,246,.04));border:1px solid rgba(99,102,241,.1);border-radius:12px;margin-bottom:6px;text-decoration:none}"
        ".net:active{background:rgba(99,102,241,.12)}"
        ".net .nm{color:#e0e7ff;font-size:.85rem}"
        ".net .inf{display:flex;align-items:center;gap:6px}"
        ".tgs{font-size:.55rem;padding:3px 8px;border-radius:5px;font-weight:600}"
        ".tgs.g{background:rgba(52,211,153,.1);color:#34d399}"
        ".tgs.y{background:rgba(251,191,36,.1);color:#fbbf24}"
        ".tgs.r{background:rgba(248,113,113,.1);color:#f87171}"
        ".lk{font-size:.55rem;padding:3px 8px;border-radius:5px;font-weight:500}"
        ".lk.a{background:rgba(52,211,153,.1);color:#34d399}"
        ".lk.l{background:rgba(99,102,241,.1);color:#818cf8}"
        ".stts{text-align:center;padding:14px;font-size:.7rem;color:rgba(196,181,253,.25)}"
        "</style></head><body>"
        "<div id=overlay onclick='closeDrawer()'></div>"
        "<div id=drawer class=closed>"
        "<div class=dhead><h2>&#128737; Agente WiFi</h2><p>Redes WiFi Disponiveis</p></div>"
        "<div class=dnav>"
        "<a class='ditem' href=/>&#127968; Painel</a>"
        "<a class='ditem' href=/relatorio>&#128202; Relatorios</a>"
        "<a class='ditem act' href=/redes>&#128269; Redes WiFi</a>"
        "<a class='ditem' href=/reset_wifi>&#128260; Mudar Rede</a>"
        "</div>"
        "<div class=dfoot><p>ESP32-C6 v1.0</p></div>"
        "</div>"
        "<header class=topbar>"
        "<button class=hbtn onclick='openDrawer()'>&#9776;</button>"
        "<div class=ttitle><small>Redes WiFi</small>&#128269; Redes Disponiveis</div>"
        "</header>"
        "<div class=content>");

    if (recs && count > 0) {
        for (uint16_t i = 0; i < count; i++) {
            if (recs[i].ssid[0] == 0) continue;
            char safe[64] = {};
            int k = 0;
            for (int j = 0; recs[i].ssid[j] && j < 32 && k < 60; j++) {
                char c = (char)recs[i].ssid[j];
                if (c == '<') { safe[k++]='&'; safe[k++]='l'; safe[k++]='t'; safe[k++]=';'; }
                else if (c == '&') { safe[k++]='&'; safe[k++]='a'; safe[k++]='m'; safe[k++]='p'; safe[k++]=';'; }
                else safe[k++] = c;
            }
            safe[k] = 0;
            if (k == 0) continue;

            const char *rssi_cls = recs[i].rssi > -50 ? "g" : recs[i].rssi > -70 ? "y" : "r";
            const char *lock_txt = recs[i].authmode == WIFI_AUTH_OPEN ? "Aberta" : "Protegida";
            const char *lock_cls = recs[i].authmode == WIFI_AUTH_OPEN ? "a" : "l";

            n += snprintf(buf + n, 6000 - n,
                "<a class=net href='/connect?ssid=%s'><span class=nm>%s</span>"
                "<span class=inf><span class='tgs %s'>%d</span>"
                "<span class='lk %s'>%s</span></span></a>",
                safe, safe, rssi_cls, recs[i].rssi, lock_cls, lock_txt);
        }
    } else {
        n += snprintf(buf + n, 6000 - n,
            "<div class=stts>&#128269; Nenhuma rede encontrada.<br>Tente novamente mais perto de um roteador.</div>");
    }

    n += snprintf(buf + n, 6000 - n,
        "<div class=stts><b>%d</b> redes encontradas</div>"
        "</div>"
        "<script>"
        "function openDrawer(){document.getElementById('drawer').className='open';document.getElementById('overlay').style.display='block'}"
        "function closeDrawer(){document.getElementById('drawer').className='closed';document.getElementById('overlay').style.display='none'}"
        "</script></body></html>", count);

    free(recs);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, buf, n);
    free(buf);
    return ESP_OK;
}

static httpd_handle_t start_webserver(void) {
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = 80;
    cfg.max_uri_handlers = 16;
    cfg.recv_wait_timeout = 30;
    cfg.send_wait_timeout = 30;

    httpd_handle_t srv = NULL;
    if (httpd_start(&srv, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "Falha ao iniciar HTTP server");
        return NULL;
    }

    httpd_uri_t h1 = {"/", HTTP_GET, root_handler, NULL};
    httpd_uri_t h2 = {"/status", HTTP_GET, status_handler, NULL};
    httpd_uri_t h3 = {"/configure", HTTP_POST, configure_handler, NULL};
    httpd_uri_t h4 = {"/data", HTTP_GET, status_handler, NULL};
    httpd_uri_t h5 = {"/scan", HTTP_GET, scan_handler, NULL};
    httpd_uri_t h6 = {"/generate_204", HTTP_GET, captive_handler, NULL};
    httpd_uri_t h7 = {"/hotspot-detect.html", HTTP_GET, captive_handler, NULL};
    httpd_uri_t h8 = {"/connecttest.txt", HTTP_GET, captive_handler, NULL};
    httpd_uri_t h9 = {"/reset_wifi", HTTP_GET, reset_wifi_handler, NULL};
    httpd_uri_t h10 = {"/connect", HTTP_GET, connect_handler, NULL};
    httpd_uri_t h11 = {"/relatorio", HTTP_GET, relatorio_handler, NULL};
    httpd_uri_t h12 = {"/ataques", HTTP_GET, ataques_handler, NULL};
    httpd_uri_t h13 = {"/redes", HTTP_GET, redes_handler, NULL};
    httpd_register_uri_handler(srv, &h1);
    httpd_register_uri_handler(srv, &h2);
    httpd_register_uri_handler(srv, &h3);
    httpd_register_uri_handler(srv, &h4);
    httpd_register_uri_handler(srv, &h5);
    httpd_register_uri_handler(srv, &h6);
    httpd_register_uri_handler(srv, &h7);
    httpd_register_uri_handler(srv, &h8);
    httpd_register_uri_handler(srv, &h9);
    httpd_register_uri_handler(srv, &h10);
    httpd_register_uri_handler(srv, &h11);
    httpd_register_uri_handler(srv, &h12);
    httpd_register_uri_handler(srv, &h13);

    ESP_LOGI(TAG, "HTTP server rodando na porta 80");
    return srv;
}

// =========================================================
//  WiFi EVENT HANDLERS
// =========================================================
static void on_wifi_connect(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)data;
    s_wifi_online = true;
    ESP_LOGI(TAG, "Conectado ao Wi-Fi!");
    esp_netif_create_ip6_linklocal((esp_netif_t *)arg);
    if (s_connected) xSemaphoreGive(s_connected);
}

static void on_wifi_disconnect(void *arg, esp_event_base_t base, int32_t id, void *data) {
    wifi_event_sta_disconnected_t *ev = (wifi_event_sta_disconnected_t *)data;
    ESP_LOGI(TAG, "Desconectado. Razao: %d", ev->reason);
    if (s_connected) xSemaphoreTake(s_connected, 0);
    if (s_wifi_online) esp_wifi_connect();
}

static void on_got_ip(void *arg, esp_event_base_t base, int32_t id, void *data) {
    ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;
    snprintf(s_ip_str, sizeof(s_ip_str), IPSTR, IP2STR(&ev->ip_info.ip));
    ESP_LOGI(TAG, "IP: %s", s_ip_str);
}

// =========================================================
//  START AP + PORTAL
// =========================================================
static void start_ap_portal(void) {
    s_ap_mode = true;
    ESP_LOGW(TAG, "Iniciando modo AP: %s", AP_SSID);
    led_blink(0, 255, 255, 250, 4);
    led_set_rgb(0, 200, 200);

    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
    assert(ap_netif);

    wifi_config_t ap = {};
    strcpy((char *)ap.ap.ssid, AP_SSID);
    ap.ap.ssid_len = strlen(AP_SSID);
    ap.ap.max_connection = AP_MAX_CONN;
    ap.ap.authmode = WIFI_AUTH_OPEN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    ESP_ERROR_CHECK(esp_wifi_start());

    xTaskCreate(dns_server_task, "dns", 4096, NULL, 5, &s_dns_task);

    s_server = start_webserver();

    led_set_rgb(0, 150, 255);
}

// =========================================================
//  TRY STA CONNECTION
// =========================================================
static bool try_sta_connection(const char *ssid, const char *pass) {
    ESP_LOGI(TAG, "Conectando a %s...", ssid);

    esp_netif_create_default_wifi_ap();

    wifi_config_t sta = {};
    strcpy((char *)sta.sta.ssid, ssid);
    strcpy((char *)sta.sta.password, pass);
    sta.sta.threshold.authmode = WIFI_AUTH_OPEN;

    wifi_config_t ap = {};
    strcpy((char *)ap.ap.ssid, AP_SSID);
    ap.ap.ssid_len = strlen(AP_SSID);
    ap.ap.max_connection = AP_MAX_CONN;
    ap.ap.authmode = WIFI_AUTH_OPEN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    ESP_ERROR_CHECK(esp_wifi_start());

    s_connected = xSemaphoreCreateBinary();

    esp_err_t ret = esp_wifi_connect();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_connect falhou: %d", ret);
    }

    return xSemaphoreTake(s_connected, pdMS_TO_TICKS(STA_TIMEOUT_MS)) == pdTRUE;
}

// =========================================================
//  ENTRY POINT
// =========================================================
extern "C" void app_main(void) {
    ESP_LOGI(TAG, "Iniciando Agente de Seguranca WiFi...");

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    led_init();
    led_set_rgb(0, 0, 255);

    esp_netif_t *netif = esp_netif_create_default_wifi_sta();
    assert(netif);
    esp_netif_set_hostname(netif, "esp32-agente");

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t conn_h, disc_h, ip_h;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED,
                    on_wifi_connect, netif, &conn_h));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED,
                    on_wifi_disconnect, netif, &disc_h));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                    on_got_ip, netif, &ip_h));

    char saved_ssid[64] = {}, saved_pass[64] = {};
    bool has_creds = load_wifi_creds(saved_ssid, sizeof(saved_ssid), saved_pass, sizeof(saved_pass));

    gpio_set_direction(GPIO_NUM_9, GPIO_MODE_INPUT);
    gpio_set_pull_mode(GPIO_NUM_9, GPIO_PULLUP_ONLY);
    bool boot_held = false;
    ESP_LOGI(TAG, "Pressione BOOT nos proximos 3s para limpar credenciais...");
    for (int i = 0; i < 30; i++) {
        if (gpio_get_level(GPIO_NUM_9) == 0) {
            boot_held = true;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (boot_held) {
        ESP_LOGW(TAG, "BOOT pressionado - limpando credenciais");
        has_creds = false;
        nvs_handle_t h;
        if (nvs_open(WIFI_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
            nvs_erase_all(h);
            nvs_commit(h);
            nvs_close(h);
        }
    }

    bool connected = false;
    if (has_creds) {
        ESP_LOGI(TAG, "Credenciais encontradas na NVS");
        ESP_LOGI(TAG, "Conectando a SSID: %s", saved_ssid);
        connected = try_sta_connection(saved_ssid, saved_pass);
        if (connected) {
            ESP_LOGI(TAG, "Conectado ao Wi-Fi!");
            led_set_rgb(0, 255, 0);
            s_report_mutex = xSemaphoreCreateMutex();
            s_server = start_webserver();
        } else {
            ESP_LOGW(TAG, "Falha ao conectar em '%s', iniciando portal...", saved_ssid);
            led_set_rgb(255, 100, 0);
        }
    } else {
        ESP_LOGW(TAG, "Nenhuma credencial salva, iniciando portal...");
        led_set_rgb(255, 100, 0);
    }

    if (connected) {
        s_wifi_online = true;
        led_set_rgb(0, 255, 0);

        ESP_LOGI(TAG, "Ativando modo promiscuo...");
        ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
        ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_cb));
        xTaskCreate(monitor_task, "monitor", 4096, NULL, 5, NULL);
        ESP_LOGI(TAG, "Agente operacional!");
    } else {
        start_ap_portal();
    }
}

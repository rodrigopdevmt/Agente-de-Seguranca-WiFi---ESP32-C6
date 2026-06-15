#!/usr/bin/env python3
import json, threading, time, os, sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
SERIAL_PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"

state = {
    "mgmt": 0, "deauth": 0, "disassoc": 0,
    "attackers": 0, "wifi": "off",
    "attack": None, "attacker_list": [],
    "history": [], "last_event": 0
}
state_lock = threading.Lock()

# --- SERIAL READER ---
def serial_reader():
    global state
    import serial
    while True:
        try:
            ser = serial.Serial(SERIAL_PORT, 115200, timeout=2)
            ser.setDTR(False)
            time.sleep(0.1)
            ser.setDTR(True)
            print(f"[server] Conectado a {SERIAL_PORT}")
            break
        except Exception as e:
            print(f"[server] Aguardando serial ({e})...")
            time.sleep(2)

    buf = b""
    while True:
        try:
            c = ser.read(1)
            if c:
                buf += c
                if c == b"\n":
                    line = buf.decode("utf-8", errors="replace").strip()
                    buf = b""
                    if line.startswith("{"):
                        try:
                            process_json(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except Exception:
            time.sleep(1)

def process_json(j):
    global state
    with state_lock:
        if j.get("t") == "report":
            state["mgmt"] = j.get("mgmt", 0)
            state["deauth"] = j.get("deauth", 0)
            state["disassoc"] = j.get("disassoc", 0)
            state["attackers"] = j.get("attackers", 0)
            state["wifi"] = j.get("wifi", "off")
            state["attack"] = None
        elif j.get("t") == "attack":
            now = time.time()
            state["attack"] = j
            state["last_event"] = now
            state["history"].append({
                "time": now, "type": "attack",
                "mac": j.get("mac", ""),
                "reason": j.get("reason", 0),
                "channel": j.get("channel", 0)
            })
            if len(state["history"]) > 200:
                state["history"] = state["history"][-200:]
        elif j.get("t") == "attackers":
            state["attacker_list"] = j.get("list", [])

# --- HTTP HANDLER ---
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/data":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            with state_lock:
                self.wfile.write(json.dumps(state).encode())
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML.encode())

    def log_message(self, *a):
        pass

# --- DASHBOARD HTML ---
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi Security Agent</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0a0a0f;color:#e0e0e0;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:20px}
h1{font-size:1.4rem;font-weight:300;letter-spacing:4px;text-transform:uppercase;color:rgba(255,255,255,.3);margin:10px 0 20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;width:100%;max-width:900px;margin-bottom:20px}
.card{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:16px;backdrop-filter:blur(12px);text-align:center;transition:all .3s}
.card:hover{border-color:rgba(255,255,255,.12);transform:translateY(-1px)}
.card .label{font-size:.65rem;text-transform:uppercase;letter-spacing:2px;color:rgba(255,255,255,.3);margin-bottom:6px}
.card .value{font-size:1.8rem;font-weight:600;font-variant-numeric:tabular-nums}
.card .value.green{color:#00ff88}
.card .value.yellow{color:#ffd700}
.card .value.red{color:#ff3355}
.card .value.orange{color:#ff8800}
.card .value.blue{color:#4499ff}
.wifi-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}
.wifi-dot.on{background:#00ff88;box-shadow:0 0 8px #00ff8866}
.wifi-dot.off{background:#ff3355;box-shadow:0 0 8px #ff335566}
.panels{display:grid;grid-template-columns:1fr 1fr;gap:14px;width:100%;max-width:900px}
@media(max-width:640px){.panels{grid-template-columns:1fr}}
.panel{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:16px;backdrop-filter:blur(12px);min-height:200px}
.panel h2{font-size:.7rem;text-transform:uppercase;letter-spacing:2px;color:rgba(255,255,255,.3);margin-bottom:12px}
.attack-alert{background:rgba(255,51,85,.12);border:1px solid rgba(255,51,85,.25);border-radius:12px;padding:12px;margin-bottom:8px;animation:pulse 1.5s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
.attack-alert .mac{font-family:'SF Mono','Fira Code',monospace;color:#ff3355;font-size:.9rem}
.attack-alert .detail{font-size:.75rem;color:rgba(255,255,255,.4);margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:.75rem}
th{text-align:left;padding:6px 4px;color:rgba(255,255,255,.3);font-weight:400;letter-spacing:1px;text-transform:uppercase;font-size:.6rem}
td{padding:4px;border-top:1px solid rgba(255,255,255,.04);font-family:'SF Mono','Fira Code',monospace;font-size:.7rem}
tr:hover td{background:rgba(255,255,255,.03)}
#history{max-height:300px;overflow-y:auto;font-size:.7rem}
#history::-webkit-scrollbar{width:4px}
#history::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:2px}
.hist-item{padding:4px 0;border-bottom:1px solid rgba(255,255,255,.03);display:flex;justify-content:space-between}
.hist-item .h-time{color:rgba(255,255,255,.2);font-family:monospace;font-size:.6rem}
.hist-item .h-mac{color:#ff3355;font-family:monospace}
.hist-item .h-ok{color:#00ff88}
footer{font-size:.6rem;color:rgba(255,255,255,.15);margin-top:20px;letter-spacing:1px}
.status-bar{display:flex;gap:12px;align-items:center;margin-bottom:16px;font-size:.75rem;color:rgba(255,255,255,.3)}
.chart-bar{display:flex;align-items:center;gap:8px;margin-top:6px}
.chart-bar .bar{flex:1;height:6px;background:rgba(255,255,255,.05);border-radius:3px;overflow:hidden}
.chart-bar .bar-fill{height:100%;border-radius:3px;transition:width .5s ease}.bar-deauth{background:#ff3355}.bar-disassoc{background:#ff8800}.bar-mgmt{background:#4499ff}
</style>
</head>
<body>

<h1>&#x25C8; WiFi Security Agent</h1>

<div class="status-bar">
<span><span class="wifi-dot" id="wifiDot">&#x25CF;</span> Wi-Fi: <span id="wifiStatus">off</span></span>
</div>

<div class="grid">
  <div class="card">
    <div class="label">Management Frames</div>
    <div class="value blue" id="mgmtVal">0</div>
  </div>
  <div class="card">
    <div class="label">Deauth</div>
    <div class="value red" id="deauthVal">0</div>
  </div>
  <div class="card">
    <div class="label">Disassoc</div>
    <div class="value orange" id="disassocVal">0</div>
  </div>
  <div class="card">
    <div class="label">Attackers</div>
    <div class="value yellow" id="attackersVal">0</div>
  </div>
</div>

<div class="chart-bar">
<span style="font-size:.65rem;color:rgba(255,255,255,.3);min-width:50px">Deauth</span>
<div class="bar"><div class="bar-fill bar-deauth" id="barDeauth" style="width:0%"></div></div>
<span class="value red" id="barDeauthVal" style="font-size:.7rem;min-width:30px">0</span>
</div>
<div class="chart-bar">
<span style="font-size:.65rem;color:rgba(255,255,255,.3);min-width:50px">Disassoc</span>
<div class="bar"><div class="bar-fill bar-disassoc" id="barDisassoc" style="width:0%"></div></div>
<span class="value orange" id="barDisassocVal" style="font-size:.7rem;min-width:30px">0</span>
</div>
<div class="chart-bar">
<span style="font-size:.65rem;color:rgba(255,255,255,.3);min-width:50px">Mgmt</span>
<div class="bar"><div class="bar-fill bar-mgmt" id="barMgmt" style="width:0%"></div></div>
<span class="value blue" id="barMgmtVal" style="font-size:.7rem;min-width:30px">0</span>
</div>

<div class="panels">
  <div class="panel">
    <h2>&#x25B6; Attackers</h2>
    <div id="alertArea"></div>
    <table><thead><tr><th>MAC</th><th>Count</th><th>Ch</th><th>Reason</th></tr></thead>
    <tbody id="attackerTable"></tbody></table>
  </div>
  <div class="panel">
    <h2>&#x25B6; History</h2>
    <div id="history"></div>
  </div>
</div>

<footer>ESP32-C6 &middot; Real-time</footer>

<script>
async function poll(){
  try{
    const r=await fetch('/data');
    const d=await r.json();
    update(d);
  }catch(e){}
  setTimeout(poll,1000);
}

function update(d){
  document.getElementById('mgmtVal').textContent=d.mgmt;
  document.getElementById('deauthVal').textContent=d.deauth;
  document.getElementById('disassocVal').textContent=d.disassoc;
  document.getElementById('attackersVal').textContent=d.attackers;

  const wifiDot=document.getElementById('wifiDot');
  const wifiStatus=document.getElementById('wifiStatus');
  if(d.wifi==='on'){
    wifiDot.className='wifi-dot on'; wifiStatus.textContent='Online';
  } else {
    wifiDot.className='wifi-dot off'; wifiStatus.textContent='Offline';
  }

  const maxVal=Math.max(d.mgmt, d.deauth, d.disassoc, 1);
  document.getElementById('barDeauth').style.width=Math.min(100,(d.deauth/maxVal)*100)+'%';
  document.getElementById('barDisassoc').style.width=Math.min(100,(d.disassoc/maxVal)*100)+'%';
  document.getElementById('barMgmt').style.width=Math.min(100,(d.mgmt/maxVal)*100)+'%';
  document.getElementById('barDeauthVal').textContent=d.deauth;
  document.getElementById('barDisassocVal').textContent=d.disassoc;
  document.getElementById('barMgmtVal').textContent=d.mgmt;

  if(d.attack){
    document.getElementById('alertArea').innerHTML=
      '<div class="attack-alert">'+
      '<div class="mac">&#x26A0; '+d.attack.mac+'</div>'+
      '<div class="detail">Reason: '+d.attack.reason+' &middot; Ch: '+d.attack.channel+' &middot; Count: '+d.attack.count+'</div>'+
      '</div>';
  }

  let tbody=document.getElementById('attackerTable');
  tbody.innerHTML='';
  if(d.attacker_list && d.attacker_list.length){
    d.attacker_list.forEach(function(a){
      let tr=document.createElement('tr');
      tr.innerHTML='<td>'+a.mac+'</td><td>'+a.count+'</td><td>'+a.channel+'</td><td>'+a.reason+'</td>';
      tbody.appendChild(tr);
    });
  } else {
    tbody.innerHTML='<tr><td colspan="4" style="color:rgba(255,255,255,.2);text-align:center;padding:20px">Nenhum atacante</td></tr>';
  }

  let history=document.getElementById('history');
  if(d.history && d.history.length){
    let h=d.history.slice().reverse();
    history.innerHTML=h.map(function(e){
      let t=new Date(e.time*1000).toLocaleTimeString('pt-BR');
      return '<div class="hist-item"><span class="h-mac">'+e.mac+'</span><span class="h-time">'+t+'</span></div>';
    }).join('');
  }
}

poll();
</script>
</body>
</html>"""

if __name__ == "__main__":
    t = threading.Thread(target=serial_reader, daemon=True)
    t.start()
    srv = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[server] Dashboard: http://localhost:{PORT}")
    srv.serve_forever()

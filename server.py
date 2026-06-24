#!/usr/bin/env python3
"""
server.py — Interfaz web para el Cifrador NASM.
Uso: python3 server.py [puerto]       (por defecto: 8080)
Sin dependencias externas (solo stdlib de Python 3).
"""

import os
import re
import sys
import json
import base64
import tempfile
import subprocess
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

BINARY = Path(__file__).parent / "cifrador"

# =============================================================================
# Página HTML (interfaz de usuario)
# =============================================================================

HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cifrador NASM</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#1e1e1e;color:#d4d4d4;font-family:'Segoe UI',Consolas,sans-serif;
     padding:32px;max-width:900px;margin:auto}
h1{color:#4ec9b0;font-size:1.5rem;margin-bottom:6px}
.sub{color:#858585;font-size:.85rem;margin-bottom:32px}
.card{background:#252526;border-radius:8px;padding:24px;margin-bottom:20px}
.card h2{color:#9cdcfe;font-size:.78rem;text-transform:uppercase;
          letter-spacing:.08em;margin-bottom:18px}
label{display:block;color:#9cdcfe;font-size:.82rem;margin-bottom:6px}
input[type=text]{
  width:100%;background:#3c3c3c;border:1px solid #555;border-radius:4px;
  color:#d4d4d4;padding:9px 12px;font-size:.95rem;outline:none}
input[type=text]:focus{border-color:#0e639c}
/* zona de arrastre */
.drop{border:2px dashed #555;border-radius:6px;padding:32px;text-align:center;
      cursor:pointer;transition:border-color .2s,background .2s}
.drop:hover,.drop.over{border-color:#4ec9b0;background:#2a2d2e}
.drop strong{display:block;color:#d4d4d4;font-size:1rem;margin-bottom:6px}
.drop span{color:#858585;font-size:.85rem}
input[type=file]{display:none}
/* grid opciones */
.row{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}
.modes{display:flex;gap:24px;margin-top:2px}
.modes label{display:flex;align-items:center;gap:8px;color:#d4d4d4;
             font-size:.95rem;cursor:pointer;text-transform:none;letter-spacing:0}
/* botones */
.actions{display:flex;align-items:center;gap:16px}
#btn-process{
  background:#0e639c;color:#fff;border:none;border-radius:4px;
  padding:10px 28px;font-size:.95rem;cursor:pointer}
#btn-process:hover{background:#1177bb}
#btn-process:disabled{background:#3c3c3c;color:#555;cursor:not-allowed}
#status{color:#858585;font-size:.88rem}
.err{color:#f48771;font-size:.88rem;margin-top:10px;min-height:1.2em}
/* resultados */
#results{display:none}
.ok-bar{display:flex;align-items:center;justify-content:space-between;
        flex-wrap:wrap;gap:12px}
.ok-bar span{color:#4ec9b0;font-weight:600}
.dl{display:inline-flex;align-items:center;gap:8px;background:#4ec9b0;
    color:#1e1e1e;font-weight:700;padding:9px 20px;border-radius:4px;
    text-decoration:none;font-size:.9rem}
.dl:hover{background:#3db99f}
iframe{width:100%;border:none;border-radius:6px;min-height:660px;
       margin-top:16px;background:#1e1e1e}
</style>
</head>
<body>

<h1>&#9651; Cifrador NASM</h1>
<p class="sub">Cifrado XOR &middot; Entrop&iacute;a de Shannon &middot; x86-64 Assembly</p>

<!-- Tarjeta: archivo -->
<div class="card">
  <h2>Archivo de entrada</h2>
  <div class="drop" id="drop" onclick="document.getElementById('file-in').click()">
    <input type="file" id="file-in">
    <strong id="drop-name">Haz clic o arrastra un archivo aqu&iacute;</strong>
    <span id="drop-size">cualquier tipo de archivo</span>
  </div>
</div>

<!-- Tarjeta: opciones -->
<div class="card">
  <h2>Opciones</h2>
  <div class="row">
    <div>
      <label for="key-in">Clave</label>
      <input type="text" id="key-in" placeholder="contrase&ntilde;a (hasta 8 bytes)">
    </div>
    <div>
      <label>Modo</label>
      <div class="modes">
        <label><input type="radio" name="mode" value="encrypt" checked> Cifrar</label>
        <label><input type="radio" name="mode" value="decrypt"> Descifrar</label>
      </div>
    </div>
  </div>
  <div class="actions">
    <button id="btn-process" onclick="runProcess()">Procesar</button>
    <span id="status"></span>
  </div>
  <p class="err" id="err-msg"></p>
</div>

<!-- Resultados -->
<div id="results">
  <div class="card">
    <div class="ok-bar">
      <span>&#10003; Procesado correctamente</span>
      <a id="dl-link" class="dl" href="#">&#11015; Descargar archivo</a>
    </div>
  </div>
  <iframe id="report-frame" title="Reporte HTML"></iframe>
</div>

<script>
// ── Drag & drop / file picker ────────────────────────────────────────────────
let selectedFile = null;
const drop = document.getElementById('drop');
const fileIn = document.getElementById('file-in');

fileIn.addEventListener('change', () => { if (fileIn.files[0]) pick(fileIn.files[0]); });
drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', e => {
  e.preventDefault(); drop.classList.remove('over');
  if (e.dataTransfer.files[0]) pick(e.dataTransfer.files[0]);
});
function pick(f) {
  selectedFile = f;
  document.getElementById('drop-name').textContent = f.name;
  const kb = (f.size / 1024).toFixed(1);
  document.getElementById('drop-size').textContent = kb + ' KB';
}

// ── Envío al servidor ────────────────────────────────────────────────────────
async function runProcess() {
  const key  = document.getElementById('key-in').value.trim();
  const mode = document.querySelector('input[name=mode]:checked').value;
  const err  = document.getElementById('err-msg');
  const st   = document.getElementById('status');
  const btn  = document.getElementById('btn-process');

  err.textContent = '';
  document.getElementById('results').style.display = 'none';

  if (!selectedFile) { err.textContent = 'Selecciona un archivo primero.'; return; }
  if (!key)          { err.textContent = 'Ingresa una clave.'; return; }

  btn.disabled = true;
  st.textContent = 'Procesando…';

  const fd = new FormData();
  fd.append('file', selectedFile, selectedFile.name);
  fd.append('key',  key);
  fd.append('mode', mode);

  try {
    const resp = await fetch('/process', { method: 'POST', body: fd });
    const data = await resp.json();

    if (!data.success) { err.textContent = 'Error: ' + data.error; return; }

    // crear URL de descarga desde base64
    const bytes = Uint8Array.from(atob(data.output_b64), c => c.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes]));
    const a = document.getElementById('dl-link');
    a.href     = url;
    a.download = data.filename;

    // incrustar reporte
    document.getElementById('report-frame').srcdoc = data.report_html;

    document.getElementById('results').style.display = 'block';
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
    st.textContent = '';
  } catch (e) {
    err.textContent = 'Error de red: ' + e.message;
  } finally {
    btn.disabled = false;
  }
}
</script>
</body>
</html>
"""


# =============================================================================
# Parser multipart sin módulo cgi (removido en Python 3.13)
# =============================================================================

def parse_multipart(data: bytes, boundary: str) -> dict:
    """Devuelve {name: (filename_o_None, bytes_del_cuerpo)}."""
    sep = ('--' + boundary).encode()
    fields = {}
    for part in data.split(sep)[1:]:
        if part.startswith(b'--'):        # delimitador final
            break
        if b'\r\n\r\n' not in part:
            continue
        raw_hdrs, body = part.split(b'\r\n\r\n', 1)
        if body.endswith(b'\r\n'):
            body = body[:-2]
        disp = ''
        for line in raw_hdrs.split(b'\r\n'):
            if line.lower().startswith(b'content-disposition:'):
                disp = line.decode('utf-8', errors='replace')
        m_name = re.search(r'name="([^"]*)"', disp)
        m_file = re.search(r'filename="([^"]*)"', disp)
        if m_name:
            fields[m_name.group(1)] = (
                m_file.group(1) if m_file else None,
                body,
            )
    return fields


# =============================================================================
# Handler HTTP
# =============================================================================

class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  {self.address_string()}  {fmt % args}")

    # GET / → servir la página HTML
    def do_GET(self):
        if self.path in ('/', '/index.html'):
            body = HTML.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    # POST /process → cifrar/descifrar
    def do_POST(self):
        if self.path != '/process':
            self.send_error(404)
            return

        ctype = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in ctype:
            self._json_error('Content-Type debe ser multipart/form-data')
            return

        m = re.search(r'boundary=([^\s;]+)', ctype)
        if not m:
            self._json_error('Falta boundary en Content-Type')
            return
        boundary = m.group(1).strip('"')

        length = int(self.headers.get('Content-Length', 0))
        raw    = self.rfile.read(length)
        fields = parse_multipart(raw, boundary)

        # extraer campos
        file_entry = fields.get('file')
        key_entry  = fields.get('key')
        mode_entry = fields.get('mode')

        if file_entry is None:
            self._json_error('Falta el campo "file"')
            return

        orig_name, file_bytes = file_entry
        key  = (key_entry[1]  if key_entry  else b'').decode('utf-8', errors='replace').strip()
        mode = (mode_entry[1] if mode_entry else b'encrypt').decode().strip()

        if not key:
            self._json_error('Clave vacía')
            return
        if mode not in ('encrypt', 'decrypt'):
            self._json_error('Modo inválido')
            return

        # nombre del archivo de salida
        base = orig_name or 'archivo'
        if mode == 'encrypt':
            out_name = base + '.enc'
        else:
            stripped = re.sub(r'\.enc$', '', base, flags=re.IGNORECASE)
            out_name = stripped if stripped and stripped != base else base + '_dec'

        # ejecutar el cifrador en directorio temporal
        with tempfile.TemporaryDirectory() as tmp:
            in_path  = os.path.join(tmp, 'input')
            out_path = os.path.join(tmp, 'output')

            with open(in_path, 'wb') as f:
                f.write(file_bytes)

            try:
                proc = subprocess.run(
                    [str(BINARY), mode, in_path, out_path, key],
                    capture_output=True, timeout=30, cwd=tmp,
                )
            except subprocess.TimeoutExpired:
                self._json_error('El cifrador tardó demasiado')
                return
            except FileNotFoundError:
                self._json_error(f'Binario no encontrado: {BINARY}')
                return

            if proc.returncode != 0:
                stderr = proc.stderr.decode('utf-8', errors='replace').strip()
                self._json_error(f'Error del cifrador (código {proc.returncode}): {stderr}')
                return

            if not os.path.exists(out_path):
                self._json_error('El cifrador no generó archivo de salida')
                return

            with open(out_path, 'rb') as f:
                out_bytes = f.read()

            # leer reporte HTML generado en el directorio temporal
            report_html = ''
            rpt_path = os.path.join(tmp, 'reporte.html')
            if os.path.exists(rpt_path):
                with open(rpt_path, encoding='utf-8', errors='replace') as f:
                    report_html = f.read()

        payload = json.dumps({
            'success':    True,
            'output_b64': base64.b64encode(out_bytes).decode(),
            'filename':   out_name,
            'report_html': report_html,
        }).encode()

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def _json_error(self, msg: str):
        payload = json.dumps({'success': False, 'error': msg}).encode()
        self.send_response(400)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(payload))
        self.end_headers()
        self.wfile.write(payload)


# =============================================================================
# Punto de entrada
# =============================================================================

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    srv  = HTTPServer(('0.0.0.0', port), Handler)
    print(f'\n  Cifrador NASM — servidor web')
    print(f'  Abre en el navegador:  http://localhost:{port}\n')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\n  Servidor detenido.')

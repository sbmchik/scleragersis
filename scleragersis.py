import os
import json
import struct
import base64
from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

MAGIC_BYTES = b"HIMORPS0"
VERSION = 2
ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))

def pack_himorps0(data_dict: dict, password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    
    payload_json = json.dumps(data_dict, ensure_ascii=False).encode('utf-8')
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, payload_json, None)
    
    header = struct.pack(">8sH16s12sQ", MAGIC_BYTES, VERSION, salt, nonce, len(ciphertext))
    return header + ciphertext

def unpack_himorps0(raw_data: bytes, password: str) -> dict:
    header_size = struct.calcsize(">8sH16s12sQ")
    if len(raw_data) < header_size:
        raise ValueError("Файл слишком мал для контейнера .himorps0")
    
    magic, ver, salt, nonce, payload_len = struct.unpack(">8sH16s12sQ", raw_data[:header_size])
    if magic != MAGIC_BYTES:
        raise ValueError("Неверный формат файла: отсутствует сигнатура HIMORPS0")
    
    key = derive_key(password, salt)
    ciphertext = raw_data[header_size:header_size + payload_len]
    
    aesgcm = AESGCM(key)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(decrypted_data.decode('utf-8'))

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/export', methods=['POST'])
def export_vault():
    req = request.json
    password = req.get('password')
    vault_data = req.get('vault')
    
    if not password or not vault_data:
        return jsonify({"error": "Пароль и данные обязательны"}), 400
        
    binary_data = pack_himorps0(vault_data, password)
    b64_output = base64.b64encode(binary_data).decode('utf-8')
    return jsonify({"file_data": b64_output, "filename": "memory_vault.himorps0"})

@app.route('/api/import', methods=['POST'])
def import_vault():
    req = request.json
    password = req.get('password')
    file_b64 = req.get('file_data')
    
    try:
        raw_data = base64.b64decode(file_b64)
        vault_data = unpack_himorps0(raw_data, password)
        return jsonify({"vault": vault_data})
    except Exception as e:
        return jsonify({"error": f"Ошибка расшифровки: {str(e)}"}), 400

# --- ИНТЕРФЕЙС (ДИЗАЙН V1 + ФУНКЦИИ V2) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>HIMORPS0 Memory Archive</title>
    <style>
        /* BASE & MODERN THEME (V1) */
        :root {
            --bg-color: #0f111a;
            --panel-bg: #1a1d2e;
            --text-color: #e2e8f0;
            --accent: #6366f1;
            --border: 1px solid #334155;
            --radius: 8px;
            --font: 'Segoe UI', Tahoma, sans-serif;
            --transform-skew: none;
            --box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }

        /* Y2K UNDERGROUND / JANKY THEME (V1) */
        body.theme-y2k {
            --bg-color: #000022;
            --panel-bg: #000000;
            --text-color: #00ff66;
            --accent: #ff007f;
            --border: 3px dashed #ff007f;
            --radius: 0px;
            --font: 'Courier New', monospace;
            --transform-skew: rotate(-0.7deg);
            --box-shadow: 5px 5px 0px #00ffff;
        }

        body.theme-y2k .crooked-box {
            clip-path: polygon(0% 2%, 98% 0%, 100% 97%, 1% 100%);
            border-style: solid;
            border-color: #00ff66;
        }

        body.theme-y2k button {
            transform: rotate(1deg);
            border: 2px solid #ffff00 !important;
            background: #ff007f !important;
            color: #fff !important;
            font-weight: bold;
            text-transform: uppercase;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: var(--font);
            margin: 0;
            padding: 20px;
            transition: all 0.2s ease;
        }

        .container { max-width: 1000px; margin: 0 auto; }

        .header {
            display: flex; justify-content: space-between; align-items: center;
            border-bottom: 2px solid var(--accent); padding-bottom: 15px; margin-bottom: 20px;
        }

        .panel {
            background: var(--panel-bg); border: var(--border); border-radius: var(--radius);
            padding: 20px; margin-bottom: 20px; transform: var(--transform-skew);
            box-shadow: var(--box-shadow); transition: all 0.3s ease;
        }

        /* FORM CONTROLS */
        input, textarea, select, button {
            background: rgba(255,255,255,0.05); border: var(--border); color: var(--text-color);
            padding: 10px; margin: 5px 0; width: 100%; box-sizing: border-box; font-family: var(--font);
        }
        button { cursor: pointer; background: var(--accent); color: #fff; border: none; font-weight: 600; }
        button:hover { filter: brightness(1.2); }

        .flex-row { display: flex; gap: 10px; align-items: center; }
        .flex-col { flex: 1; }

        /* TIMELINE (DOTS) */
        .timeline-wrapper { position: relative; margin: 40px 0 20px 0; padding: 10px 0; }
        .timeline-axis { width: 100%; height: 4px; background: var(--text-color); position: relative; border-radius: 2px; }
        
        .timeline-dot {
            position: absolute; top: -6px; width: 14px; height: 14px;
            background: var(--bg-color); border: 3px solid var(--accent);
            border-radius: 50%; cursor: pointer; transform: translateX(-50%);
            transition: all 0.2s ease; z-index: 2;
        }
        .timeline-dot:hover { scale: 1.6; background: var(--accent); box-shadow: 0 0 10px var(--accent); z-index: 3; }

        /* MEMORY LIST */
        .memory-card {
            border-left: 4px solid var(--accent); margin-bottom: 15px; padding: 15px;
            background: rgba(255,255,255,0.02); transition: background 0.3s;
        }
        .tag {
            display: inline-block; font-size: 12px; padding: 3px 8px;
            background: var(--accent); color: #fff; margin-right: 5px; margin-bottom: 10px; border-radius: var(--radius);
        }

        /* LIGHTBOX VIEWER */
        .lightbox {
            display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.85); z-index: 9999; justify-content: center; align-items: center; flex-direction: column;
            backdrop-filter: blur(5px);
        }
        .lightbox img {
            max-width: 90%; max-height: 85%; border: var(--border); border-radius: var(--radius);
            box-shadow: var(--box-shadow);
        }
        .lightbox-close { color: #fff; margin-top: 15px; font-weight: bold; cursor: pointer; padding: 10px; background: rgba(0,0,0,0.5); }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>[ HIMORPS0 :: VAULT ]</h1>
        <div>
            <button onclick="toggleTheme()" style="width: auto; padding: 10px 20px;">Сменить тему (Y2K / Modern)</button>
        </div>
    </div>

    <!-- УПРАВЛЕНИЕ АРХИВОМ -->
    <div class="panel crooked-box">
        <h3 style="margin-top:0;">Управление крипто-контейнером (.himorps0)</h3>
        <div class="flex-row">
            <input type="password" id="vaultPassword" placeholder="Мастер-пароль AES-256">
            <button onclick="exportVault()">Запаковать .himorps0</button>
            <input type="file" id="importFile" onchange="importVault(event)" style="display:none">
            <button onclick="document.getElementById('importFile').click()">Загрузить .himorps0</button>
        </div>
    </div>

    <!-- ТАЙМЛАЙН -->
    <div class="panel crooked-box">
        <h3 style="margin-top:0;">Шкала времени</h3>
        <div class="flex-row">
            <div class="flex-col">
                <label style="font-size: 12px;">Дата рождения (Старт оси):</label>
                <input type="date" id="birthDate" value="2000-01-01" onchange="renderTimeline()">
            </div>
            <div class="flex-col">
                <label style="font-size: 12px;">Фильтр С (период):</label>
                <input type="datetime-local" id="filterFrom" onchange="renderList()">
            </div>
            <div class="flex-col">
                <label style="font-size: 12px;">Фильтр ПО (период):</label>
                <input type="datetime-local" id="filterTo" onchange="renderList()">
            </div>
        </div>

        <div class="timeline-wrapper">
            <div class="timeline-axis" id="timelineAxis">
                <!-- Точки генерируются JS -->
            </div>
        </div>
    </div>

    <!-- НОВОЕ ВОСПОМИНАНИЕ -->
    <div class="panel crooked-box">
        <h3 style="margin-top:0;">Новое воспоминание</h3>
        <input type="text" id="memTitle" placeholder="Заголовок / Ключевой фактор">
        <textarea id="memText" rows="3" placeholder="Текст воспоминания..."></textarea>
        
        <div class="flex-row">
            <div class="flex-col">
                <label style="font-size: 12px;">Дата и Точное время:</label>
                <input type="datetime-local" id="memDateTime" step="1">
            </div>
            <div class="flex-col">
                <label style="font-size: 12px;">Погрешность (число):</label>
                <input type="number" id="memMarginVal" placeholder="± 0" value="0">
            </div>
            <div class="flex-col">
                <label style="font-size: 12px;">Единица погрешности:</label>
                <select id="memMarginUnit">
                    <option value="exact">Точно (без погрешности)</option>
                    <option value="days">Дней (±)</option>
                    <option value="months">Месяцев (±)</option>
                    <option value="years">Лет (±)</option>
                </select>
            </div>
        </div>
        
        <label style="font-size: 12px; margin-top: 10px; display: block;">Прикрепить медиа (картинки, аудио, файлы):</label>
        <input type="file" id="memAttachments" multiple>

        <button onclick="addMemory()" style="margin-top: 15px; padding: 15px;">Зафиксировать Воспоминание в памяти</button>
    </div>

    <!-- ЛЕНТА ВОСПОМИНАНИЙ -->
    <div class="panel crooked-box">
        <h3 style="margin-top:0;">Архив записей</h3>
        <div id="memoryList"></div>
    </div>
</div>

<!-- LIGHTBOX VIEWER -->
<div class="lightbox" id="lightbox" onclick="closeLightbox()">
    <img id="lightboxImg" src="" onclick="event.stopPropagation()">
    <div class="lightbox-close">[ Нажмите в любом месте, чтобы закрыть ]</div>
</div>

<script>
    let vault = [];

    function toggleTheme() {
        document.body.classList.toggle('theme-y2k');
    }

    function addMemory() {
        const title = document.getElementById('memTitle').value;
        const text = document.getElementById('memText').value;
        const dt = document.getElementById('memDateTime').value;
        const marginVal = document.getElementById('memMarginVal').value;
        const marginUnit = document.getElementById('memMarginUnit').value;
        const files = document.getElementById('memAttachments').files;

        if (!dt) return alert('Укажите хотя бы дату и время!');

        const attachments = [];
        let loaded = 0;

        if (files.length === 0) {
            saveEntry();
        } else {
            for (let f of files) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    attachments.push({ name: f.name, type: f.type, data: e.target.result });
                    loaded++;
                    if (loaded === files.length) saveEntry();
                };
                reader.readAsDataURL(f);
            }
        }

        function saveEntry() {
            vault.push({
                id: Date.now(),
                title,
                text,
                datetime: dt,
                marginVal: parseInt(marginVal) || 0,
                marginUnit,
                attachments
            });
            render();
            document.getElementById('memTitle').value = '';
            document.getElementById('memText').value = '';
            document.getElementById('memAttachments').value = '';
        }
    }

    function render() {
        renderTimeline();
        renderList();
    }

    function renderTimeline() {
        const axis = document.getElementById('timelineAxis');
        axis.innerHTML = '';

        const birthStr = document.getElementById('birthDate').value;
        const birthTime = new Date(birthStr).getTime();
        const nowTime = new Date().getTime();
        const totalDuration = nowTime - birthTime;

        vault.forEach(m => {
            const mTime = new Date(m.datetime).getTime();
            if (mTime >= birthTime && mTime <= nowTime) {
                const pct = ((mTime - birthTime) / totalDuration) * 100;
                const dot = document.createElement('div');
                dot.className = 'timeline-dot';
                dot.style.left = `${pct}%`;
                dot.title = `${m.title || 'Запись'} (${m.datetime})`;
                dot.onclick = () => scrollToCard(m.id);
                axis.appendChild(dot);
            }
        });
    }

    function renderList() {
        const list = document.getElementById('memoryList');
        list.innerHTML = '';

        const fromVal = document.getElementById('filterFrom').value;
        const toVal = document.getElementById('filterTo').value;

        const fromTime = fromVal ? new Date(fromVal).getTime() : 0;
        const toTime = toVal ? new Date(toVal).getTime() : Infinity;

        const sorted = [...vault].sort((a,b) => new Date(b.datetime) - new Date(a.datetime));

        sorted.forEach(m => {
            const mTime = new Date(m.datetime).getTime();
            if (mTime < fromTime || mTime > toTime) return;

            const card = document.createElement('div');
            card.className = 'memory-card';
            card.id = `card-${m.id}`;

            let marginText = m.marginUnit !== 'exact' ? ` (± ${m.marginVal} ${m.marginUnit})` : '';

            let mediaHTML = m.attachments.map(f => {
                if (f.type.startsWith('image/')) {
                    return `<img src="${f.data}" style="max-height: 200px; cursor:pointer; margin: 10px 10px 0 0; border: var(--border); border-radius: var(--radius);" onclick="openLightbox('${f.data}')">`;
                } else if (f.type.startsWith('audio/')) {
                    return `<div style="margin-top:10px;"><audio controls src="${f.data}"></audio></div>`;
                }
                return `<div style="margin-top:10px;">📎 <a href="${f.data}" download="${f.name}" style="color: var(--accent);">${f.name}</a></div>`;
            }).join('');

            card.innerHTML = `
                <h3 style="margin:0 0 10px 0;">${m.title || 'Без темы'}</h3>
                <div>
                    <span class="tag">⏱ ${m.datetime.replace('T', ' ')}</span>
                    ${m.marginUnit !== 'exact' ? `<span class="tag">Погрешность: ±${m.marginVal}${m.marginUnit}</span>` : ''}
                </div>
                <p style="margin: 10px 0; line-height: 1.5;">${m.text}</p>
                <div>${mediaHTML}</div>
            `;
            list.appendChild(card);
        });
    }

    function scrollToCard(id) {
        const el = document.getElementById(`card-${id}`);
        if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            el.style.backgroundColor = 'rgba(99, 102, 241, 0.2)';
            setTimeout(() => el.style.backgroundColor = '', 1000);
        }
    }

    function openLightbox(src) {
        document.getElementById('lightboxImg').src = src;
        document.getElementById('lightbox').style.display = 'flex';
    }

    function closeLightbox() {
        document.getElementById('lightbox').style.display = 'none';
    }

    async function exportVault() {
        const password = document.getElementById('vaultPassword').value;
        if (!password) return alert('Введите мастер-пароль!');

        const res = await fetch('/api/export', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ vault, password })
        });

        const data = await res.json();
        if (data.file_data) {
            const a = document.createElement('a');
            a.href = 'data:application/octet-stream;base64,' + data.file_data;
            a.download = data.filename;
            a.click();
        }
    }

    async function importVault(event) {
        const file = event.target.files[0];
        const password = document.getElementById('vaultPassword').value;
        if (!file || !password) return alert('Выберите файл и введите пароль!');

        const reader = new FileReader();
        reader.onload = async (e) => {
            const b64 = e.target.result.split(',')[1];
            const res = await fetch('/api/import', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ file_data: b64, password })
            });
            const data = await res.json();
            if (data.vault) {
                vault = data.vault;
                render();
                alert('Контейнер .himorps0 успешно расшифрован!');
            } else {
                alert(data.error || 'Ошибка загрузки. Проверьте пароль.');
            }
        };
        reader.readAsDataURL(file);
    }
</script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True, port=5000)
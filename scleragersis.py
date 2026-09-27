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
        raise ValueError("Файл повреждён или имеет неверный размер.")
    
    magic, ver, salt, nonce, payload_len = struct.unpack(">8sH16s12sQ", raw_data[:header_size])
    if magic != MAGIC_BYTES:
        raise ValueError("Ошибка сигнатуры: файл не является контейнером HIMORPS0")
    
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
    binary_data = pack_himorps0(vault_data, password)
    b64_output = base64.b64encode(binary_data).decode('utf-8')
    return jsonify({"file_data": b64_output, "filename": "memory_archive.himorps0"})

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
        return jsonify({"error": f"Ошибка доступа: {str(e)}"}), 400

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>HIMORPS0 :: REPACKER EDITION</title>
    <style>
        :root {
            --bg: #050508;
            --panel: #0d0e15;
            --border: #ff0055;
            --text: #00ffcc;
            --accent: #ff0055;
            --yellow: #ffe600;
            --font: 'Courier New', monospace;
        }

        body.theme-y2k {
            --bg: #020202;
            --panel: #090a10;
            --border: #00ff66;
            --text: #00ff66;
            --accent: #ff007f;
            --yellow: #ffff00;
        }

        body {
            background-color: var(--bg);
            color: var(--text);
            font-family: var(--font);
            margin: 0;
            padding: 15px;
            box-sizing: border-box;
        }

        .installer-window {
            border: 3px double var(--border);
            box-shadow: 6px 6px 0px rgba(255,0,85,0.3);
            background: var(--panel);
            padding: 15px;
            margin-bottom: 20px;
            position: relative;
        }

        .crooked {
            clip-path: polygon(0% 1%, 99% 0%, 100% 98%, 1% 100%);
        }

        .title-bar {
            background: var(--border);
            color: #000;
            padding: 4px 8px;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            margin: -15px -15px 15px -15px;
            text-transform: uppercase;
        }

        /* TIMELINE WITH DOTS */
        .timeline-wrapper {
            position: relative;
            margin: 30px 0;
            padding: 10px 0;
        }

        .timeline-axis {
            width: 100%;
            height: 4px;
            background: var(--text);
            position: relative;
        }

        .timeline-dot {
            position: absolute;
            top: -6px;
            width: 14px;
            height: 14px;
            background: var(--yellow);
            border: 2px solid #000;
            border-radius: 50%;
            cursor: pointer;
            transform: translateX(-50%);
            transition: all 0.2s;
        }

        .timeline-dot:hover {
            scale: 1.5;
            background: var(--accent);
            box-shadow: 0 0 10px var(--accent);
        }

        /* INPUTS & BUTTONS */
        input, textarea, select, button {
            background: #000;
            border: 1px solid var(--text);
            color: var(--text);
            padding: 8px;
            font-family: var(--font);
            box-sizing: border-box;
        }

        button {
            background: var(--border);
            color: #000;
            font-weight: bold;
            cursor: pointer;
            border: none;
            text-transform: uppercase;
        }

        button:hover {
            filter: brightness(1.3);
        }

        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; }

        /* LIGHTBOX (IMAGE VIEWER) */
        .lightbox {
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 9999;
            justify-content: center;
            align-items: center;
            flex-direction: column;
        }

        .lightbox img {
            max-width: 85%;
            max-height: 80%;
            border: 4px solid var(--border);
            box-shadow: 0 0 20px var(--border);
        }

        .memory-card {
            border-left: 3px solid var(--yellow);
            padding: 10px;
            margin-bottom: 15px;
            background: rgba(255,255,255,0.02);
        }
    </style>
</head>
<body class="theme-y2k">

<div class="installer-window crooked">
    <div class="title-bar">
        <span>HIMORPS0 :: REPACKER ARCHIVE SYSTEM v2</span>
        <button onclick="document.body.classList.toggle('theme-y2k')" style="padding:0 5px;">THEME</button>
    </div>

    <!-- КОНТЕЙНЕР ПАРОЛЯ -->
    <div class="grid-3" style="align-items: center;">
        <input type="password" id="vaultPassword" placeholder="Крипто-пароль (AES-256)">
        <button onclick="exportVault()">Упаковать в .himorPS0</button>
        <button onclick="document.getElementById('fileInput').click()">Открыть .himorPS0</button>
        <input type="file" id="fileInput" style="display:none" onchange="importVault(event)">
    </div>
</div>

<!-- НАСТРОЙКИ ТОЧКИ ОТСЧЕТА И ТАЙМЛАЙН -->
<div class="installer-window">
    <div class="title-bar"><span>Шкала времени (От Рождения до Настоящего моменты)</span></div>
    
    <div class="grid-3" style="margin-bottom: 15px;">
        <div>
            <label>Дата рождения:</label>
            <input type="date" id="birthDate" value="2000-01-01" onchange="renderTimeline()">
        </div>
        <div>
            <label>Фильтр С:</label>
            <input type="datetime-local" id="filterFrom" onchange="renderList()">
        </div>
        <div>
            <label>Фильтр ПО:</label>
            <input type="datetime-local" id="filterTo" onchange="renderList()">
        </div>
    </div>

    <div class="timeline-wrapper">
        <div class="timeline-axis" id="timelineAxis"></div>
    </div>
</div>

<!-- ФОРМА ДОБАВЛЕНИЯ -->
<div class="installer-window crooked">
    <div class="title-bar"><span>Запись Фактора / Воспоминания</span></div>
    
    <input type="text" id="memTitle" placeholder="Заголовок воспоминания / фактора" style="width:100%; margin-bottom: 10px;">
    <textarea id="memText" rows="3" placeholder="Описание, текст, мысли..." style="width:100%; margin-bottom: 10px;"></textarea>

    <div class="grid-3">
        <div>
            <label>Дата и Точное время:</label>
            <input type="datetime-local" id="memDateTime" step="1">
        </div>
        <div>
            <label>Погрешность (±):</label>
            <input type="number" id="memMarginVal" placeholder="Число..." value="0">
        </div>
        <div>
            <label>Единица погрешности:</label>
            <select id="memMarginUnit">
                <option value="exact">Точно (без погрешности)</option>
                <option value="days">Дней (±)</option>
                <option value="months">Месяцев (±)</option>
                <option value="years">Лет (±)</option>
            </select>
        </div>
    </div>

    <div style="margin-top: 10px;">
        <label>Прикрепить Медиа (Картинки / Голосовые):</label>
        <input type="file" id="memFiles" multiple style="width: 100%;">
    </div>

    <button onclick="addMemory()" style="width:100%; margin-top:15px; height: 40px;">Зафиксировать Воспоминание</button>
</div>

<!-- СПИСОК -->
<div class="installer-window">
    <div class="title-bar"><span>Архив Сохранений</span></div>
    <div id="memoryList"></div>
</div>

<!-- LIGHTBOX -->
<div class="lightbox" id="lightbox" onclick="closeLightbox()">
    <img id="lightboxImg" src="">
    <div style="color: #fff; margin-top: 10px;">[ Нажмите в любом месте, чтобы закрыть ]</div>
</div>

<script>
    let vault = [];

    function addMemory() {
        const title = document.getElementById('memTitle').value;
        const text = document.getElementById('memText').value;
        const dt = document.getElementById('memDateTime').value;
        const marginVal = document.getElementById('memMarginVal').value;
        const marginUnit = document.getElementById('memMarginUnit').value;
        const files = document.getElementById('memFiles').files;

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
                dot.title = `${m.title} (${m.datetime})`;
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
                    return `<img src="${f.data}" style="max-width: 150px; cursor:pointer; margin: 5px; border:1px solid var(--border)" onclick="openLightbox('${f.data}')">`;
                } else if (f.type.startsWith('audio/')) {
                    return `<div style="margin-top:5px;"><audio controls src="${f.data}"></audio></div>`;
                }
                return `<div>📎 <a href="${f.data}" download="${f.name}" style="color:var(--yellow)">${f.name}</a></div>`;
            }).join('');

            card.innerHTML = `
                <h3 style="margin:0; color:var(--yellow)">${m.title || 'Без темы'}</h3>
                <div style="font-size:11px; color:var(--text)">
                    ⏱ <b>${m.datetime.replace('T', ' ')}</b>${marginText}
                </div>
                <p style="margin: 8px 0;">${m.text}</p>
                <div>${mediaHTML}</div>
            `;
            list.appendChild(card);
        });
    }

    function scrollToCard(id) {
        const el = document.getElementById(`card-${id}`);
        if (el) el.scrollIntoView({ behavior: 'smooth' });
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
        if (!password) return alert('Введите пароль!');
        const res = await fetch('/api/export', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ vault, password })
        });
        const data = await res.json();
        const a = document.createElement('a');
        a.href = 'data:application/octet-stream;base64,' + data.file_data;
        a.download = data.filename;
        a.click();
    }

    async function importVault(e) {
        const password = document.getElementById('vaultPassword').value;
        const file = e.target.files[0];
        if (!password || !file) return alert('Пароль и файл обязательны!');

        const reader = new FileReader();
        reader.onload = async (evt) => {
            const b64 = evt.target.result.split(',')[1];
            const res = await fetch('/api/import', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ file_data: b64, password })
            });
            const data = await res.json();
            if (data.vault) {
                vault = data.vault;
                render();
                alert('Архив успешно расшифрован!');
            } else alert(data.error);
        };
        reader.readAsDataURL(file);
    }
</script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True, port=5000)
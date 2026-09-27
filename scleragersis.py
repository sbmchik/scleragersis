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
VERSION = 1
ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    """Генерация 256-битного AES-ключа из пароля через PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))

def pack_himorps0(data_dict: dict, password: str) -> bytes:
    """Упаковка и шифрование данных в бинарный контейнер .himorps0."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    
    payload_json = json.dumps(data_dict, ensure_ascii=False).encode('utf-8')
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, payload_json, None)
    
    # Формируем бинарный заголовок
    header = struct.pack(
        ">8sH16s12sQ",
        MAGIC_BYTES,
        VERSION,
        salt,
        nonce,
        len(ciphertext)
    )
    return header + ciphertext

def unpack_himorps0(raw_data: bytes, password: str) -> dict:
    """Распаковка и расшифровка контейнера .himorps0."""
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

# --- API Endpoints ---

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
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>HIMORPS0 Memory Archive</title>
    <style>
        /* BASE & MODERN THEME */
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

        /* Y2K UNDERGROUND / JANKY THEME */
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

        .container {
            max-width: 1000px;
            margin: 0 auto;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--accent);
            padding-bottom: 15px;
            margin-bottom: 20px;
        }

        .panel {
            background: var(--panel-bg);
            border: var(--border);
            border-radius: var(--radius);
            padding: 20px;
            margin-bottom: 20px;
            transform: var(--transform-skew);
            box-shadow: var(--box-shadow);
        }

        /* WAYBACK TIMELINE BAR CHART */
        .timeline-container {
            overflow-x: auto;
            padding: 10px 0;
        }

        .wayback-bar {
            display: flex;
            align-items: flex-end;
            gap: 4px;
            height: 100px;
            border-bottom: 2px solid var(--accent);
            padding-bottom: 5px;
        }

        .time-column {
            flex: 1;
            min-width: 25px;
            display: flex;
            flex-direction: column;
            align-items: center;
            font-size: 10px;
        }

        .bar {
            width: 100%;
            background: var(--accent);
            min-height: 2px;
            transition: height 0.3s;
            cursor: pointer;
        }

        .bar:hover {
            filter: brightness(1.5);
        }

        /* FORM CONTROLS */
        input, textarea, select, button {
            background: rgba(255,255,255,0.05);
            border: var(--border);
            color: var(--text-color);
            padding: 10px;
            margin: 5px 0;
            width: 100%;
            box-sizing: border-box;
            font-family: var(--font);
        }

        button {
            cursor: pointer;
            background: var(--accent);
            color: #fff;
            border: none;
            font-weight: 600;
        }

        .memory-card {
            border-left: 4px solid var(--accent);
            margin-bottom: 15px;
            padding: 10px 15px;
            background: rgba(255,255,255,0.02);
        }

        .tag {
            display: inline-block;
            font-size: 11px;
            padding: 2px 6px;
            background: var(--accent);
            color: #fff;
            margin-right: 5px;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>[ HIMORPS0 :: VAULT ]</h1>
        <div>
            <button onclick="toggleTheme()" style="width: auto;">Сменить тему (Y2K / Modern)</button>
        </div>
    </div>

    <!-- ИМПОРТ / ЭКСПОРТ КОНТЕЙНЕРА -->
    <div class="panel crooked-box">
        <h3>Управление крипто-контейнером (.himorps0)</h3>
        <div style="display: flex; gap: 10px;">
            <input type="password" id="vaultPassword" placeholder="Мастер-пароль AES-256">
            <button onclick="exportVault()">Запаковать .himorps0</button>
            <input type="file" id="importFile" onchange="importVault(event)" style="display:none">
            <button onclick="document.getElementById('importFile').click()">Загрузить .himorps0</button>
        </div>
    </div>

    <!-- ARCHIVE.ORG WAYBACK TIMELINE -->
    <div class="panel crooked-box">
        <h3>Таймлайн сохранений (Archive.org Style)</h3>
        <div class="timeline-container">
            <div class="wayback-bar" id="timelineBar">
                <!-- Заполняется динамически -->
            </div>
        </div>
    </div>

    <!-- ФОРМА ДОБАВЛЕНИЯ -->
    <div class="panel crooked-box">
        <h3>Новое воспоминание</h3>
        <input type="text" id="memTitle" placeholder="Заголовок / Ключевой фактор">
        <textarea id="memText" rows="3" placeholder="Текст воспоминания..."></textarea>
        
        <div style="display: flex; gap: 10px;">
            <input type="date" id="memDate">
            <select id="memPrecision">
                <option value="exact">Точная дата</option>
                <option value="month">Примерно (месяц)</option>
                <option value="year">Примерно (год)</option>
                <option value="era">Эпоха / Смутно</option>
            </select>
        </div>
        
        <label style="font-size: 12px; margin-top: 5px; display: block;">Прикрепить медиа (картинки, аудио, файлы):</label>
        <input type="file" id="memAttachments" multiple>

        <button onclick="addMemory()">Сохранить фактор в память</button>
    </div>

    <!-- СПИСОК ВОСПОМИНАНИЙ -->
    <div class="panel crooked-box">
        <h3>Лента записей</h3>
        <div id="memoryList"></div>
    </div>
</div>

<script>
    let vault = [];

    function toggleTheme() {
        document.body.classList.toggle('theme-y2k');
    }

    async function addMemory() {
        const title = document.getElementById('memTitle').value;
        const text = document.getElementById('memText').value;
        const date = document.getElementById('memDate').value || new Date().toISOString().split('T')[0];
        const precision = document.getElementById('memPrecision').value;
        const filesInput = document.getElementById('memAttachments');

        const attachments = [];
        for (let file of filesInput.files) {
            const b64 = await toBase64(file);
            attachments.push({ name: file.name, type: file.type, data: b64 });
        }

        const entry = {
            id: Date.now(),
            title,
            text,
            date,
            precision,
            attachments,
            created_at: new Date().toISOString()
        };

        vault.push(entry);
        render();
        // Сброс полей
        document.getElementById('memTitle').value = '';
        document.getElementById('memText').value = '';
    }

    function toBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.readAsDataURL(file);
            reader.onload = () => resolve(reader.result);
            reader.onerror = error => reject(error);
        });
    }

    function render() {
        renderTimeline();
        renderList();
    }

    function renderTimeline() {
        const barContainer = document.getElementById('timelineBar');
        barContainer.innerHTML = '';

        // Группировка по годам
        const countsByYear = {};
        vault.forEach(m => {
            const year = m.date.split('-')[0] || 'Unknown';
            countsByYear[year] = (countsByYear[year] || 0) + 1;
        });

        const years = Object.keys(countsByYear).sort();
        const maxCount = Math.max(...Object.values(countsByYear), 1);

        years.forEach(year => {
            const count = countsByYear[year];
            const heightPct = (count / maxCount) * 100;

            const col = document.createElement('div');
            col.className = 'time-column';
            col.innerHTML = `
                <div class="bar" style="height: ${heightPct}%;" title="${year}: ${count} записей"></div>
                <span>${year}</span>
                <span style="font-size: 8px; color: var(--accent);">${count}</span>
            `;
            barContainer.appendChild(col);
        });
    }

    function renderList() {
        const list = document.getElementById('memoryList');
        list.innerHTML = '';

        const sorted = [...vault].sort((a,b) => new Date(b.date) - new Date(a.date));

        sorted.forEach(m => {
            const card = document.createElement('div');
            card.className = 'memory-card';
            
            let filesHTML = m.attachments.map(f => {
                if(f.type.startsWith('image/')) {
                    return `<br><img src="${f.data}" style="max-width: 200px; margin-top: 5px; border: var(--border);">`;
                } else if(f.type.startsWith('audio/')) {
                    return `<br><audio controls src="${f.data}" style="margin-top: 5px;"></audio>`;
                }
                return `<br><a href="${f.data}" download="${f.name}">📎 ${f.name}</a>`;
            }).join('');

            card.innerHTML = `
                <h4>${m.title || 'Без названия'}</h4>
                <div>
                    <span class="tag">${m.date}</span>
                    <span class="tag">Точность: ${m.precision}</span>
                </div>
                <p>${m.text}</p>
                <div>${filesHTML}</div>
            `;
            list.appendChild(card);
        });
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
                alert(data.error || 'Ошибка загрузки');
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
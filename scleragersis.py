import os
import json
import struct
import base64
from flask import Flask, request, jsonify, render_template_string, Response
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

app = Flask(__name__)

# Ограничение размера HTTP-запроса (512 МБ)
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024 * 1024

MAGIC_BYTES = b"HIMORPS0"
VERSION = 4

def derive_key(password: str, salt: bytes) -> bytes:
    # Argon2id по рекомендациям RFC 9106
    kdf = Argon2id(
        salt=salt,
        length=32,          # Ключ AES-256
        iterations=3,       # Проходы
        lanes=4,            # Параллелизм
        memory_cost=65536,  # 64 MB RAM
    )
    return kdf.derive(password.encode('utf-8'))

def pack_himorps0(vault_data: dict, password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    
    memories = vault_data.get('memories', [])
    raw_files = vault_data.get('files', {}) # {file_id: {name, type, data}}
    
    file_metas = {}
    file_blobs_list = []
    
    # Сборка файлов в бинарный поток
    for fid, fobj in raw_files.items():
        data = fobj.get('data', '')
        if isinstance(data, str):
            if ',' in data:
                data = data.split(',', 1)[1]
            content = base64.b64decode(data)
        elif isinstance(data, bytes):
            content = data
        else:
            content = b''
        
        file_metas[fid] = {
            "name": str(fobj.get('name', '')),
            "type": str(fobj.get('type', '')),
            "size": len(content)
        }
        file_blobs_list.append(content)

    file_blobs = b''.join(file_blobs_list)

    manifest = {
        "memories": memories,
        "files": file_metas
    }
    
    json_bytes = json.dumps(manifest, ensure_ascii=False).encode('utf-8')
    json_len = len(json_bytes)
    
    # Структура payload
    payload = struct.pack(">I", json_len) + json_bytes + file_blobs
    ciphertext_len = len(payload) + 16  # Длина шифротекста вместе с 16-байтным тегом GCM
    
    # Канонический заголовок (46 байт)
    header = struct.pack(">8sH16s12sQ", MAGIC_BYTES, VERSION, salt, nonce, ciphertext_len)
    
    # Передаем весь заголовок целиком в качестве AAD
    header_aad = header
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, payload, header_aad)
    
    return header + ciphertext

def unpack_himorps0(raw_data: bytes, password: str) -> dict:
    header_size = struct.calcsize(">8sH16s12sQ")
    if len(raw_data) < header_size:
        raise ValueError("Файл слишком мал для контейнера .himorps0")
    
    header = raw_data[:header_size]
    magic, ver, salt, nonce, payload_len = struct.unpack(">8sH16s12sQ", header)
    
    if magic != MAGIC_BYTES:
        raise ValueError("Неверный формат файла: отсутствует сигнатура HIMORPS0")
    if ver != VERSION:
        raise ValueError(f"Неподдерживаемая версия файла: {ver}")
    
    key = derive_key(password, salt)
    ciphertext = raw_data[header_size:header_size + payload_len]
    if len(ciphertext) != payload_len:
        raise ValueError("Файл повреждён или передан не полностью")
    
    # Использование ровно прочитанного заголовка в качестве AAD
    header_aad = header
    
    aesgcm = AESGCM(key)
    try:
        payload = aesgcm.decrypt(nonce, ciphertext, header_aad)
    except InvalidTag:
        raise ValueError("Неверный пароль или данные контейнера повреждены")
    
    if len(payload) < 4:
        raise ValueError("Некорректная структура расшифрованных данных")
        
    json_len = struct.unpack(">I", payload[:4])[0]
    if len(payload) < 4 + json_len:
        raise ValueError("Ошибка чтения манифеста: недостаточно данных")
        
    json_bytes = payload[4:4+json_len]
    manifest = json.loads(json_bytes.decode('utf-8'))
    
    files_data = {}
    offset = 4 + json_len
    for fid, meta in manifest.get("files", {}).items():
        size = meta.get("size", 0)
        
        # Валидация типа и значения размера
        if not isinstance(size, int) or size < 0:
            raise ValueError(f"Некорректный размер файла {fid}: {size}")
            
        if offset + size > len(payload):
            raise ValueError(f"Ошибка чтения файла {fid}: выход за пределы данных")
            
        content = payload[offset:offset+size]
        b64_content = base64.b64encode(content).decode('utf-8')
        mime_type = meta.get("type", "application/octet-stream")
        files_data[fid] = {
            "name": meta.get("name", "unnamed"),
            "type": mime_type,
            "data": f"data:{mime_type};base64,{b64_content}"
        }
        offset += size
        
    # Проверка отсутствия хвостового мусора
    if offset != len(payload):
        raise ValueError("Лишние или потерянные данные в конце контейнера")
        
    return {
        "memories": manifest.get("memories", []),
        "files": files_data
    }

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/export', methods=['POST'])
def export_vault():
    req = request.get_json(silent=True) or {}
    password = req.get('password')
    vault_data = req.get('vault')
    
    if not password or not vault_data:
        return jsonify({"error": "Пароль и данные обязательны"}), 400
        
    try:
        binary_data = pack_himorps0(vault_data, password)
        # Отправляем бинарный файл напрямую без Base64 в HTTP-ответе
        response = Response(binary_data, mimetype='application/octet-stream')
        response.headers['Content-Disposition'] = 'attachment; filename="memory_vault.himorps0"'
        return response
    except Exception as e:
        return jsonify({"error": f"Ошибка упаковки: {str(e)}"}), 400

@app.route('/api/import', methods=['POST'])
def import_vault():
    # Импорт через FormData (прямая бинарная передача)
    password = request.form.get('password')
    file_obj = request.files.get('file')
    
    if not password or not file_obj:
        return jsonify({"error": "Пароль и файл обязательны"}), 400
        
    try:
        raw_data = file_obj.read()
        vault_data = unpack_himorps0(raw_data, password)
        return jsonify({"vault": vault_data})
    except Exception as e:
        return jsonify({"error": f"Ошибка расшифровки: {str(e)}"}), 400

# --- ИНТЕРФЕЙС ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>HIMORPS0 Memory Archive</title>
    <style>
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

        input, textarea, select, button {
            background: rgba(255,255,255,0.05); border: var(--border); color: var(--text-color);
            padding: 10px; margin: 5px 0; width: 100%; box-sizing: border-box; font-family: var(--font);
        }
        button { cursor: pointer; background: var(--accent); color: #fff; border: none; font-weight: 600; }
        button:hover { filter: brightness(1.2); }

        .flex-row { display: flex; gap: 10px; align-items: center; }
        .flex-col { flex: 1; }

        .timeline-wrapper { position: relative; margin: 40px 0 20px 0; padding: 10px 0; }
        .timeline-axis { width: 100%; height: 4px; background: var(--text-color); position: relative; border-radius: 2px; }
        
        .timeline-dot {
            position: absolute; top: -6px; width: 14px; height: 14px;
            background: var(--bg-color); border: 3px solid var(--accent);
            border-radius: 50%; cursor: pointer; transform: translateX(-50%);
            transition: all 0.2s ease; z-index: 2;
        }
        .timeline-dot:hover { scale: 1.6; background: var(--accent); box-shadow: 0 0 10px var(--accent); z-index: 3; }

        .memory-card {
            border-left: 4px solid var(--accent); margin-bottom: 15px; padding: 15px;
            background: rgba(255,255,255,0.02); transition: background 0.3s;
        }
        .tag {
            display: inline-block; font-size: 12px; padding: 3px 8px;
            background: var(--accent); color: #fff; margin-right: 5px; margin-bottom: 10px; border-radius: var(--radius);
        }

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
            <input type="password" id="vaultPassword" placeholder="Мастер-пароль Argon2id + AES-256">
            <button onclick="exportVault()">Запаковать .himorps0</button>
            <input type="file" id="importFile" onchange="importVault(event)" style="display:none">
            <button onclick="document.getElementById('importFile').click()">Загрузить .himorps0</button>
        </div>
    </div>

    <!-- ТАЙМЛАЙН -->
    <div class="panel crooked-box">
        <h3 style="margin-top:0;">Шкала времени (Архив сохранений: <span id="saveCount">0</span>)</h3>
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
            <div class="timeline-axis" id="timelineAxis"></div>
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
        
        <label style="font-size: 12px; margin-top: 10px; display: block;">Прикрепить медиа (картинки, аудио, файлы любые):</label>
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
    let vaultMemories = [];
    let vaultFiles = {};
    let saveCounter = 0;
    const blobUrlCache = {};

    function toggleTheme() {
        document.body.classList.toggle('theme-y2k');
    }

    function b64ToBlob(b64Data, contentType='') {
        const parts = b64Data.split(',');
        const byteCharacters = atob(parts[1] || parts[0]);
        const byteArrays = [];
        for (let offset = 0; offset < byteCharacters.length; offset += 512) {
            const slice = byteCharacters.slice(offset, offset + 512);
            const byteNumbers = new Array(slice.length);
            for (let i = 0; i < slice.length; i++) {
                byteNumbers[i] = slice.charCodeAt(i);
            }
            byteArrays.push(new Uint8Array(byteNumbers));
        }
        return new Blob(byteArrays, { type: contentType });
    }

    function getFileBlobUrl(fileId) {
        if (blobUrlCache[fileId]) return blobUrlCache[fileId];
        const fObj = vaultFiles[fileId];
        if (!fObj) return '';
        const blob = b64ToBlob(fObj.data, fObj.type);
        const url = URL.createObjectURL(blob);
        blobUrlCache[fileId] = url;
        return url;
    }

    function clearBlobCache() {
        Object.keys(blobUrlCache).forEach(k => {
            URL.revokeObjectURL(blobUrlCache[k]);
            delete blobUrlCache[k];
        });
    }

    function addMemory() {
        const title = document.getElementById('memTitle').value;
        const text = document.getElementById('memText').value;
        const dt = document.getElementById('memDateTime').value;
        const marginVal = document.getElementById('memMarginVal').value;
        const marginUnit = document.getElementById('memMarginUnit').value;
        const files = document.getElementById('memAttachments').files;

        if (!dt) return alert('Укажите хотя бы дату и время!');

        const attachmentIds = [];
        let loaded = 0;

        if (files.length === 0) {
            saveEntry();
        } else {
            for (let f of files) {
                const fileId = 'file_' + crypto.randomUUID();
                const reader = new FileReader();
                reader.onload = (e) => {
                    vaultFiles[fileId] = {
                        name: f.name,
                        type: f.type,
                        data: e.target.result
                    };
                    attachmentIds.push(fileId);
                    loaded++;
                    if (loaded === files.length) saveEntry();
                };
                reader.readAsDataURL(f);
            }
        }

        function saveEntry() {
            vaultMemories.push({
                id: Date.now(),
                title,
                text,
                datetime: dt,
                marginVal: parseInt(marginVal) || 0,
                marginUnit,
                attachmentIds
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
        document.getElementById('saveCount').textContent = saveCounter;
    }

    function renderTimeline() {
        const axis = document.getElementById('timelineAxis');
        axis.innerHTML = '';

        const birthStr = document.getElementById('birthDate').value;
        const birthTime = new Date(birthStr).getTime();
        const nowTime = new Date().getTime();
        const totalDuration = nowTime - birthTime;

        vaultMemories.forEach(m => {
            const mTime = new Date(m.datetime).getTime();
            if (mTime >= birthTime && mTime <= nowTime && totalDuration > 0) {
                const pct = ((mTime - birthTime) / totalDuration) * 100;
                const dot = document.createElement('div');
                dot.className = 'timeline-dot';
                dot.style.left = `${Math.max(0, Math.min(100, pct))}%`;
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

        const sorted = [...vaultMemories].sort((a,b) => new Date(b.datetime) - new Date(a.datetime));

        sorted.forEach(m => {
            const mTime = new Date(m.datetime).getTime();
            if (mTime < fromTime || mTime > toTime) return;

            const card = document.createElement('div');
            card.className = 'memory-card';
            card.id = `card-${m.id}`;

            const h3 = document.createElement('h3');
            h3.style.margin = '0 0 10px 0';
            h3.textContent = m.title || 'Без темы';
            card.appendChild(h3);

            const metaDiv = document.createElement('div');
            const tag1 = document.createElement('span');
            tag1.className = 'tag';
            tag1.textContent = `⏱ ${(m.datetime || '').replace('T', ' ')}`;
            metaDiv.appendChild(tag1);

            if (m.marginUnit !== 'exact') {
                const tag2 = document.createElement('span');
                tag2.className = 'tag';
                tag2.textContent = `Погрешность: ±${m.marginVal} ${m.marginUnit}`;
                metaDiv.appendChild(tag2);
            }
            card.appendChild(metaDiv);

            const p = document.createElement('p');
            p.style.margin = '10px 0';
            p.style.lineHeight = '1.5';
            p.style.whiteSpace = 'pre-wrap';
            p.textContent = m.text;
            card.appendChild(p);

            if (m.attachmentIds && m.attachmentIds.length > 0) {
                const mediaDiv = document.createElement('div');
                m.attachmentIds.forEach(fid => {
                    const fObj = vaultFiles[fid];
                    if (!fObj) return;
                    const blobUrl = getFileBlobUrl(fid);

                    if (fObj.type.startsWith('image/')) {
                        const img = document.createElement('img');
                        img.src = blobUrl;
                        img.style.cssText = 'max-height: 200px; cursor: pointer; margin: 10px 10px 0 0; border: var(--border); border-radius: var(--radius);';
                        img.onclick = () => openLightbox(blobUrl);
                        mediaDiv.appendChild(img);
                    } else if (fObj.type.startsWith('audio/')) {
                        const audioWrap = document.createElement('div');
                        audioWrap.style.marginTop = '10px';
                        const audio = document.createElement('audio');
                        audio.controls = true;
                        audio.src = blobUrl;
                        audioWrap.appendChild(audio);
                        mediaDiv.appendChild(audioWrap);
                    } else {
                        const fileWrap = document.createElement('div');
                        fileWrap.style.marginTop = '10px';
                        const a = document.createElement('a');
                        a.href = blobUrl;
                        a.download = fObj.name;
                        a.textContent = `📎 ${fObj.name}`;
                        a.style.color = 'var(--accent)';
                        fileWrap.appendChild(a);
                        mediaDiv.appendChild(fileWrap);
                    }
                });
                card.appendChild(mediaDiv);
            }

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

        try {
            const res = await fetch('/api/export', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ vault: { memories: vaultMemories, files: vaultFiles }, password })
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                return alert(errData.error || 'Ошибка экспорта');
            }

            // Прямая скачка бинарного файла без Base64-оболочки
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            saveCounter++;
            document.getElementById('saveCount').textContent = saveCounter;
            
            const a = document.createElement('a');
            a.href = url;
            a.download = "memory_vault.himorps0";
            a.click();
            setTimeout(() => URL.revokeObjectURL(url), 10000);
        } catch (e) {
            alert('Ошибка экспорта: ' + e.message);
        }
    }

    async function importVault(event) {
        const file = event.target.files[0];
        const password = document.getElementById('vaultPassword').value;
        if (!file || !password) return alert('Выберите файл и введите пароль!');

        // Отправляем бинарный файл через FormData без кодирования в Base64 в JS
        const formData = new FormData();
        formData.append('file', file);
        formData.append('password', password);

        try {
            const res = await fetch('/api/import', {
                method: 'POST',
                body: formData
            });

            const data = await res.json();
            if (res.ok && data.vault) {
                clearBlobCache(); // Очищаем старые ссылки на Blob для freeing RAM
                vaultMemories = data.vault.memories || [];
                vaultFiles = data.vault.files || {};
                saveCounter++;
                render();
                alert('Архив успешно загружен!');
            } else {
                alert(data.error || 'Ошибка расшифровки или неверный пароль');
            }
        } catch (e) {
            alert('Ошибка импорта: ' + e.message);
        } finally {
            event.target.value = '';
        }
    }
</script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
import os
import json
import struct
import tempfile
from flask import Flask, request, jsonify, Response
from werkzeug.exceptions import HTTPException
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Формат HIMORPS0 v5 (потоковый, чанковый AES-256-GCM, схема STREAM)
#
#   HEADER (37 байт, целиком идёт в AAD КАЖДОГО чанка)
#     MAGIC(8) | VERSION(2) | SALT(16) | NONCE_PREFIX(7) | CHUNK_SIZE(4)
#
#   ЧАНКИ: каждый = AES-GCM(plaintext_chunk) + 16 байт тега
#     nonce = NONCE_PREFIX(7) | счётчик чанка (4, big-endian) | флаг "последний" (1)
#     Флаг последнего чанка защищает от тихой обрезки контейнера.
#
#   PAYLOAD (то, что внутри шифрования, идёт одним потоком)
#     JSON_LEN(4) | JSON manifest | файл_1 | файл_2 | ...
#     manifest = {"memories": [...], "files": [{id, name, type, size}, ...]}
#
# Ни сервер, ни браузер никогда не держат весь vault в памяти:
# сервер работает кусками по CHUNK_SIZE, браузер держит файлы как Blob.
# ---------------------------------------------------------------------------

MAGIC_BYTES = b"HIMORPS0"
VERSION = 5
HEADER_FMT = ">8sH16s7sI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 37
TAG_SIZE = 16

CHUNK_SIZE = 1024 * 1024                 # 1 МиБ plaintext на чанк
MIN_CHUNK_SIZE = 4 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024        # защита от злого заголовка
IO_STEP = 1024 * 1024                    # размер одного чтения из сети/диска
MAX_MANIFEST_BYTES = 64 * 1024 * 1024    # потолок на JSON-манифест (тексты воспоминаний)

# Потолок размера HTTP-запроса. Теперь это реально размер контейнера (без Base64),
# а в память он не грузится, так что можно ставить большое значение.
MAX_REQUEST_BYTES = 8 * 1024 * 1024 * 1024
app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_BYTES


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


# --- Низкоуровневые утилиты ---------------------------------------------------

def _safe_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _read_upto(fp, n: int) -> bytes:
    """Читает ровно n байт, либо меньше, если достигнут конец файла."""
    parts = []
    left = n
    while left > 0:
        b = fp.read(left)
        if not b:
            break
        parts.append(b)
        left -= len(b)
    return b''.join(parts)


class ByteSource:
    """Обёртка над read_some(n) -> bytes (b'' = конец данных)."""

    def __init__(self, read_some):
        self.read_some = read_some

    def iter_exact(self, n: int):
        left = n
        while left > 0:
            piece = self.read_some(min(left, IO_STEP))
            if not piece:
                raise ValueError("Неожиданный конец данных")
            left -= len(piece)
            yield piece

    def read_exact(self, n: int) -> bytes:
        return b''.join(self.iter_exact(n))


class _GenReader:
    """Превращает генератор кусков в read_some()."""

    def __init__(self, gen):
        self._gen = gen
        self._buf = b''
        self._pos = 0

    def read_some(self, n: int) -> bytes:
        while self._pos >= len(self._buf):
            try:
                self._buf = next(self._gen)
                self._pos = 0
            except StopIteration:
                return b''
        end = min(self._pos + n, len(self._buf))
        out = self._buf[self._pos:end]
        self._pos = end
        return out


def _drain(stream):
    """Дочитывает и выбрасывает остаток тела запроса, чтобы клиент увидел JSON-ошибку,
    а не оборванное соединение."""
    try:
        while stream.read(IO_STEP):
            pass
    except Exception:
        pass


# --- Потоковое шифрование/расшифровка ----------------------------------------

def _chunk_nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if counter >= 2 ** 32:
        raise ValueError("Контейнер слишком велик (переполнение счётчика чанков)")
    return prefix + struct.pack(">IB", counter, 1 if last else 0)


class StreamEncryptor:
    """write(data) ... finish(). В памяти держится не больше ~CHUNK_SIZE + размера порции."""

    def __init__(self, out, key: bytes, header: bytes, prefix: bytes, chunk_size: int):
        self._out = out
        self._aead = AESGCM(key)
        self._header = header          # весь заголовок = AAD
        self._prefix = prefix
        self._chunk_size = chunk_size
        self._buf = bytearray()
        self._counter = 0

    def _emit(self, chunk: bytes, last: bool):
        nonce = _chunk_nonce(self._prefix, self._counter, last)
        self._out.write(self._aead.encrypt(nonce, chunk, self._header))
        self._counter += 1

    def write(self, data: bytes):
        self._buf += data
        # Строго ">": последний чанк всегда остаётся в буфере для finish()
        while len(self._buf) > self._chunk_size:
            self._emit(bytes(self._buf[:self._chunk_size]), False)
            del self._buf[:self._chunk_size]

    def finish(self):
        self._emit(bytes(self._buf), True)
        self._buf.clear()


def read_header(fp):
    header = _read_upto(fp, HEADER_SIZE)
    if len(header) < HEADER_SIZE:
        raise ValueError("Файл слишком мал для контейнера .himorps0")
    magic, ver, salt, prefix, chunk_size = struct.unpack(HEADER_FMT, header)
    if magic != MAGIC_BYTES:
        raise ValueError("Неверный формат файла: отсутствует сигнатура HIMORPS0")
    if ver != VERSION:
        raise ValueError(f"Неподдерживаемая версия файла: {ver}")
    # chunk_size читается ДО проверки тега, поэтому валидируем диапазон вручную
    if not (MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE):
        raise ValueError("Некорректный размер блока в заголовке")
    return header, salt, prefix, chunk_size


def iter_decrypt(fp, key: bytes, header: bytes, prefix: bytes, chunk_size: int):
    """Генератор расшифрованных кусков. Каждый чанк аутентифицируется до выдачи;
    обрезка/дописывание/перестановка чанков -> ValueError."""
    aead = AESGCM(key)
    full = chunk_size + TAG_SIZE
    counter = 0

    cur = _read_upto(fp, full)
    if len(cur) < TAG_SIZE:
        raise ValueError("Контейнер обрезан или повреждён")

    while True:
        nxt = _read_upto(fp, full) if len(cur) == full else b''
        last = not nxt
        try:
            plain = aead.decrypt(_chunk_nonce(prefix, counter, last), cur, header)
        except InvalidTag:
            raise ValueError("Неверный пароль или данные контейнера повреждены")
        yield plain
        if last:
            return
        cur = nxt
        counter += 1


# --- Разбор payload ----------------------------------------------------------

def read_password(src: ByteSource) -> str:
    n = struct.unpack(">H", src.read_exact(2))[0]
    if n == 0:
        raise ValueError("Пароль обязателен")
    try:
        return src.read_exact(n).decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("Некорректная кодировка пароля")


def read_manifest(src: ByteSource):
    """Читает JSON_LEN + манифест, строго валидирует. Возвращает (сырые_байты_префикса, manifest)."""
    len_bytes = src.read_exact(4)
    json_len = struct.unpack(">I", len_bytes)[0]
    if json_len > MAX_MANIFEST_BYTES:
        raise ValueError("Манифест слишком велик")
    json_bytes = src.read_exact(json_len)

    try:
        manifest = json.loads(json_bytes.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Манифест повреждён")

    if not isinstance(manifest, dict):
        raise ValueError("Некорректная структура манифеста")
    if not isinstance(manifest.get("memories", []), list):
        raise ValueError("Некорректный список воспоминаний")
    files = manifest.get("files", [])
    if not isinstance(files, list):
        raise ValueError("Некорректный список файлов")

    seen = set()
    for f in files:
        if not isinstance(f, dict):
            raise ValueError("Некорректная запись о файле")
        fid = f.get("id")
        if not isinstance(fid, str) or not fid or fid in seen:
            raise ValueError("Некорректный или повторяющийся id файла")
        seen.add(fid)
        if not isinstance(f.get("name", ""), str) or not isinstance(f.get("type", ""), str):
            raise ValueError(f"Некорректные метаданные файла {fid}")
        size = f.get("size")
        # bool — подкласс int, его отсекаем явно
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError(f"Некорректный размер файла {fid}: {size}")

    manifest["files"] = files
    return len_bytes + json_bytes, manifest


# --- Маршруты ----------------------------------------------------------------

@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "Слишком большой запрос"}), 413


@app.route('/')
def index():
    return Response(HTML_TEMPLATE, mimetype='text/html')


@app.route('/api/export', methods=['POST'])
def export_vault():
    """Тело запроса (application/octet-stream):
         PW_LEN(2) | PASSWORD | JSON_LEN(4) | JSON manifest | байты файлов подряд
       Это ровно plaintext-payload, сервер шифрует его на лету кусками и кладёт
       ТОЛЬКО шифротекст во временный файл, потом отдаёт его потоком."""
    tmp_path = None
    try:
        src = ByteSource(request.stream.read)
        password = read_password(src)
        raw_head, manifest = read_manifest(src)

        salt = os.urandom(16)
        prefix = os.urandom(7)
        header = struct.pack(HEADER_FMT, MAGIC_BYTES, VERSION, salt, prefix, CHUNK_SIZE)
        key = derive_key(password, salt)

        fd, tmp_path = tempfile.mkstemp(prefix='himorps0_', suffix='.tmp')
        with os.fdopen(fd, 'wb') as out:
            out.write(header)
            enc = StreamEncryptor(out, key, header, prefix, CHUNK_SIZE)
            enc.write(raw_head)
            for f in manifest["files"]:
                for piece in src.iter_exact(f["size"]):
                    enc.write(piece)
            if src.read_some(1):
                raise ValueError("Лишние данные после последнего файла")
            enc.finish()

        total = os.path.getsize(tmp_path)
    except HTTPException:
        if tmp_path:
            _safe_remove(tmp_path)
        raise
    except ValueError as e:
        if tmp_path:
            _safe_remove(tmp_path)
        _drain(request.stream)
        return jsonify({"error": f"Ошибка упаковки: {e}"}), 400
    except Exception:
        if tmp_path:
            _safe_remove(tmp_path)
        app.logger.exception("export failed")
        return jsonify({"error": "Внутренняя ошибка упаковки"}), 500

    def generate():
        try:
            with open(tmp_path, 'rb') as fp:
                while True:
                    b = fp.read(IO_STEP)
                    if not b:
                        break
                    yield b
        finally:
            _safe_remove(tmp_path)

    resp = Response(generate(), mimetype='application/octet-stream')
    resp.headers['Content-Length'] = str(total)
    resp.headers['Content-Disposition'] = 'attachment; filename="memory_vault.himorps0"'
    return resp


@app.route('/api/import', methods=['POST'])
def import_vault():
    """Тело запроса: PW_LEN(2) | PASSWORD | байты контейнера .himorps0
       Ответ: расшифрованный payload потоком (JSON_LEN | manifest | файлы).
       Сначала контейнер целиком проверяется (проход 1, плейнтекст отбрасывается),
       и только потом идёт поток клиенту (проход 2) — значит, посреди ответа
       ошибка аутентификации возникнуть не может. Плейнтекст на диск не пишется."""
    tmp_path = None
    try:
        src = ByteSource(request.stream.read)
        password = read_password(src)

        fd, tmp_path = tempfile.mkstemp(prefix='himorps0_', suffix='.tmp')
        with os.fdopen(fd, 'wb') as tmp:     # на диске только шифротекст
            while True:
                b = src.read_some(IO_STEP)
                if not b:
                    break
                tmp.write(b)

        # Проход 1: полная проверка
        with open(tmp_path, 'rb') as fp:
            header, salt, prefix, chunk_size = read_header(fp)
            key = derive_key(password, salt)
            plain = ByteSource(_GenReader(iter_decrypt(fp, key, header, prefix, chunk_size)).read_some)

            raw_head, manifest = read_manifest(plain)
            total = len(raw_head)
            for f in manifest["files"]:
                for piece in plain.iter_exact(f["size"]):
                    pass
                total += f["size"]
            # Проверка хвоста; заодно прогоняет генератор до последнего чанка
            if plain.read_some(1):
                raise ValueError("Лишние данные в конце контейнера")
    except HTTPException:
        if tmp_path:
            _safe_remove(tmp_path)
        raise
    except ValueError as e:
        if tmp_path:
            _safe_remove(tmp_path)
        _drain(request.stream)
        return jsonify({"error": f"Ошибка расшифровки: {e}"}), 400
    except Exception:
        if tmp_path:
            _safe_remove(tmp_path)
        app.logger.exception("import failed")
        return jsonify({"error": "Внутренняя ошибка расшифровки"}), 500

    # Проход 2: потоковая выдача
    def generate():
        try:
            with open(tmp_path, 'rb') as fp:
                fp.seek(HEADER_SIZE)
                for piece in iter_decrypt(fp, key, header, prefix, chunk_size):
                    yield piece
        finally:
            _safe_remove(tmp_path)

    resp = Response(generate(), mimetype='application/octet-stream')
    resp.headers['Content-Length'] = str(total)
    return resp


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
    let vaultFiles = {};   // { fileId: { name, type, size, blob } } — blob это File/Blob, не Base64
    let saveCounter = 0;
    let busy = false;
    const blobUrlCache = {};

    const textEnc = new TextEncoder();
    const textDec = new TextDecoder();
    const BLOB_FLUSH_BYTES = 32 * 1024 * 1024;

    function toggleTheme() {
        document.body.classList.toggle('theme-y2k');
    }

    // --- Бинарные хелперы ---
    function u16(n) {
        const b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, n, false);
        return b;
    }

    function u32(n) {
        const b = new ArrayBuffer(4);
        new DataView(b).setUint32(0, n, false);
        return b;
    }

    function passwordPrefix(password) {
        const pw = textEnc.encode(password);
        if (pw.length === 0 || pw.length > 65535) {
            throw new Error('Пароль должен быть от 1 до 65535 байт в UTF-8');
        }
        return [u16(pw.length), pw];
    }

    // Читает response.body потоком. Файлы собираются в Blob порциями,
    // чтобы в JS-куче не копился весь файл целиком.
    class StreamReader {
        constructor(stream) {
            this.reader = stream.getReader();
            this.chunk = new Uint8Array(0);
            this.pos = 0;
        }

        async _fill() {
            const { done, value } = await this.reader.read();
            if (done) return false;
            this.chunk = value;
            this.pos = 0;
            return true;
        }

        async _ensure() {
            while (this.pos >= this.chunk.length) {
                if (!(await this._fill())) throw new Error('Неожиданный конец потока');
            }
        }

        async readBytes(n) {
            const out = new Uint8Array(n);
            let got = 0;
            while (got < n) {
                await this._ensure();
                const take = Math.min(n - got, this.chunk.length - this.pos);
                out.set(this.chunk.subarray(this.pos, this.pos + take), got);
                got += take;
                this.pos += take;
            }
            return out;
        }

        async readBlob(n, type) {
            const blobs = [];
            let parts = [];
            let partsBytes = 0;
            let left = n;
            while (left > 0) {
                await this._ensure();
                const take = Math.min(left, this.chunk.length - this.pos);
                parts.push(this.chunk.subarray(this.pos, this.pos + take));
                partsBytes += take;
                left -= take;
                this.pos += take;
                if (partsBytes >= BLOB_FLUSH_BYTES) {
                    blobs.push(new Blob(parts));
                    parts = [];
                    partsBytes = 0;
                }
            }
            if (parts.length) blobs.push(new Blob(parts));
            return new Blob(blobs, { type: type });
        }
    }

    function getFileBlobUrl(fileId) {
        if (blobUrlCache[fileId]) return blobUrlCache[fileId];
        const fObj = vaultFiles[fileId];
        if (!fObj) return '';
        const url = URL.createObjectURL(fObj.blob);
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

        // Файлы не читаются в память: File — это ссылка на файл на диске
        for (const f of files) {
            const fileId = 'file_' + crypto.randomUUID();
            vaultFiles[fileId] = {
                name: f.name,
                type: f.type || 'application/octet-stream',
                size: f.size,
                blob: f
            };
            attachmentIds.push(fileId);
        }

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
        if (busy) return;
        const password = document.getElementById('vaultPassword').value;
        if (!password) return alert('Введите мастер-пароль!');

        busy = true;
        try {
            const ids = Object.keys(vaultFiles);
            const manifest = {
                memories: vaultMemories,
                files: ids.map(id => ({
                    id: id,
                    name: vaultFiles[id].name,
                    type: vaultFiles[id].type,
                    size: vaultFiles[id].blob.size
                }))
            };
            const json = textEnc.encode(JSON.stringify(manifest));

            // Тело = PW_LEN | PASSWORD | JSON_LEN | JSON | файлы подряд.
            // Blob склеивается лениво: браузер стримит файлы с диска, ничего не копируется в RAM.
            const body = new Blob([
                ...passwordPrefix(password),
                u32(json.length),
                json,
                ...ids.map(id => vaultFiles[id].blob)
            ]);

            const res = await fetch('/api/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/octet-stream' },
                body: body
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                return alert(errData.error || 'Ошибка экспорта');
            }

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
        } finally {
            busy = false;
        }
    }

    async function importVault(event) {
        const file = event.target.files[0];
        const password = document.getElementById('vaultPassword').value;
        if (!file || !password) {
            event.target.value = '';
            return alert('Выберите файл и введите пароль!');
        }
        if (busy) {
            event.target.value = '';
            return;
        }

        busy = true;
        try {
            // Тело = PW_LEN | PASSWORD | байты контейнера (без Base64 и без FormData)
            const body = new Blob([...passwordPrefix(password), file]);
            const res = await fetch('/api/import', {
                method: 'POST',
                headers: { 'Content-Type': 'application/octet-stream' },
                body: body
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                return alert(errData.error || 'Ошибка расшифровки или неверный пароль');
            }

            // Сервер уже проверил весь контейнер, дальше идёт только чтение потока
            const reader = new StreamReader(res.body);
            const head = await reader.readBytes(4);
            const jsonLen = new DataView(head.buffer).getUint32(0, false);
            const manifest = JSON.parse(textDec.decode(await reader.readBytes(jsonLen)));

            const newFiles = {};
            for (const f of (manifest.files || [])) {
                const type = f.type || 'application/octet-stream';
                newFiles[f.id] = {
                    name: f.name || 'unnamed',
                    type: type,
                    size: f.size,
                    blob: await reader.readBlob(f.size, type)
                };
            }

            // Подменяем состояние только после полного успешного разбора
            clearBlobCache();
            vaultMemories = manifest.memories || [];
            vaultFiles = newFiles;
            saveCounter++;
            render();
            alert('Архив успешно загружен!');
        } catch (e) {
            alert('Ошибка импорта: ' + e.message);
        } finally {
            busy = false;
            event.target.value = '';
        }
    }
</script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000, threaded=True)
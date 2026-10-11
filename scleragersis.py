#!/usr/bin/env python3
"""
HIMORPS0 Memory Archive — локальный зашифрованный архив воспоминаний (Flask).

Запуск:  python app.py         (по умолчанию http://127.0.0.1:5000)

=====================================================================
1. ФОРМАТ КОНТЕЙНЕРА .himorps0
=====================================================================
v6 (так пишутся ВСЕ новые архивы). Заголовок переменной длины; ВЕСЬ он
(байт в байт) входит в AAD каждого чанка:

    MAGIC(8) | VERSION(2)=6 | KDF_ID(1) | T(4) | M_KiB(4) | P(4)
    | SALT_LEN(1) | NONCE_PREFIX(7) | CHUNK_SIZE(4) | SALT(SALT_LEN)

    KDF_ID=1 -> Argon2id; T = число проходов, M_KiB = память в КиБ,
    P = параллелизм (lanes). Ключ AES-256 = Argon2id(пароль, SALT, T, M, P).

v5 (ТОЛЬКО ЧТЕНИЕ, обратная совместимость):

    MAGIC(8) | VERSION(2)=5 | SALT(16) | NONCE_PREFIX(7) | CHUNK_SIZE(4)

    Параметры Argon2id в v5 не хранились и всегда равны t=3, m=64 МиБ, p=4.

Чанки (одинаково в v5 и v6, криптосхема не менялась): AES-256-GCM,
    nonce = NONCE_PREFIX(7) | номер_чанка(4, BE) | флаг_последнего(1),
    AAD   = весь заголовок.
Флаг «последний» + номер в nonce => обрезка, перестановка и дописывание
чанков обнаруживаются. Тег каждого чанка проверяется ДО выдачи данных.

Payload v6 (внутри шифрования), схема 1 — последовательность записей:

    запись = TYPE(1) | LENGTH(8, u64 big-endian) | BODY(LENGTH байт)

    1 META    BODY = JSON {"schema":1,...}   — первая и единственная
    2 MEMORY  BODY = JSON одного воспоминания
    3 FILE    BODY = META_LEN(4) | JSON {"id","name","type"} | байты файла
    4 END     BODY = число_MEMORY(8) | число_FILE(8)  — последняя, после неё
                      данных нет

Записи читаются и пишутся потоком по одной; большой JSON-манифест на весь
архив не нужен. Порядок записей сохраняется; связи «воспоминание → файл» —
по id (поле attachmentIds у воспоминания, id у файла). Экспортёр кладёт файлы
воспоминания непосредственно перед ним, но читатель порядок не требует.
Версионирование двухуровневое: VERSION контейнера (шифрование/заголовок) и
"schema" в META (структура записей).

Открытие v5: сервер расшифровывает монолитный JSON-манифест v5 и «на лету»
превращает его в тот же поток записей v6 (клиент видит один формат).
У v5 это единственное место, где манифест целиком живёт в RAM
(потолок HIMORPS_MAX_V5_MANIFEST_BYTES).

=====================================================================
2. ЛИМИТЫ: ФОРМАТ  vs  ОКРУЖЕНИЕ
=====================================================================
Ограничения ФОРМАТА (не настраиваются):
  * длина записи и размер файла: u64 (до 2^64-1 байт);
  * число чанков: 2^32 (счётчик в nonce) => при чанке 1 МиБ это 4 ПиБ
    шифротекста, при чанке 16 МиБ — 64 ПиБ;
  * число воспоминаний/файлов: формат не ограничивает.
Ограничения ОКРУЖЕНИЯ (реальные пределы — они всегда ниже формата):
  * браузер: размер одного файла <= 2^53-1 байт (точные целые Number),
    все воспоминания (текст/метаданные) живут в куче JS, файлы — в Blob
    (браузер сбрасывает большие Blob на диск, но это его квота/диск);
  * сервер: свободное место в HIMORPS_TMPDIR (во время операции там лежит
    шифротекст целиком: ~размер архива; при импорте+экспорте — по одной копии);
  * файловая система (макс. размер файла), ОЗУ браузера, диск пользователя.
Эксплуатационные настройки (переменные окружения, 0 = «без лимита» там, где указано):
  HIMORPS_HOST / HIMORPS_PORT         адрес (по умолчанию 127.0.0.1:5000)
  HIMORPS_MAX_UPLOAD_BYTES            лимит размера запроса, 0 = нет (по умолч. 0)
  HIMORPS_MAX_RECORD_JSON_BYTES       макс. JSON одной записи (по умолч. 64 МиБ)
  HIMORPS_MAX_V5_MANIFEST_BYTES       макс. манифест v5 (по умолч. 256 МиБ)
  HIMORPS_CHUNK_SIZE                  размер чанка новых архивов (по умолч. 1 МиБ)
  HIMORPS_MAX_CHUNK_SIZE              макс. чанк в чужих заголовках (по умолч. 16 МиБ)
  HIMORPS_KDF_ITERATIONS / _MEMORY_KIB / _LANES   параметры Argon2id НОВЫХ архивов
                                      (по умолч. 3 / 65536 / 4)
  HIMORPS_KDF_MIN_ITERATIONS / _MAX_ITERATIONS    допустимо для ОТКРЫВАЕМЫХ (1 / 10)
  HIMORPS_KDF_MIN_MEMORY_KIB / _MAX_MEMORY_KIB    (19456 / 1048576 = 1 ГиБ)
  HIMORPS_KDF_MAX_LANES               (по умолч. 16)
  HIMORPS_MAX_CONCURRENT_KDF          одновременных Argon2id (по умолч. 2)
  HIMORPS_MIN_FREE_DISK_BYTES         резерв свободного места (по умолч. 64 МиБ)
  HIMORPS_TMPDIR                      каталог временных файлов (по умолч. системный)
  HIMORPS_STAGE_TTL_SEC / _MAX_STAGED резервный режим скачивания (600 с / 8 шт.)
  HIMORPS_DRAIN_LIMIT_BYTES           сколько тела запроса дочитывать при ошибке (1 ГиБ)

=====================================================================
3. СКАЧИВАНИЕ ПРИ ЭКСПОРТЕ (два режима, выбирает клиент)
=====================================================================
  A. Потоковая запись в файл: window.showSaveFilePicker (File System Access
     API: Chrome/Edge/Opera, нужен secure context — localhost подходит).
     Ответ сервера пишется в файл кусками, в памяти страницы целого архива нет;
     при обрыве/несовпадении длины запись отменяется и файл не подменяется.
  B. Резервный (Firefox, Safari и т.п.): POST /api/export?stage=1 оставляет
     готовый шифротекст на сервере и возвращает одноразовый токен; браузер
     скачивает GET /api/download/<токен> обычным менеджером загрузок —
     поток идёт на диск без участия JS и без Blob. Ограничения: токен
     одноразовый и живёт HIMORPS_STAGE_TTL_SEC; при обрыве загрузки экспорт нужно
     повторить; на сервере временно занято место под архив; куда сохранится файл
     и как он называется, решает браузер.

Все ответы /api/* отдаются с Cache-Control: no-store (в т.ч. ошибки 4xx/5xx).
"""
import atexit
import errno
import json
import os
import secrets
import shutil
import struct
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Optional

from flask import Flask, Response, g, jsonify, request
from werkzeug.exceptions import HTTPException
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB

# --- Константы ФОРМАТА (не настраиваются) -----------------------------------
MAGIC_BYTES = b"HIMORPS0"
VERSION_V5 = 5
VERSION = 6
KDF_ARGON2ID = 1
V5_FMT = ">8sH16s7sI"
V5_HEADER_SIZE = struct.calcsize(V5_FMT)            # 37
V5_KDF = (3, 65536, 4)                              # t, m_KiB, p — зашиты в v5
V6_FIXED_FMT = ">8sHBIIIB7sI"
V6_FIXED_SIZE = struct.calcsize(V6_FIXED_FMT)       # 35 (+ соль)
COMMON_PREFIX_SIZE = 10                             # MAGIC + VERSION
SALT_LEN_MIN, SALT_LEN_MAX, NEW_SALT_LEN = 16, 64, 16
NONCE_PREFIX_LEN = 7
TAG_SIZE = 16
MIN_CHUNK_SIZE = 4 * KiB
MAX_CHUNKS = 2 ** 32                                # счётчик чанка в nonce — 4 байта

R_META, R_MEMORY, R_FILE, R_END = 1, 2, 3, 4
RECORD_HDR_FMT = ">BQ"
RECORD_HDR_SIZE = struct.calcsize(RECORD_HDR_FMT)   # 9
PAYLOAD_SCHEMA = 1

IO_STEP = 1 * MiB
WORKDIR_PREFIX = "himorps0_"
STALE_WORKDIR_AGE = 6 * 3600


# --- Конфигурация (эксплуатационные ограничения) -----------------------------
class ConfigError(Exception):
    pass


def _env_int(env, name, default, lo=None, hi=None):
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        val = int(raw.strip().replace('_', ''), 10)
    except ValueError:
        raise ConfigError(f"{name}: ожидалось целое число, получено {raw!r}")
    if lo is not None and val < lo:
        raise ConfigError(f"{name}={val}: минимум {lo}")
    if hi is not None and val > hi:
        raise ConfigError(f"{name}={val}: максимум {hi}")
    return val


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    max_upload_bytes: int          # 0 = без лимита
    max_record_json_bytes: int
    max_v5_manifest_bytes: int
    chunk_size: int
    max_chunk_size: int
    kdf_iterations: int            # параметры НОВЫХ архивов
    kdf_memory_kib: int
    kdf_lanes: int
    kdf_min_iterations: int        # границы для ОТКРЫВАЕМЫХ архивов
    kdf_max_iterations: int
    kdf_min_memory_kib: int
    kdf_max_memory_kib: int
    kdf_max_lanes: int
    max_concurrent_kdf: int
    min_free_disk_bytes: int
    tmpdir: Optional[str]
    stage_ttl_sec: int
    max_staged: int
    drain_limit_bytes: int


def load_config(env=None) -> Config:
    env = os.environ if env is None else env

    def i(name, default, lo=None, hi=None):
        return _env_int(env, name, default, lo, hi)

    u32max = 2 ** 32 - 1
    cfg = Config(
        host=env.get('HIMORPS_HOST', '127.0.0.1'),
        port=i('HIMORPS_PORT', 5000, 1, 65535),
        max_upload_bytes=i('HIMORPS_MAX_UPLOAD_BYTES', 0, 0),
        # верхняя граница = потолок разбора JSON одной записи в браузере (MAX_JSON_IN_RAM в клиенте)
        max_record_json_bytes=i('HIMORPS_MAX_RECORD_JSON_BYTES', 64 * MiB, 1 * KiB, 256 * MiB),
        max_v5_manifest_bytes=i('HIMORPS_MAX_V5_MANIFEST_BYTES', 256 * MiB, 1 * KiB, u32max),
        chunk_size=i('HIMORPS_CHUNK_SIZE', 1 * MiB, MIN_CHUNK_SIZE, u32max),
        max_chunk_size=i('HIMORPS_MAX_CHUNK_SIZE', 16 * MiB, MIN_CHUNK_SIZE, u32max),
        kdf_iterations=i('HIMORPS_KDF_ITERATIONS', 3, 1, u32max),
        kdf_memory_kib=i('HIMORPS_KDF_MEMORY_KIB', 65536, 8, u32max),
        kdf_lanes=i('HIMORPS_KDF_LANES', 4, 1, 2 ** 24 - 1),
        kdf_min_iterations=i('HIMORPS_KDF_MIN_ITERATIONS', 1, 1, u32max),
        kdf_max_iterations=i('HIMORPS_KDF_MAX_ITERATIONS', 10, 1, u32max),
        kdf_min_memory_kib=i('HIMORPS_KDF_MIN_MEMORY_KIB', 19456, 8, u32max),
        kdf_max_memory_kib=i('HIMORPS_KDF_MAX_MEMORY_KIB', 1 * GiB // KiB, 8, u32max),
        kdf_max_lanes=i('HIMORPS_KDF_MAX_LANES', 16, 1, 2 ** 24 - 1),
        max_concurrent_kdf=i('HIMORPS_MAX_CONCURRENT_KDF', 2, 1, 64),
        min_free_disk_bytes=i('HIMORPS_MIN_FREE_DISK_BYTES', 64 * MiB, 0),
        tmpdir=(env.get('HIMORPS_TMPDIR') or None),
        stage_ttl_sec=i('HIMORPS_STAGE_TTL_SEC', 600, 1),
        max_staged=i('HIMORPS_MAX_STAGED', 8, 1),
        drain_limit_bytes=i('HIMORPS_DRAIN_LIMIT_BYTES', 1 * GiB, 0),
    )
    if cfg.chunk_size > cfg.max_chunk_size:
        raise ConfigError("HIMORPS_CHUNK_SIZE больше HIMORPS_MAX_CHUNK_SIZE: новые архивы "
                          "не открылись бы этим же сервером")
    # Параметры НОВЫХ архивов обязаны проходить собственные же проверки при открытии
    validate_kdf(KDF_ARGON2ID, cfg.kdf_iterations, cfg.kdf_memory_kib, cfg.kdf_lanes,
                 NEW_SALT_LEN, cfg, exc=ConfigError, what="параметры Argon2id новых архивов")
    return cfg


# --- Ошибки ------------------------------------------------------------------
class FormatError(ValueError):
    """Некорректный/подделанный контейнер или запрос (HTTP 400)."""


class OutOfSpace(Exception):
    """Не хватает места во временном каталоге (HTTP 507)."""


class TooManyStaged(Exception):
    pass


# --- Временные файлы и диск --------------------------------------------------
_workdir_lock = threading.Lock()
_workdir = None


def _cleanup_workdir():
    global _workdir
    if _workdir:
        shutil.rmtree(_workdir, ignore_errors=True)
        _workdir = None


def _sweep_stale_workdirs(base):
    """Удаляет каталоги, оставшиеся от аварийно завершённых запусков."""
    now = time.time()
    try:
        names = os.listdir(base)
    except OSError:
        return
    for name in names:
        if not name.startswith(WORKDIR_PREFIX):
            continue
        path = os.path.join(base, name)
        try:
            if os.path.isdir(path) and now - os.path.getmtime(path) > STALE_WORKDIR_AGE:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass


def workdir() -> str:
    """Личный каталог процесса для временных файлов (шифротекст, никогда не plaintext)."""
    global _workdir
    with _workdir_lock:
        if _workdir is None or not os.path.isdir(_workdir):
            base = CFG.tmpdir or tempfile.gettempdir()
            os.makedirs(base, exist_ok=True)
            _sweep_stale_workdirs(base)
            first = _workdir is None
            _workdir = tempfile.mkdtemp(prefix=WORKDIR_PREFIX, dir=base)
            if first:
                atexit.register(_cleanup_workdir)
        return _workdir


def new_temp():
    return tempfile.mkstemp(prefix='ct_', suffix='.tmp', dir=workdir())


def _safe_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _fmt_size(n):
    for unit in ('Б', 'КиБ', 'МиБ', 'ГиБ', 'ТиБ'):
        if n < 1024 or unit == 'ТиБ':
            return f"{n:.0f} {unit}" if unit == 'Б' else f"{n:.1f} {unit}"
        n /= 1024


def _no_space_message(needed, free):
    return (f"Недостаточно места во временном каталоге ({workdir()}): нужно ~{_fmt_size(needed)} "
            f"+ резерв {_fmt_size(CFG.min_free_disk_bytes)}, свободно {_fmt_size(free)}. "
            f"Освободите место или задайте HIMORPS_TMPDIR на другой диск.")


def require_disk(needed: int):
    """Проверка ДО начала записи: хватит ли места под временный шифротекст."""
    free = shutil.disk_usage(workdir()).free
    if free < needed + CFG.min_free_disk_bytes:
        raise OutOfSpace(_no_space_message(needed, free))


class DiskGuard:
    """Периодически проверяет свободное место во время записи (длина тела может быть
    неизвестна заранее — chunked). Дополняет предварительную проверку."""

    def __init__(self, every=32 * MiB):
        self._every = every
        self._since = 0

    def account(self, n: int):
        self._since += n
        if self._since >= self._every:
            self._since = 0
            free = shutil.disk_usage(workdir()).free
            if free < CFG.min_free_disk_bytes:
                raise OutOfSpace(_no_space_message(0, free))


# --- Argon2id ----------------------------------------------------------------


def validate_kdf(kdf_id, t, m, p, salt_len, cfg, exc=FormatError, what="заголовок"):
    """Проверка параметров KDF ДО запуска Argon2id: недоверенный заголовок
    не должен заставить сервер занять гигабайты памяти или минуты CPU."""
    if kdf_id != KDF_ARGON2ID:
        raise exc(f"{what}: неизвестный идентификатор KDF ({kdf_id})")
    if not (cfg.kdf_min_iterations <= t <= cfg.kdf_max_iterations):
        raise exc(f"{what}: Argon2id t={t} вне допустимого диапазона "
                  f"[{cfg.kdf_min_iterations}, {cfg.kdf_max_iterations}]")
    if not (1 <= p <= cfg.kdf_max_lanes):
        raise exc(f"{what}: Argon2id p={p} вне допустимого диапазона [1, {cfg.kdf_max_lanes}]")
    lo_m = max(cfg.kdf_min_memory_kib, 8 * p)
    if not (lo_m <= m <= cfg.kdf_max_memory_kib):
        raise exc(f"{what}: Argon2id m={m} КиБ вне допустимого диапазона "
                  f"[{lo_m}, {cfg.kdf_max_memory_kib}]")
    if not (SALT_LEN_MIN <= salt_len <= SALT_LEN_MAX):
        raise exc(f"{what}: недопустимая длина соли ({salt_len})")


try:
    CFG = load_config()
except ConfigError as _e:
    sys.exit(f"Ошибка конфигурации: {_e}")

app = Flask(__name__)
# Лимит запроса — только эксплуатационная настройка, по умолчанию его нет.
# Реальную защиту дают проверка свободного места и потоковая обработка.
app.config['MAX_CONTENT_LENGTH'] = CFG.max_upload_bytes or None


_kdf_sem = threading.BoundedSemaphore(CFG.max_concurrent_kdf)


def derive_key(password: str, salt: bytes, t: int, m: int, p: int) -> bytes:
    with _kdf_sem:      # ограничивает одновременную память Argon2id
        kdf = Argon2id(salt=salt, length=32, iterations=t, lanes=p, memory_cost=m)
        return kdf.derive(password.encode('utf-8'))


# --- Заголовок ---------------------------------------------------------------
@dataclass(frozen=True)
class Header:
    version: int
    t: int
    m: int
    p: int
    salt: bytes
    prefix: bytes
    chunk_size: int
    raw: bytes                  # ровно то, что идёт в AAD

    @property
    def size(self):
        return len(self.raw)


def pack_header_v6(salt, prefix, chunk_size, t, m, p) -> bytes:
    return struct.pack(V6_FIXED_FMT, MAGIC_BYTES, VERSION, KDF_ARGON2ID, t, m, p,
                       len(salt), prefix, chunk_size) + salt


def _read_upto(fp, n: int) -> bytes:
    """Читает ровно n байт либо меньше, если файл закончился."""
    parts = []
    left = n
    while left > 0:
        b = fp.read(left)
        if not b:
            break
        parts.append(b)
        left -= len(b)
    return b''.join(parts)


def _check_chunk_size(chunk_size, cfg):
    # chunk_size читается ДО проверки тега, поэтому диапазон проверяется вручную
    if not (MIN_CHUNK_SIZE <= chunk_size <= cfg.max_chunk_size):
        raise FormatError("Некорректный размер блока в заголовке")


def read_header(fp, cfg) -> Header:
    first = _read_upto(fp, COMMON_PREFIX_SIZE)
    if len(first) < COMMON_PREFIX_SIZE:
        raise FormatError("Файл слишком мал для контейнера .himorps0")
    magic, ver = struct.unpack(">8sH", first)
    if magic != MAGIC_BYTES:
        raise FormatError("Неверный формат файла: отсутствует сигнатура HIMORPS0")

    if ver == VERSION_V5:
        rest = _read_upto(fp, V5_HEADER_SIZE - COMMON_PREFIX_SIZE)
        if len(rest) < V5_HEADER_SIZE - COMMON_PREFIX_SIZE:
            raise FormatError("Файл слишком мал для контейнера .himorps0")
        raw = first + rest
        _, _, salt, prefix, chunk_size = struct.unpack(V5_FMT, raw)
        _check_chunk_size(chunk_size, cfg)
        t, m, p = V5_KDF
        return Header(VERSION_V5, t, m, p, salt, prefix, chunk_size, raw)

    if ver == VERSION:
        rest = _read_upto(fp, V6_FIXED_SIZE - COMMON_PREFIX_SIZE)
        if len(rest) < V6_FIXED_SIZE - COMMON_PREFIX_SIZE:
            raise FormatError("Файл слишком мал для контейнера .himorps0")
        fixed = first + rest
        _, _, kdf_id, t, m, p, salt_len, prefix, chunk_size = struct.unpack(V6_FIXED_FMT, fixed)
        # Всё проверяется до чтения соли и, тем более, до запуска Argon2id
        validate_kdf(kdf_id, t, m, p, salt_len, cfg)
        _check_chunk_size(chunk_size, cfg)
        salt = _read_upto(fp, salt_len)
        if len(salt) != salt_len:
            raise FormatError("Файл слишком мал для контейнера .himorps0")
        return Header(VERSION, t, m, p, salt, prefix, chunk_size, fixed + salt)

    if ver > VERSION:
        raise FormatError(f"Файл создан более новой версией формата ({ver}); обновите приложение")
    raise FormatError(f"Неподдерживаемая версия файла: {ver}")


# --- Потоковые источники -----------------------------------------------------
class Source:
    """Буферизованный источник байт поверх next_chunk() -> bytes (b'' = конец).
    Если задан tee, он получает КАЖДЫЙ прочитанный байт (в порядке чтения)."""

    def __init__(self, next_chunk, tee=None):
        self._next = next_chunk
        self._buf = b''
        self._pos = 0
        self.tee = tee

    def read_some(self, n: int) -> bytes:
        """До n байт (не больше остатка текущего буфера); b'' — конец данных."""
        if self._pos >= len(self._buf):
            data = self._next()
            if not data:
                return b''
            self._buf, self._pos = data, 0
        end = min(self._pos + n, len(self._buf))
        out = self._buf[self._pos:end]
        self._pos = end
        if self.tee:
            self.tee(out)
        return out

    def iter_exact(self, n: int):
        left = n
        while left > 0:
            piece = self.read_some(left)
            if not piece:
                raise FormatError("Неожиданный конец данных")
            left -= len(piece)
            yield piece

    def read_exact(self, n: int) -> bytes:
        """Только для малых n (ограничение вызывающий проверяет заранее)."""
        parts = list(self.iter_exact(n))
        return parts[0] if len(parts) == 1 else b''.join(parts)


def _drain_request():
    """Дочитывает (с лимитом) остаток тела, чтобы клиент увидел JSON-ошибку, а не
    оборванное соединение. Не дочитали — просим закрыть соединение."""
    try:
        stream = request.stream
        left = CFG.drain_limit_bytes
        while left > 0:
            b = stream.read(min(IO_STEP, left))
            if not b:
                return
            left -= len(b)
    except Exception:
        pass
    g.close_conn = True


# --- Потоковое шифрование/расшифровка (схема не менялась с v5) ----------------
def _chunk_nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if counter >= MAX_CHUNKS:
        raise FormatError("Контейнер слишком велик для формата (переполнение счётчика чанков)")
    return prefix + struct.pack(">IB", counter, 1 if last else 0)


class StreamEncryptor:
    """write(data)... finish(). В памяти не больше ~chunk_size + размера порции."""

    def __init__(self, out, key, header: bytes, prefix: bytes, chunk_size: int):
        self._out = out
        self._aead = AESGCM(key)
        self._header = header
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


def iter_decrypt(fp, key: bytes, hdr: Header):
    """Генератор расшифрованных кусков. Каждый чанк аутентифицируется до выдачи;
    обрезка/дописывание/перестановка чанков -> FormatError."""
    aead = AESGCM(key)
    full = hdr.chunk_size + TAG_SIZE
    counter = 0
    cur = _read_upto(fp, full)
    if len(cur) < TAG_SIZE:
        raise FormatError("Контейнер обрезан или повреждён")
    while True:
        nxt = _read_upto(fp, full) if len(cur) == full else b''
        last = not nxt
        try:
            plain = aead.decrypt(_chunk_nonce(hdr.prefix, counter, last), cur, hdr.raw)
        except InvalidTag:
            raise FormatError("Неверный пароль или данные контейнера повреждены")
        yield plain
        if last:
            return
        cur = nxt
        counter += 1


# --- Записи payload ----------------------------------------------------------
def pack_record(rtype: int, body: bytes) -> bytes:
    return struct.pack(RECORD_HDR_FMT, rtype, len(body)) + body


def read_password(src: Source) -> str:
    n = struct.unpack(">H", src.read_exact(2))[0]
    if n == 0:
        raise FormatError("Пароль обязателен")
    try:
        return src.read_exact(n).decode('utf-8')
    except UnicodeDecodeError:
        raise FormatError("Некорректная кодировка пароля")


def validate_payload(src: Source, cfg):
    """Строгий потоковый разбор payload v6. Размеры проверяются ДО выделения памяти:
    JSON-записи — по лимиту, байты файлов только пропускаются по кускам.
    Возвращает (воспоминаний, файлов). Каждый прочитанный байт идёт в src.tee."""
    max_json = cfg.max_record_json_bytes

    def read_json_obj(n, what):
        if n > max_json:
            raise FormatError(f"{what} слишком велик ({n} Б > {max_json} Б; "
                              f"лимит HIMORPS_MAX_RECORD_JSON_BYTES)")
        raw = src.read_exact(n)
        try:
            obj = json.loads(raw.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise FormatError(f"{what} повреждён")
        if not isinstance(obj, dict):
            raise FormatError(f"{what}: ожидался JSON-объект")
        return obj

    memories = files = 0
    first = True
    while True:
        rtype, length = struct.unpack(RECORD_HDR_FMT, src.read_exact(RECORD_HDR_SIZE))
        if first and rtype != R_META:
            raise FormatError("Архив должен начинаться с записи META")
        if rtype == R_META:
            if not first:
                raise FormatError("Повторная запись META")
            obj = read_json_obj(length, "Запись META")
            schema = obj.get("schema")
            if isinstance(schema, bool) or not isinstance(schema, int):
                raise FormatError("META: отсутствует схема данных")
            if schema != PAYLOAD_SCHEMA:
                raise FormatError(f"Неподдерживаемая схема данных: {schema}")
        elif rtype == R_MEMORY:
            read_json_obj(length, "Запись воспоминания")
            memories += 1
        elif rtype == R_FILE:
            if length < 4:
                raise FormatError("Запись файла слишком коротка")
            meta_len = struct.unpack(">I", src.read_exact(4))[0]
            if meta_len > length - 4:
                raise FormatError("Метаданные файла выходят за границы записи")
            meta = read_json_obj(meta_len, "Метаданные файла")
            fid = meta.get("id")
            if not isinstance(fid, str) or not fid:
                raise FormatError("Некорректный id файла")
            if not isinstance(meta.get("name", ""), str) or not isinstance(meta.get("type", ""), str):
                raise FormatError(f"Некорректные метаданные файла {fid}")
            for _ in src.iter_exact(length - 4 - meta_len):   # без накопления в памяти
                pass
            files += 1
        elif rtype == R_END:
            if length != 16:
                raise FormatError("Некорректная запись END")
            declared = struct.unpack(">QQ", src.read_exact(16))
            if declared != (memories, files):
                raise FormatError(f"Счётчики записей не совпадают: в END {declared}, "
                                  f"прочитано {(memories, files)}")
            if src.read_some(1):
                raise FormatError("Лишние данные в конце контейнера")
            return memories, files
        else:
            raise FormatError(f"Неизвестный тип записи: {rtype}")
        first = False


def convert_v5_payload(src: Source, cfg):
    """v5-payload (JSON_LEN | JSON-манифест | файлы) -> поток записей v6.
    Генератор; файлы идут потоком, манифест (ограниченный) целиком в RAM."""
    json_len = struct.unpack(">I", src.read_exact(4))[0]
    if json_len > cfg.max_v5_manifest_bytes:
        raise FormatError(f"Манифест v5 слишком велик ({json_len} Б; "
                          f"лимит HIMORPS_MAX_V5_MANIFEST_BYTES)")
    raw = src.read_exact(json_len)
    try:
        manifest = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise FormatError("Манифест повреждён")
    del raw
    if not isinstance(manifest, dict):
        raise FormatError("Некорректная структура манифеста")
    memories = manifest.get("memories", [])
    files = manifest.get("files", [])
    if not isinstance(memories, list) or not isinstance(files, list):
        raise FormatError("Некорректная структура манифеста")
    seen = set()
    for f in files:
        if not isinstance(f, dict):
            raise FormatError("Некорректная запись о файле")
        fid = f.get("id")
        if not isinstance(fid, str) or not fid or fid in seen:
            raise FormatError("Некорректный или повторяющийся id файла")
        seen.add(fid)
        if not isinstance(f.get("name", ""), str) or not isinstance(f.get("type", ""), str):
            raise FormatError(f"Некорректные метаданные файла {fid}")
        size = f.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise FormatError(f"Некорректный размер файла {fid}: {size}")

    yield pack_record(R_META, json.dumps({"schema": PAYLOAD_SCHEMA, "converted_from": VERSION_V5}).encode())
    for m in memories:
        if not isinstance(m, dict):
            raise FormatError("Некорректная запись воспоминания")
        yield pack_record(R_MEMORY, json.dumps(m, ensure_ascii=False).encode('utf-8'))
    for f in files:
        meta = json.dumps({"id": f["id"], "name": f.get("name", ""), "type": f.get("type", "")},
                          ensure_ascii=False).encode('utf-8')
        size = f["size"]
        yield struct.pack(RECORD_HDR_FMT, R_FILE, 4 + len(meta) + size) + struct.pack(">I", len(meta)) + meta
        for piece in src.iter_exact(size):
            yield piece
    if src.read_some(1):
        raise FormatError("Лишние данные в конце контейнера")
    yield pack_record(R_END, struct.pack(">QQ", len(memories), len(files)))


def payload_chunks(fp, hdr: Header, key: bytes, cfg):
    """Единый поток payload v6 для любого поддерживаемого контейнера.
    fp должен стоять сразу после заголовка."""
    dec = iter_decrypt(fp, key, hdr)
    if hdr.version == VERSION:
        return dec
    return convert_v5_payload(Source(lambda: next(dec, b'')), cfg)


# --- Резервный режим скачивания (одноразовые токены) ---------------------------
_staged = {}            # token -> (path, size, expires_at)
_staged_lock = threading.Lock()


def _sweep_staged_locked(now):
    for tok in [t for t, (_, _, exp) in _staged.items() if exp <= now]:
        _safe_remove(_staged.pop(tok)[0])


def stage_check_capacity():
    with _staged_lock:
        _sweep_staged_locked(time.time())
        if len(_staged) >= CFG.max_staged:
            raise TooManyStaged()


_sweeper_started = False


def _start_staged_sweeper():
    """Фоновая очистка: без неё забытый (не скачанный) архив лежал бы на диске до
    следующего обращения к API — для огромных архивов это недопустимо долго."""
    global _sweeper_started
    with _staged_lock:
        if _sweeper_started:
            return
        _sweeper_started = True

    def loop():
        period = max(1, min(30, CFG.stage_ttl_sec // 2 or 1))
        while True:
            time.sleep(period)
            with _staged_lock:
                _sweep_staged_locked(time.time())

    threading.Thread(target=loop, name="staged-sweeper", daemon=True).start()


def stage_put(path, size) -> str:
    _start_staged_sweeper()
    with _staged_lock:
        now = time.time()
        _sweep_staged_locked(now)
        if len(_staged) >= CFG.max_staged:
            raise TooManyStaged()
        token = secrets.token_urlsafe(32)
        _staged[token] = (path, size, now + CFG.stage_ttl_sec)
        return token


def stage_take(token):
    with _staged_lock:
        _sweep_staged_locked(time.time())
        entry = _staged.pop(token, None)
    return entry


# --- HTTP ----------------------------------------------------------------------
@app.after_request
def api_headers(resp):
    # Единая точка: срабатывает и для успешных ответов, и для ошибок
    # (в т.ч. 404/405/413/500 из обработчиков ошибок Flask).
    if request.path.startswith('/api/'):
        resp.headers['Cache-Control'] = 'no-store'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        if getattr(g, 'close_conn', False):
            resp.headers['Connection'] = 'close'
    return resp


@app.errorhandler(413)
def too_large(_e):
    g.close_conn = True      # тело не прочитано — соединение переиспользовать нельзя
    return jsonify({"error": "Слишком большой запрос (HIMORPS_MAX_UPLOAD_BYTES)"}), 413


@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "Не найдено"}), 404


@app.errorhandler(405)
def not_allowed(_e):
    return jsonify({"error": "Метод не поддерживается"}), 405


def _json_error(status, message):
    return jsonify({"error": message}), status


def _failure(exc, op):
    """Преобразует исключение операции в JSON-ответ (+ дочитывает тело)."""
    if isinstance(exc, FormatError):
        _drain_request()
        return _json_error(400, f"{op}: {exc}")
    if isinstance(exc, OutOfSpace):
        _drain_request()
        return _json_error(507, str(exc))
    if isinstance(exc, TooManyStaged):
        _drain_request()
        return _json_error(503, "Слишком много неполученных архивов: скачайте или подождите "
                                f"{CFG.stage_ttl_sec} с (HIMORPS_MAX_STAGED)")
    if isinstance(exc, OSError) and exc.errno in (errno.ENOSPC, errno.EDQUOT):
        _drain_request()
        return _json_error(507, "Во время записи закончилось место на диске во временном каталоге "
                                f"({workdir()}); временные данные удалены")
    if isinstance(exc, OSError) and exc.errno == errno.EFBIG:
        # предел размера ОДНОГО файла (FAT32: 4 ГиБ, ulimit -f и т.п.) — это ограничение
        # файловой системы/окружения, а не формата
        _drain_request()
        return _json_error(507, "Временный файл достиг предела размера файла в файловой системе "
                                f"({workdir()}); задайте HIMORPS_TMPDIR на другой диск")
    if isinstance(exc, (ConnectionError, TimeoutError)):
        # клиент отменил операцию или пропал: это штатная ситуация, ответ уже некому читать
        app.logger.info("%s: клиент прервал соединение (%s)", op, type(exc).__name__)
        g.close_conn = True
        return _json_error(400, f"{op}: соединение прервано")
    app.logger.error("%s failed", op, exc_info=exc)
    g.close_conn = True
    return _json_error(500, f"{op}: внутренняя ошибка сервера")


@app.route('/')
def index():
    return Response(HTML_TEMPLATE, mimetype='text/html')


@app.route('/api/export', methods=['POST'])
def export_vault():
    """Тело (application/octet-stream): PW_LEN(2) | PASSWORD | payload v6 (записи).
    Сервер валидирует записи на лету, шифрует кусками и пишет ТОЛЬКО шифротекст
    во временный файл. Затем (A) отдаёт его потоком либо (B, ?stage=1) выдаёт токен."""
    stage = request.args.get('stage') == '1'
    tmp_path = None
    try:
        if stage:
            stage_check_capacity()
        cl = request.content_length
        if cl is not None:
            require_disk(cl + (cl // CFG.chunk_size + 2) * TAG_SIZE + 4 * KiB)

        src = Source(lambda: request.stream.read(IO_STEP))
        password = read_password(src)

        salt = os.urandom(NEW_SALT_LEN)
        prefix = os.urandom(NONCE_PREFIX_LEN)
        header = pack_header_v6(salt, prefix, CFG.chunk_size,
                                CFG.kdf_iterations, CFG.kdf_memory_kib, CFG.kdf_lanes)
        key = derive_key(password, salt, CFG.kdf_iterations, CFG.kdf_memory_kib, CFG.kdf_lanes)

        fd, tmp_path = new_temp()
        guard = DiskGuard()
        with os.fdopen(fd, 'wb') as out:
            out.write(header)
            enc = StreamEncryptor(out, key, header, prefix, CFG.chunk_size)

            def sink(b):
                guard.account(len(b))
                enc.write(b)

            src.tee = sink                      # пароль в шифруемый поток не попадает
            validate_payload(src, CFG)
            enc.finish()
        total = os.path.getsize(tmp_path)

        if stage:
            token = stage_put(tmp_path, total)
            tmp_path = None                      # владение у реестра
            return jsonify({"token": token, "size": total, "filename": "memory_vault.himorps0"})
    except HTTPException:
        if tmp_path:
            _safe_remove(tmp_path)
        raise
    except Exception as e:
        if tmp_path:
            _safe_remove(tmp_path)
        return _failure(e, "Ошибка упаковки")

    def generate():
        with open(path, 'rb') as fp:
            while True:
                b = fp.read(IO_STEP)
                if not b:
                    break
                yield b

    path = tmp_path
    resp = Response(generate(), mimetype='application/octet-stream')
    resp.headers['Content-Length'] = str(total)
    resp.headers['Content-Disposition'] = 'attachment; filename="memory_vault.himorps0"'
    resp.call_on_close(lambda: _safe_remove(path))      # сработает и при обрыве клиента
    return resp


@app.route('/api/download/<token>', methods=['GET'])
def download_staged(token):
    """Резервный режим: одноразовая выдача подготовленного контейнера."""
    entry = stage_take(token)
    if entry is None:
        return _json_error(404, "Ссылка недействительна, уже использована или истекла")
    path, size, _ = entry
    if not os.path.exists(path):
        return _json_error(404, "Файл больше недоступен")

    def generate():
        with open(path, 'rb') as fp:
            while True:
                b = fp.read(IO_STEP)
                if not b:
                    break
                yield b

    resp = Response(generate(), mimetype='application/octet-stream')
    resp.headers['Content-Length'] = str(size)
    resp.headers['Content-Disposition'] = 'attachment; filename="memory_vault.himorps0"'
    resp.call_on_close(lambda: _safe_remove(path))
    return resp


@app.route('/api/import', methods=['POST'])
def import_vault():
    """Тело: PW_LEN(2) | PASSWORD | байты контейнера (v5 или v6).
    Ответ: payload v6 (записи) потоком. Сначала весь контейнер проверяется
    (проход 1, данные отбрасываются), и только затем идёт поток клиенту
    (проход 2) — ошибка аутентификации посреди ответа невозможна.
    Plaintext на диск не пишется; на диске только присланный шифротекст."""
    tmp_path = None
    try:
        cl = request.content_length
        if cl is not None:
            require_disk(cl)
        src = Source(lambda: request.stream.read(IO_STEP))
        password = read_password(src)

        fd, tmp_path = new_temp()
        guard = DiskGuard()
        with os.fdopen(fd, 'wb') as tmp:
            while True:
                b = src.read_some(IO_STEP)
                if not b:
                    break
                guard.account(len(b))
                tmp.write(b)

        # Проход 1: заголовок (с проверкой KDF до Argon2id) -> ключ -> полная проверка
        with open(tmp_path, 'rb') as fp:
            hdr = read_header(fp, CFG)
            key = derive_key(password, hdr.salt, hdr.t, hdr.m, hdr.p)
            counted = [0]

            def counting():
                for c in payload_chunks(fp, hdr, key, CFG):
                    counted[0] += len(c)
                    yield c

            it = counting()
            validate_payload(Source(lambda: next(it, b'')), CFG)
            total = counted[0]
    except HTTPException:
        if tmp_path:
            _safe_remove(tmp_path)
        raise
    except Exception as e:
        if tmp_path:
            _safe_remove(tmp_path)
        return _failure(e, "Ошибка расшифровки")

    path = tmp_path

    def generate():     # Проход 2
        with open(path, 'rb') as fp:
            fp.seek(hdr.size)
            for piece in payload_chunks(fp, hdr, key, CFG):
                yield piece

    resp = Response(generate(), mimetype='application/octet-stream')
    resp.headers['Content-Length'] = str(total)
    resp.call_on_close(lambda: _safe_remove(path))
    return resp


# --- ИНТЕРФЕЙС ---
HTML_TEMPLATE = r"""
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
            <button id="cancelBtn" onclick="cancelOp()" style="display:none">Отмена</button>
        </div>
        <div id="opStatus" style="font-size: 12px; margin-top: 8px; min-height: 1.2em;"></div>
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
        <div id="listInfo" style="font-size: 12px;"></div>
        <div id="listTop" style="display:none"><button onclick="listFromTop()">↑ К началу списка</button></div>
        <div id="memoryList"></div>
        <div id="listMore" style="display:none"><button onclick="renderNextPage()">Показать ещё</button></div>
    </div>
</div>

<!-- LIGHTBOX VIEWER -->
<div class="lightbox" id="lightbox" onclick="closeLightbox()">
    <img id="lightboxImg" src="" onclick="event.stopPropagation()">
    <div class="lightbox-close">[ Нажмите в любом месте, чтобы закрыть ]</div>
</div>

<script>
    // ===== Состояние =====
    let vaultMemories = [];
    let vaultFiles = Object.create(null);   // { fileId: { name, type, size, blob } } — blob это File/Blob, не Base64
    let saveCounter = 0;
    let busy = false;
    let currentAbort = null;
    const blobUrlCache = Object.create(null);

    const textEnc = new TextEncoder();
    const textDec = new TextDecoder();

    // ===== Формат payload v6: записи TYPE(1) | LENGTH(8, u64 BE) | BODY =====
    const REC = { META: 1, MEMORY: 2, FILE: 3, END: 4 };
    const REC_HEADER_SIZE = 9;
    const PAYLOAD_SCHEMA = 1;
    const BATCH_BYTES = 1024 * 1024;               // мелкие записи склеиваются в Blob порциями ~1 МиБ
    const BLOB_FLUSH_BYTES = 32 * 1024 * 1024;     // файлы при импорте собираются в Blob порциями
    const MAX_JSON_IN_RAM = 256 * 1024 * 1024;     // защитный потолок JSON одной записи на клиенте
    const PAGE_SIZE = 50;                          // сколько карточек рисуется за раз
    const TIMELINE_BUCKETS = 400;                  // точки шкалы времени склеиваются в корзины

    // Режим экспорта: A — потоковая запись в файл (File System Access API),
    // B — резервный: сервер хранит готовый архив, браузер качает его менеджером загрузок.
    const SAVE_PICKER = typeof window.showSaveFilePicker === 'function';

    function toggleTheme() {
        document.body.classList.toggle('theme-y2k');
    }

    function setStatus(text) {
        document.getElementById('opStatus').textContent = text;
    }

    function setBusy(on) {
        busy = on;
        document.getElementById('cancelBtn').style.display = on ? '' : 'none';
    }

    function cancelOp() {
        if (currentAbort) currentAbort.abort();
    }

    // ===== Бинарные хелперы =====
    function u16(n) {
        const b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, n, false);
        return b;
    }

    function u32(n) {
        const b = new ArrayBuffer(4);
        new DataView(b).setUint32(0, n, false);
        return new Uint8Array(b);
    }

    // Длины — u64 на проводе; в JS точны до 2^53-1 (Number.MAX_SAFE_INTEGER)
    function recHeader(type, len) {
        if (!Number.isSafeInteger(len) || len < 0) {
            throw new Error('Размер записи вне диапазона, который браузер умеет считать точно (2^53-1 байт)');
        }
        const b = new Uint8Array(REC_HEADER_SIZE);
        const v = new DataView(b.buffer);
        v.setUint8(0, type);
        v.setBigUint64(1, BigInt(len), false);
        return b;
    }

    function u64ToNumber(big) {
        if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error('Размер записи превышает возможности браузера (2^53-1 байт)');
        }
        return Number(big);
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

        async atEnd() {
            while (this.pos >= this.chunk.length) {
                if (!(await this._fill())) return true;
            }
            return false;
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

    // Разбор потока записей. Всё собирается в локальные переменные; состояние
    // приложения подменяется вызывающим только после полного успеха.
    async function readPayload(reader, onProgress) {
        const memories = [];
        const files = Object.create(null);
        let nMem = 0, nFiles = 0;

        const readJson = async (n, what) => {
            if (n > MAX_JSON_IN_RAM) throw new Error(what + ' слишком велика для браузера');
            return JSON.parse(textDec.decode(await reader.readBytes(n)));
        };

        for (let first = true; ; first = false) {
            const hdr = await reader.readBytes(REC_HEADER_SIZE);
            const dv = new DataView(hdr.buffer, hdr.byteOffset, hdr.byteLength);
            const type = dv.getUint8(0);
            const len = u64ToNumber(dv.getBigUint64(1, false));

            if (first && type !== REC.META) throw new Error('Архив не начинается с записи META');

            if (type === REC.META) {
                if (!first) throw new Error('Повторная запись META');
                const meta = await readJson(len, 'Запись META');
                if (meta.schema !== PAYLOAD_SCHEMA) {
                    throw new Error('Неподдерживаемая схема данных: ' + meta.schema);
                }
            } else if (type === REC.MEMORY) {
                const m = await readJson(len, 'Запись воспоминания');
                if (m === null || typeof m !== 'object' || Array.isArray(m)) {
                    throw new Error('Некорректная запись воспоминания');
                }
                memories.push(m);
                nMem++;
            } else if (type === REC.FILE) {
                if (len < 4) throw new Error('Запись файла слишком коротка');
                const metaLen = new DataView((await reader.readBytes(4)).buffer).getUint32(0, false);
                if (metaLen > len - 4) throw new Error('Метаданные файла выходят за границы записи');
                const meta = await readJson(metaLen, 'Метаданные файла');
                if (typeof meta.id !== 'string' || !meta.id) throw new Error('Некорректный id файла');
                if (meta.id in files) throw new Error('Повторяющийся id файла: ' + meta.id);
                const type_ = (typeof meta.type === 'string' && meta.type) || 'application/octet-stream';
                const size = len - 4 - metaLen;
                files[meta.id] = {
                    name: (typeof meta.name === 'string' && meta.name) || 'unnamed',
                    type: type_,
                    size: size,
                    blob: await reader.readBlob(size, type_)
                };
                nFiles++;
            } else if (type === REC.END) {
                if (len !== 16) throw new Error('Некорректная запись END');
                const c = new DataView((await reader.readBytes(16)).buffer);
                if (u64ToNumber(c.getBigUint64(0, false)) !== nMem || u64ToNumber(c.getBigUint64(8, false)) !== nFiles) {
                    throw new Error('Счётчики записей в END не совпадают с прочитанным');
                }
                if (!(await reader.atEnd())) throw new Error('Лишние данные после записи END');
                break;
            } else {
                throw new Error('Неизвестный тип записи: ' + type);
            }
            if (onProgress) onProgress(nMem, nFiles);
        }

        // Структура связей воспоминание -> файл проверяется до того, как что-либо попадёт в интерфейс.
        // Ссылка на отсутствующий файл НЕ делает архив нечитаемым (как и раньше, такое вложение
        // просто не показывается), но считается и показывается пользователю как предупреждение.
        let dangling = 0;
        for (const m of memories) {
            if (m.attachmentIds == null) continue;
            if (!Array.isArray(m.attachmentIds)) throw new Error('Некорректный список вложений у воспоминания ' + m.id);
            for (const fid of m.attachmentIds) {
                if (typeof fid !== 'string') throw new Error('Некорректный id вложения у воспоминания ' + m.id);
                if (!(fid in files)) dangling++;
            }
        }
        return { memories, files, dangling };
    }

    // Тело экспорта: PW_LEN | PASSWORD | META | (файлы воспоминания, MEMORY)... | файлы-сироты | END.
    // Blob склеивается лениво: файлы остаются ссылками на диск, мелкие записи
    // упаковываются порциями ~1 МиБ — никаких гигантских строк/массивов.
    function buildExportBody(password) {
        const parts = [...passwordPrefix(password)];
        let batch = [];
        let batchBytes = 0;
        const flush = () => {
            if (batch.length) {
                parts.push(new Blob(batch));
                batch = [];
                batchBytes = 0;
            }
        };
        const add = (u8) => {
            batch.push(u8);
            batchBytes += u8.length;
            if (batchBytes >= BATCH_BYTES) flush();
        };
        const addRecord = (type, body) => {
            add(recHeader(type, body.length));
            add(body);
        };

        let nMem = 0, nFiles = 0;
        const emitted = new Set();
        const emitFile = (fid) => {
            const f = vaultFiles[fid];
            if (!f || emitted.has(fid)) return;
            emitted.add(fid);
            const meta = textEnc.encode(JSON.stringify({ id: fid, name: f.name, type: f.type }));
            add(recHeader(REC.FILE, 4 + meta.length + f.blob.size));
            add(u32(meta.length));
            add(meta);
            flush();                      // порядок: заголовок файла -> сам Blob -> дальше
            parts.push(f.blob);
            nFiles++;
        };

        addRecord(REC.META, textEnc.encode(JSON.stringify({ schema: PAYLOAD_SCHEMA, app: 'himorps0-vault' })));
        for (const m of vaultMemories) {
            let out = m;
            if (Array.isArray(m.attachmentIds)) {
                const ids = m.attachmentIds.filter(id => vaultFiles[id]);
                ids.forEach(emitFile);
                if (ids.length !== m.attachmentIds.length) out = { ...m, attachmentIds: ids };  // без висячих ссылок
            }
            addRecord(REC.MEMORY, textEnc.encode(JSON.stringify(out)));
            nMem++;
        }
        for (const fid of Object.keys(vaultFiles)) emitFile(fid);   // файлы без воспоминаний

        const end = new Uint8Array(16);
        const ev = new DataView(end.buffer);
        ev.setBigUint64(0, BigInt(nMem), false);
        ev.setBigUint64(8, BigInt(nFiles), false);
        addRecord(REC.END, end);
        flush();
        return new Blob(parts);
    }

    // ===== Blob-ссылки на вложения =====
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
        viewDirty = true;
        render();
        document.getElementById('memTitle').value = '';
        document.getElementById('memText').value = '';
        document.getElementById('memAttachments').value = '';
    }

    // ===== Отображение: шкала времени (корзины) и ленивый список =====
    let viewDirty = true;          // индекс отсортированных записей нужно пересобрать
    let sortedEntries = [];        // [{ m, t }] по убыванию времени
    let currentView = [];          // после фильтра по периоду
    let viewOffset = 0;            // с какого индекса currentView начат показ
    let renderedCount = 0;         // до какого (не включая) отрисовано
    let moreObserver = null;

    function ensureSorted() {
        if (!viewDirty) return;
        sortedEntries = vaultMemories.map(m => {
            const t = Date.parse(m.datetime);
            return { m, t: Number.isNaN(t) ? 0 : t };
        });
        sortedEntries.sort((a, b) => b.t - a.t);
        viewDirty = false;
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
        if (!(totalDuration > 0)) return;

        ensureSorted();
        let inRange = 0;
        for (const e of sortedEntries) if (e.t >= birthTime && e.t <= nowTime) inRange++;

        // До TIMELINE_BUCKETS записей — по точке на запись, как раньше. Больше — не более
        // TIMELINE_BUCKETS точек в DOM: близкие по времени записи склеиваются в корзины.
        const dots = [];
        if (inRange <= TIMELINE_BUCKETS) {
            for (const e of sortedEntries) if (e.t >= birthTime && e.t <= nowTime) dots.push({ n: 1, e });
        } else {
            const buckets = new Map();
            for (const e of sortedEntries) {
                if (e.t < birthTime || e.t > nowTime) continue;
                const b = Math.min(TIMELINE_BUCKETS - 1, Math.floor((e.t - birthTime) / totalDuration * TIMELINE_BUCKETS));
                const cur = buckets.get(b);
                if (cur) cur.n++; else buckets.set(b, { n: 1, e });
            }
            dots.push(...buckets.values());
        }
        const frag = document.createDocumentFragment();
        for (const { n, e } of dots) {
            const pct = ((e.t - birthTime) / totalDuration) * 100;
            const dot = document.createElement('div');
            dot.className = 'timeline-dot';
            dot.style.left = `${Math.max(0, Math.min(100, pct))}%`;
            dot.title = n === 1
                ? `${e.m.title || 'Запись'} (${e.m.datetime})`
                : `${n} записей (около ${e.m.datetime})`;
            dot.onclick = () => scrollToCard(e.m.id);
            frag.appendChild(dot);
        }
        axis.appendChild(frag);
    }

    function renderList() {
        ensureSorted();
        const fromVal = document.getElementById('filterFrom').value;
        const toVal = document.getElementById('filterTo').value;
        const fromTime = fromVal ? new Date(fromVal).getTime() : 0;
        const toTime = toVal ? new Date(toVal).getTime() : Infinity;

        currentView = (fromTime === 0 && toTime === Infinity)
            ? sortedEntries
            : sortedEntries.filter(e => e.t >= fromTime && e.t <= toTime);
        resetList(0);
    }

    function resetList(offset) {
        document.getElementById('memoryList').innerHTML = '';
        viewOffset = offset;
        renderedCount = offset;
        renderNextPage();
    }

    function renderNextPage() {
        const list = document.getElementById('memoryList');
        const end = Math.min(renderedCount + PAGE_SIZE, currentView.length);
        const frag = document.createDocumentFragment();
        for (let i = renderedCount; i < end; i++) frag.appendChild(buildCard(currentView[i].m));
        list.appendChild(frag);
        renderedCount = end;
        updateListControls();
    }

    function listFromTop() {
        resetList(0);
        document.getElementById('memoryList').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function updateListControls() {
        const total = currentView.length;
        const remaining = total - renderedCount;
        document.getElementById('listInfo').textContent = total === 0 ? '' :
            (viewOffset > 0
                ? `Записи ${viewOffset + 1}–${renderedCount} из ${total}`
                : `Показано ${renderedCount} из ${total}`);
        document.getElementById('listTop').style.display = viewOffset > 0 ? '' : 'none';

        const more = document.getElementById('listMore');
        if (remaining > 0) {
            more.style.display = '';
            more.firstElementChild.textContent = `Показать ещё (${remaining})`;
            if ('IntersectionObserver' in window) {
                if (!moreObserver) {
                    moreObserver = new IntersectionObserver(entries => {
                        if (entries.some(en => en.isIntersecting)) renderNextPage();
                    }, { rootMargin: '600px' });
                }
                moreObserver.unobserve(more);   // повторная подписка заново запускает проверку видимости
                moreObserver.observe(more);
            }
        } else {
            more.style.display = 'none';
            if (moreObserver) moreObserver.unobserve(more);
        }
    }

    function buildCard(m) {
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

        if (Array.isArray(m.attachmentIds) && m.attachmentIds.length > 0) {
            const mediaDiv = document.createElement('div');
            m.attachmentIds.forEach(fid => {
                const fObj = vaultFiles[fid];
                if (!fObj) return;
                const blobUrl = getFileBlobUrl(fid);   // создаётся лениво, только для показанных карточек

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
                    audio.preload = 'none';
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
        return card;
    }

    function scrollToCard(id) {
        const idx = currentView.findIndex(e => e.m.id === id);
        if (idx < 0) return;                       // запись скрыта фильтром
        if (idx < viewOffset || idx >= renderedCount) {
            if (idx >= renderedCount && idx - renderedCount < 2 * PAGE_SIZE) {
                while (renderedCount <= idx) renderNextPage();
            } else {
                resetList(Math.max(0, idx - 2));   // далёкая запись: начинаем показ с неё
            }
        }
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

    // ===== Экспорт =====
    async function errorFromResponse(res, fallback) {
        const errData = await res.json().catch(() => ({}));
        return new Error(errData.error || fallback);
    }

    // Режим A: ответ пишется в файл кусками. Закрытие (commit) — только после
    // проверки полной длины; при любой ошибке запись отменяется (abort).
    async function saveStreamToHandle(res, handle) {
        const expected = parseInt(res.headers.get('Content-Length') || '', 10);
        const writable = await handle.createWritable();
        const reader = res.body.getReader();
        let written = 0;
        let lastUi = 0;
        try {
            for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                await writable.write(value);
                written += value.byteLength;
                const now = performance.now();
                if (now - lastUi > 250) {
                    lastUi = now;
                    setStatus(`Запись в файл: ${(written / 1048576).toFixed(1)} МиБ` +
                        (Number.isFinite(expected) ? ` из ${(expected / 1048576).toFixed(1)}` : ''));
                }
            }
            if (Number.isFinite(expected) && written !== expected) {
                throw new Error(`Получено ${written} из ${expected} байт — файл не сохранён`);
            }
            await writable.close();
        } catch (e) {
            try { await writable.abort(); } catch (_) { /* уже закрыт/отменён */ }
            throw e;
        }
        return written;
    }

    // Режим B: сервер выдал одноразовый токен — браузер скачивает файл сам.
    function startNativeDownload(info) {
        const a = document.createElement('a');
        a.href = '/api/download/' + encodeURIComponent(info.token);
        a.download = info.filename || 'memory_vault.himorps0';
        document.body.appendChild(a);
        a.click();
        a.remove();
    }

    async function exportVault() {
        if (busy) return;
        const password = document.getElementById('vaultPassword').value;
        if (!password) return alert('Введите мастер-пароль!');
        try { passwordPrefix(password); } catch (e) { return alert(e.message); }

        // Диалог сохранения должен открываться сразу из обработчика клика (user activation),
        // поэтому он идёт ДО подготовки данных и запроса.
        setBusy(true);                   // повторный клик, пока открыт диалог, не запустит второй экспорт
        let handle = null;
        let handleWasEmpty = false;      // удалять при неудаче можно ТОЛЬКО созданный нами пустой файл
        if (SAVE_PICKER) {
            try {
                handle = await window.showSaveFilePicker({
                    suggestedName: 'memory_vault.himorps0',
                    types: [{ description: 'HIMORPS0 vault', accept: { 'application/octet-stream': ['.himorps0'] } }]
                });
                try { handleWasEmpty = (await handle.getFile()).size === 0; } catch (_) { handleWasEmpty = false; }
            } catch (e) {
                if (e && e.name === 'AbortError') { setBusy(false); setStatus('Экспорт отменён'); return; }
                handle = null;       // нет прав/контекста — уходим на резервный режим B
            }
        }

        const ctl = new AbortController();
        currentAbort = ctl;
        let committed = false;
        try {
            setStatus('Подготовка данных…');
            const body = buildExportBody(password);
            setStatus('Отправка на шифрование…');
            const res = await fetch(handle ? '/api/export' : '/api/export?stage=1', {
                method: 'POST',
                headers: { 'Content-Type': 'application/octet-stream' },
                body: body,
                signal: ctl.signal
            });
            if (!res.ok) throw await errorFromResponse(res, 'Ошибка экспорта');

            if (handle) {
                const bytes = await saveStreamToHandle(res, handle);
                committed = true;
                setStatus(`Архив сохранён потоково: ${(bytes / 1048576).toFixed(1)} МиБ`);
            } else {
                startNativeDownload(await res.json());
                committed = true;
                setStatus('Архив готов: скачивание передано менеджеру загрузок браузера (резервный режим)');
            }
            saveCounter++;
            document.getElementById('saveCount').textContent = saveCounter;
        } catch (e) {
            // Если пользователь выбрал для перезаписи СУЩЕСТВУЮЩИЙ непустой файл, его не трогаем:
            // createWritable() пишет в своп и подменяет файл только при close(), abort() оставляет оригинал.
            if (handle && !committed && handleWasEmpty && typeof handle.remove === 'function') {
                try { await handle.remove(); } catch (_) { /* пустой файл мог остаться — это ограничение API */ }
            }
            if (e && e.name === 'AbortError') {
                setStatus('Экспорт отменён');
            } else {
                setStatus('Ошибка экспорта');
                alert('Ошибка экспорта: ' + (e && e.message ? e.message : e));
            }
        } finally {
            currentAbort = null;
            setBusy(false);
        }
    }

    // ===== Импорт =====
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

        const ctl = new AbortController();
        currentAbort = ctl;
        setBusy(true);
        try {
            // Тело = PW_LEN | PASSWORD | байты контейнера (без Base64 и без FormData)
            const body = new Blob([...passwordPrefix(password), file]);
            setStatus('Отправка и проверка контейнера на сервере…');
            const res = await fetch('/api/import', {
                method: 'POST',
                headers: { 'Content-Type': 'application/octet-stream' },
                body: body,
                signal: ctl.signal
            });
            if (!res.ok) throw await errorFromResponse(res, 'Ошибка расшифровки или неверный пароль');

            // Сервер уже проверил весь контейнер, дальше идёт только чтение потока
            let lastUi = 0;
            const { memories, files, dangling } = await readPayload(new StreamReader(res.body), (nm, nf) => {
                const now = performance.now();
                if (now - lastUi > 250) {
                    lastUi = now;
                    setStatus(`Загрузка: воспоминаний ${nm}, файлов ${nf}`);
                }
            });

            // Подмена состояния — только после полного успешного разбора и проверки связей
            clearBlobCache();
            vaultMemories = memories;
            vaultFiles = files;
            viewDirty = true;
            saveCounter++;
            render();
            const warn = dangling > 0 ? `; ссылок на отсутствующие в архиве файлы: ${dangling} (пропущены)` : '';
            setStatus(`Архив загружен: воспоминаний ${memories.length}, файлов ${Object.keys(files).length}${warn}`);
            alert('Архив успешно загружен!' + (dangling > 0 ? `\nВнимание: ссылок на отсутствующие файлы: ${dangling}.` : ''));
        } catch (e) {
            if (e && e.name === 'AbortError') {
                setStatus('Импорт отменён; текущие данные не изменены');
            } else {
                setStatus('Ошибка импорта; текущие данные не изменены');
                alert('Ошибка импорта: ' + (e && e.message ? e.message : e));
            }
        } finally {
            currentAbort = null;
            setBusy(false);
            event.target.value = '';
        }
    }

    setStatus(SAVE_PICKER
        ? 'Режим экспорта: потоковая запись в выбранный файл (File System Access API)'
        : 'Режим экспорта: резервный — готовый архив скачивается менеджером загрузок браузера');
    render();
</script>
</body>
</html>
"""


def main():
    import signal
    # SIGTERM -> штатный выход, чтобы atexit удалил временный каталог
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    workdir()
    app.run(debug=False, host=CFG.host, port=CFG.port, threaded=True)


if __name__ == '__main__':
    main()
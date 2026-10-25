"""Журнал аудита с хэш-цепочкой: укреплённая версия реализации C.

Только стандартная библиотека. Для событий, которые принимают и исходная C,
и эта версия, хэши записей совпадают, поэтому записи C проходят verify отсюда,
а записи отсюда проходят verify из C.

Что добавлено к C:
- точные типы вместо подклассов: иначе события, различные по ==, дают один хэш;
- проверка события без рекурсии и с лимитами глубины, числа узлов и суммарной
  длины ключей и строк: защита от циклов, разросшихся общих ссылок и огромных событий;
- целые только в пределах 64 бит, чтобы приём события не зависел от версии Python;
- строгая форма записи: ровно четыре ключа, лишнее поле считается порчей;
- блокировка в append, head и records;
- verify не бросает исключений на испорченных записях.

Границы честности: без внешнего anchor усечение хвоста и полная пересборка цепочки
не видны, хэш без секрета не подпись, а float хэшируются через repr Python,
так что переносить проверку в другой язык без отдельной канонизации чисел нельзя.
"""
from __future__ import annotations

import hashlib
import json
import math
import threading

MAX_DEPTH = 64
MAX_NODES = 100_000
MAX_TEXT = 1_000_000
INT_MIN = -(2 ** 63)
INT_MAX = 2 ** 64 - 1

_KEYS = frozenset(("index", "prev", "event", "hash"))


def _check_event(event) -> None:
    """Бросает TypeError или ValueError, если событие не годится для журнала."""
    if type(event) is not dict:
        raise TypeError("event must be a dict")
    nodes = 0
    text = 0
    stack = [(event, 1)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise ValueError("event has too many nodes")
        kind = type(value)
        if value is None or kind is bool:
            continue
        if kind is str:
            text += len(value)
            if text > MAX_TEXT:
                raise ValueError("event text is too long")
            continue
        if kind is int:
            if not INT_MIN <= value <= INT_MAX:
                raise ValueError("integer is out of range")
            continue
        if kind is float:
            if not math.isfinite(value):
                raise ValueError("float must be finite")
            continue
        if kind is list or kind is dict:
            if depth > MAX_DEPTH:
                raise ValueError("event is nested too deeply")
            if kind is list:
                for item in value:
                    stack.append((item, depth + 1))
            else:
                for key, item in value.items():
                    if type(key) is not str:
                        raise TypeError("dict keys must be str")
                    text += len(key)
                    stack.append((item, depth + 1))
            continue
        raise TypeError("unsupported type: " + kind.__name__)


def _canonical(obj) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _record_hash(index: int, prev: str, event: dict) -> str:
    payload = {"index": index, "prev": prev, "event": event}
    return hashlib.sha256(_canonical(payload)).hexdigest()


class AuditLog:
    def __init__(self) -> None:
        self._records: list[dict] = []
        self._lock = threading.RLock()

    def append(self, event: dict) -> str:
        _check_event(event)
        snapshot = json.loads(_canonical(event))
        with self._lock:
            index = len(self._records)
            prev = self._records[-1]["hash"] if self._records else ""
            digest = _record_hash(index, prev, snapshot)
            self._records.append(
                {"index": index, "prev": prev, "event": snapshot, "hash": digest}
            )
            return digest

    def head(self) -> str:
        with self._lock:
            return self._records[-1]["hash"] if self._records else ""

    def records(self) -> list:
        with self._lock:
            return json.loads(_canonical(self._records))


def verify(records, anchor=None):
    """None, если журнал цел. Иначе позиция первой испорченной записи.
    Если цепочка цела, но anchor не совпадает с последним хэшем, len(records)."""
    if not isinstance(records, (list, tuple)):
        raise TypeError("records must be a list or tuple")
    previous = ""
    for i, record in enumerate(records):
        if type(record) is not dict or record.keys() != _KEYS:
            return i
        index = record["index"]
        prev = record["prev"]
        event = record["event"]
        digest = record["hash"]
        if type(index) is not int or index != i:
            return i
        if type(prev) is not str or type(digest) is not str or prev != previous:
            return i
        try:
            _check_event(event)
            expected = _record_hash(i, prev, event)
        except Exception:
            # любая ошибка при разборе испорченной записи считается порчей
            return i
        if digest != expected:
            return i
        previous = digest
    if anchor is not None and anchor != previous:
        return len(records)
    return None

"""Builds tiny PDFs in memory for tests, so no sample files are needed."""
from __future__ import annotations

import zlib
from typing import Dict, List, Tuple, Union


def _b(value: Union[bytes, str]) -> bytes:
    return value if isinstance(value, bytes) else value.encode("latin-1")


def make_pdf(objects: Union[Dict[int, Union[bytes, str]], List[Tuple[int, Union[bytes, str]]]],
             trailer: str = "<< /Root 1 0 R >>") -> bytes:
    """Build a minimal PDF.

    Args:
        objects: Object id -> body (without the ``N 0 obj`` wrapper), or a
            list of ``(id, body)`` pairs so an id can be defined more than once.
        trailer: Trailer dictionary text.

    Returns:
        PDF bytes: header, each object in dict order, then trailer, startxref and EOF.
    """
    out = b"%PDF-1.7\n"
    for num, body in (objects.items() if isinstance(objects, dict) else objects):
        out += b"%d 0 obj\n" % num + _b(body) + b"\nendobj\n"
    # pdf_parser only emits a trailer when "startxref" follows it.
    out += b"trailer\n" + _b(trailer) + b"\nstartxref\n0\n%%EOF\n"
    return out


def stream_obj(dict_entries: str, data: bytes, flate: bool = True) -> bytes:
    """Build a stream object body, Flate-compressed by default."""
    if flate:
        data = zlib.compress(data)
    filt = " /Filter /FlateDecode" if flate else ""
    head = "<< %s /Length %d%s >>\nstream\n" % (dict_entries, len(data), filt)
    return head.encode("latin-1") + data + b"\nendstream"


def objstm_obj(inner: Dict[int, str]) -> bytes:
    """Build a Flate ``/Type /ObjStm`` stream holding the inner objects."""
    index, body = "", ""
    for num, text in inner.items():
        index += "%d %d " % (num, len(body))
        body += text + "\n"
    index = index.strip() + "\n"
    entries = "/Type /ObjStm /N %d /First %d" % (len(inner), len(index))
    return stream_obj(entries, (index + body).encode("latin-1"))

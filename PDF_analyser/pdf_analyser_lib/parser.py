"""Wrapper around the vendored pdf_parser (Didier Stevens).

Loads a PDF into a ``ParsedPdf`` of ``PdfObject`` items, expanding
``/ObjStm`` object streams. Parsing never raises on malformed content;
problems are recorded in ``ParsedPdf.errors`` so the report can say the
parse was partial. Nothing in the file is ever executed.
"""
from __future__ import annotations

import importlib.util
import zlib
from dataclasses import dataclass, field
from io import BytesIO, StringIO
from pathlib import Path
from typing import Dict, List, Optional, Set

from . import config

_VENDOR_PARSER = Path(__file__).resolve().parent.parent / "vendor" / "pdf_parser.py"
_spec = importlib.util.spec_from_file_location("pdf_parser", _VENDOR_PARSER)
pdf_parser = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pdf_parser)


# Size-capped stream decoders. pdf_parser's own FlateDecode, LZWDecode and
# RunLengthDecode have no output limit, so a small hostile stream can use
# gigabytes of memory. pdf_parser looks these names up in its own module when
# it decodes, so replacing them here caps every decode without editing the
# vendored file. Each one behaves like the original apart from the cap, except
# that damaged Flate data is decoded as far as possible instead of failing.
_cuts = [0]      # streams cut at the limit so far; PdfObject.stream() reports new ones
_damaged = [0]   # Flate streams that were truncated or corrupt, reported the same way


def _cap(out):
    if len(out) > config.MAX_STREAM_BYTES:
        _cuts[0] += 1
        return out[:config.MAX_STREAM_BYTES]
    return out


def _flate_decode(data):
    """pdf_parser.FlateDecode with a size cap and a byte-by-byte salvage of damaged data.

    Unlike the original, truncated or corrupt data is decoded as far as it
    goes instead of failing; such streams are counted in ``_damaged``.
    """
    raw = pdf_parser.C2BIP3(data)
    limit = config.MAX_STREAM_BYTES + 1
    try:
        d = zlib.decompressobj()
        out = d.decompress(raw, limit)
        if not d.eof and len(out) < limit:
            _damaged[0] += 1   # the data ends before the end of the compressed stream
        return _cap(out)
    except zlib.error:
        if len(raw) <= 10:
            raise
        d, out = zlib.decompressobj(), bytearray()
        for i in range(len(raw)):
            try:
                out += d.decompress(raw[i:i + 1], limit - len(out))
            except zlib.error:
                break
            if len(out) >= limit:
                break
        if not out:
            raise
        _damaged[0] += 1
        return _cap(bytes(out))


def _lzw_decode(data):
    """pdf_parser.LZWDecode with a size cap."""
    out, size = [], 0
    for chunk in pdf_parser.LZWDecoder(StringIO(data)).run():
        out.append(chunk)
        size += len(chunk)
        if size > config.MAX_STREAM_BYTES:
            break
    return _cap("".join(out))


def _run_length_decode(data):
    """pdf_parser.RunLengthDecode with a size cap (also stops at a 0 length byte, like the original)."""
    f, out, size = StringIO(data), [], 0
    length = ord(f.read(1))
    while length and length != 128 and size <= config.MAX_STREAM_BYTES:
        piece = f.read(length + 1) if length < 128 else f.read(1) * (257 - length)
        out.append(piece)
        size += len(piece)
        length = ord(f.read(1))
    return _cap("".join(out))


pdf_parser.FlateDecode = _flate_decode
pdf_parser.LZWDecode = _lzw_decode
pdf_parser.RunLengthDecode = _run_length_decode


@dataclass
class PdfObject:
    """One indirect object, possibly taken from inside an ``/ObjStm``."""

    id: int
    objstm: Optional[int]   # id of the containing /ObjStm, else None
    element: object         # pdf_parser cPDFElementIndirectObject
    parent: Optional["ParsedPdf"] = field(default=None, repr=False)
    copy: int = 1           # 1-based position among the copies of this id, in file order

    @property
    def duplicated(self) -> bool:
        """True when the file defines this object id more than once."""
        return self.parent is not None and len(self.parent.objects.get(self.id, [])) > 1

    def _dict(self):
        """Parse the object's dictionary; on failure record an error and return an empty parse.

        pdf_parser parses nested dictionaries recursively, so a hostile file
        with thousands of nesting levels raises RecursionError. That must
        not crash the tool: the object is treated as having no dictionary and
        the parse is marked partial.
        """
        try:
            head = self.element.ContainsStream() or self.element.content
            return pdf_parser.cPDFParseDictionary(head, False)
        except Exception as exc:
            if self.parent is not None:
                self.parent.add_error_once(
                    "object %d: dictionary not parsed (%s)" % (self.id, type(exc).__name__))
            return pdf_parser.cPDFParseDictionary([], False)

    def items(self) -> list:
        """Return the top-level ``(key, tokens)`` pairs of the dictionary (may be empty)."""
        return self._dict().parsed or []

    def get(self, key: str):
        """Return the token list for ``key`` in the object's dictionary.

        Args:
            key: Dictionary key such as ``/JS``.

        Returns:
            The pdf_parser token list, or None if the key is absent or the
            object has no parsable dictionary.
        """
        d = self._dict()
        if d.parsed is None:
            return None
        return d.Get(key)

    def has_name(self, name: str) -> bool:
        """Return True if the name appears (hex-escapes such as ``/J#53`` match)."""
        return bool(self.element.ContainsName(name))

    def type(self) -> str:
        """Return the ``/Type`` value (e.g. ``/Catalog``), or an empty string."""
        return self.element.GetType()

    def refs(self) -> List[int]:
        """Return the ids of all objects this object references."""
        return [int(r[0]) for r in self.element.GetReferences()]

    def stream(self) -> Optional[bytes]:
        """Return the stream bytes, or None if the object has no stream.

        Filters are applied. If the filter is unsupported or fails, the raw
        bytes are returned instead and a message is added to the parent's
        ``errors``.
        """
        try:
            if not self.element.ContainsStream():
                return None
        except Exception:   # defensive: parser internals must not crash the tool
            return None
        cuts, damaged = _cuts[0], _damaged[0]
        try:
            data = self.element.Stream(True)
        except Exception as exc:
            data = "decode error: %s" % exc
        if _cuts[0] != cuts and self.parent is not None:
            self.parent.add_error_once("object %d: decoded stream cut at %d MB (decompression limit)"
                                       % (self.id, config.MAX_STREAM_BYTES // (1024 * 1024)))
        if _damaged[0] != damaged and self.parent is not None:
            self.parent.add_error_once("object %d: compressed stream truncated or corrupt "
                                       "(decoded as far as possible)" % self.id)
        if isinstance(data, bytes):
            return data
        if data != "No filters":
            if self.parent is not None:
                self.parent.add_error_once(
                    "object %d: stream not decoded (%s)" % (self.id, str(data)[:80]))
        try:
            raw = self.element.Stream(False)
        except Exception:
            return None
        if not isinstance(raw, str):
            return None
        raw = raw.encode("latin-1", "replace")
        # The end-of-line before "endstream" is not stream data.
        if raw.endswith(b"\r\n"):
            return raw[:-2]
        return raw[:-1] if raw.endswith(b"\n") else raw


@dataclass
class ParsedPdf:
    """Result of ``load_pdf``."""

    objects: Dict[int, List[PdfObject]] = field(default_factory=dict)
    encrypted: bool = False
    errors: List[str] = field(default_factory=list)
    _logged: Set[str] = field(default_factory=set, init=False, repr=False, compare=False)

    def add_error_once(self, msg: str) -> None:
        """Append ``msg`` to ``errors`` unless it is already there."""
        if msg not in self._logged:
            self._logged.add(msg)
            self.errors.append(msg)

    @property
    def partial(self) -> bool:
        """True when the parse was incomplete or content cannot be decoded."""
        return bool(self.errors) or self.encrypted


def _expand_objstm(obj) -> StringIO:
    """Build a synthesised PDF text from an ``/ObjStm`` object.

    Copied from vendor/pdf_parser.py (main(), the ``options.objstm`` branch,
    lines ~1598-1620); only the error handling and variable names differ, and
    an unfiltered stream is read raw (pdf_parser returns 'No filters' for it).

    Raises:
        Exception: If the object's index is inconsistent or the stream cannot be decoded.
    """
    c2s = pdf_parser.C2SIP3
    d = pdf_parser.cPDFParseDictionary(obj.ContainsStream(), False)
    number_of_objects = int(d.Get("/N")[0])
    offset_first = int(d.Get("/First")[0])
    stream = obj.Stream()
    if stream == "No filters":
        stream = obj.Stream(False).encode("latin-1")
    elif not isinstance(stream, bytes):
        raise Exception(stream)
    indexes = list(map(int, c2s(stream)[:offset_first].strip().replace("\n", " ").split(" ")))
    if len(indexes) % 2 != 0 or len(indexes) / 2 != number_of_objects:
        raise Exception("Error in index of /ObjStm stream")
    stream_object = c2s(stream[offset_first:])
    synthesized = ""
    while len(indexes) > 0:
        number = indexes[0]
        offset = indexes[1]
        indexes = indexes[2:]
        if len(indexes) >= 2:
            offset_next = indexes[1]
        else:
            offset_next = len(stream_object)
        synthesized += "%d 0 obj\n%s\nendobj\n" % (number, stream_object[offset:offset_next])
    return StringIO(synthesized)


def load_pdf(path: str) -> ParsedPdf:
    """Parse a PDF file without raising on malformed content.

    Args:
        path: Path to the PDF.

    Returns:
        ParsedPdf. Every definition of an object id is kept, in file order:
        a reader picks a copy through the xref, which a crafted file can
        point at an earlier copy, so none may be dropped. Objects inside
        ``/ObjStm`` streams are included with ``objstm`` set to the
        container's id.

    Raises:
        OSError: If the file cannot be read.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    pdf = ParsedPdf()

    def add(element, objstm=None):
        copies = pdf.objects.setdefault(element.id, [])
        copies.append(PdfObject(element.id, objstm, element, pdf, len(copies) + 1))

    try:
        parser = pdf_parser.cPDFParser(BytesIO(data))
        inner = None
        saw_trailer = False
        while True:
            try:
                if inner is None:
                    element = parser.GetObject()
                else:
                    element = inner.GetObject()
                    if element is None:
                        inner = None
                        continue
            except Exception as exc:
                pdf.errors.append("parse stopped: %s" % exc)
                break
            if element is None:
                break
            if element.type == pdf_parser.PDF_ELEMENT_INDIRECT_OBJECT:
                add(element, element.objstm[0] if element.objstm else None)
                # Xref-stream PDFs keep /Encrypt in the stream dictionary.
                if element.GetType() == "/XRef" and element.ContainsName("/Encrypt"):
                    pdf.encrypted = True
                is_objstm = pdf_parser.EqualCanonical(element.GetType(), "/ObjStm")
                if is_objstm and inner is not None:
                    pdf.errors.append("object %d: /ObjStm inside an /ObjStm not expanded"
                                      % element.id)
                elif is_objstm and element.ContainsStream():
                    cuts, damaged = _cuts[0], _damaged[0]
                    try:
                        text = _expand_objstm(element)
                        inner = pdf_parser.cPDFParser(
                            text, False, None, (element.id, element.version))
                    except Exception as exc:
                        pdf.errors.append("object %d: /ObjStm not expanded (%s)" % (element.id, exc))
                    if _cuts[0] != cuts:
                        pdf.errors.append("object %d: /ObjStm cut at %d MB (decompression limit)"
                                          % (element.id, config.MAX_STREAM_BYTES // (1024 * 1024)))
                    if _damaged[0] != damaged:
                        pdf.errors.append("object %d: /ObjStm compressed stream truncated or corrupt "
                                          "(decoded as far as possible)" % element.id)
            elif element.type == pdf_parser.PDF_ELEMENT_TRAILER:
                saw_trailer = True
                if any(pdf_parser.EqualCanonical(tok[1], "/Encrypt") for tok in element.content):
                    pdf.encrypted = True
        if parser.context == pdf_parser.CONTEXT_OBJ:
            pdf.errors.append("truncated: object %s has no endobj" % parser.objectId)
        if not saw_trailer and not any(o.type() == "/XRef"
                                       for c in pdf.objects.values() for o in c):
            pdf.errors.append("no trailer or xref stream found")
    except Exception as exc:  # defensive: parser internals must not crash the tool
        pdf.errors.append("parse failed: %s" % exc)
    return pdf

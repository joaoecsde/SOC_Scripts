"""Wrapper around the vendored pdf_parser (Didier Stevens).

Loads a PDF into a ``ParsedPdf`` of ``PdfObject`` items, expanding
``/ObjStm`` object streams. Parsing never raises on malformed content;
problems are recorded in ``ParsedPdf.errors`` so the report can say the
parse was partial. Nothing in the file is ever executed.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from io import BytesIO, StringIO
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vendor"))
import pdf_parser  # noqa: E402


@dataclass
class PdfObject:
    """One indirect object, possibly taken from inside an ``/ObjStm``."""

    id: int
    objstm: Optional[int]   # id of the containing /ObjStm, else None
    element: object         # pdf_parser cPDFElementIndirectObject
    parent: Optional["ParsedPdf"] = field(default=None, repr=False)

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
            msg = "object %d: dictionary not parsed (%s)" % (self.id, type(exc).__name__)
            if self.parent is not None and msg not in self.parent.errors:
                self.parent.errors.append(msg)
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
        try:
            data = self.element.Stream(True)
        except Exception as exc:
            data = "decode error: %s" % exc
        if isinstance(data, bytes):
            return data
        if data != "No filters":
            if self.parent is not None:
                self.parent.errors.append(
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

    objects: Dict[int, PdfObject] = field(default_factory=dict)
    encrypted: bool = False
    errors: List[str] = field(default_factory=list)

    @property
    def partial(self) -> bool:
        """True when the parse was incomplete or content cannot be decoded."""
        return bool(self.errors) or self.encrypted


def _expand_objstm(obj) -> StringIO:
    """Build a synthesised PDF text from an ``/ObjStm`` object.

    Copied from vendor/pdf_parser.py (main(), the ``options.objstm`` branch,
    lines ~1598-1620); only the error handling and variable names differ.

    Raises:
        Exception: If the object's index is inconsistent.
    """
    c2s = pdf_parser.C2SIP3
    d = pdf_parser.cPDFParseDictionary(obj.ContainsStream(), False)
    number_of_objects = int(d.Get("/N")[0])
    offset_first = int(d.Get("/First")[0])
    stream = obj.Stream()
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
        ParsedPdf. The last definition of an object id wins (incremental
        updates). Objects inside ``/ObjStm`` streams are included with
        ``objstm`` set to the container's id.

    Raises:
        OSError: If the file cannot be read.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    pdf = ParsedPdf()

    def add(element, objstm=None):
        pdf.objects[element.id] = PdfObject(element.id, objstm, element, pdf)

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
                    try:
                        text = _expand_objstm(element)
                        inner = pdf_parser.cPDFParser(
                            text, False, None, (element.id, element.version))
                    except Exception as exc:
                        pdf.errors.append("object %d: bad /ObjStm index (%s)" % (element.id, exc))
            elif element.type == pdf_parser.PDF_ELEMENT_TRAILER:
                saw_trailer = True
                if any("/Encrypt" in tok[1] for tok in element.content):
                    pdf.encrypted = True
        if parser.context == pdf_parser.CONTEXT_OBJ:
            pdf.errors.append("truncated: object %s has no endobj" % parser.objectId)
        if not saw_trailer and not any(o.type() == "/XRef" for o in pdf.objects.values()):
            pdf.errors.append("no trailer or xref stream found")
    except Exception as exc:  # defensive: parser internals must not crash the tool
        pdf.errors.append("parse failed: %s" % exc)
    return pdf

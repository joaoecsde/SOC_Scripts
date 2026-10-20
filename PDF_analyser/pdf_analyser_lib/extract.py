"""Extraction of strings, JavaScript, actions, triggers and embedded files.

Everything is read through ``PdfObject.get`` / ``stream`` (pdf_parser does the
tokenising and filtering). Extracted content is only decoded, never executed.
All ``find_*`` functions return plain dicts so they serialise to JSON.

An object id can be defined more than once (see ``load_pdf``). Every copy is
scanned and a reference follows every copy of its target, whatever the
generation number: readers may ignore a mismatch, so no copy is skipped.
Each result's ``copy`` is the copy number when the id has several copies,
else None.
"""
from __future__ import annotations

import re
from typing import Dict, Iterator, List, Optional, Set, Tuple

from .parser import ParsedPdf, PdfObject, pdf_parser

ACTION_TYPES = ("/URI", "/SubmitForm", "/GoToR", "/GoToE", "/Launch", "/ImportData")
# Actions that make an automatic trigger HIGH (the same set rules.py grades).
_ACTIVE_ACTIONS = ("/JavaScript",) + ACTION_TYPES
# Names that make a duplicated object worth a look (rules.py grades it medium).
# /OpenAction and /AA are left out: most only go to a page, and a trigger that
# runs a script reaches a /JS or /JavaScript name, which is listed.
DUPLICATE_ACTIVE_NAMES = ("/JS", "/JavaScript", "/Launch", "/SubmitForm", "/GoToR", "/GoToE",
                          "/ImportData", "/EmbeddedFile")
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f"}


def _bytes_to_text(raw: bytes) -> str:
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    return raw.decode("latin-1")


def decode_pdf_string(tokens: Optional[List[str]]) -> str:
    """Decode a PDF literal ``( )`` or hex ``< >`` string token list.

    Args:
        tokens: pdf_parser token list for the value.

    Returns:
        The decoded text (UTF-16BE if a BOM is present, else latin-1), or
        an empty string if the tokens are not a string.
    """
    if not tokens or not isinstance(tokens, list) or any(not isinstance(t, str) for t in tokens):
        return ""
    text = "".join(tokens).strip()
    if text.startswith("(") and text.endswith(")"):
        body = text[1:-1]
        out = bytearray()
        i = 0
        while i < len(body):
            ch = body[i]
            if ch != "\\" or i + 1 >= len(body):
                out += ch.encode("latin-1", "replace")
                i += 1
                continue
            nxt = body[i + 1]
            if nxt in _ESCAPES:
                out += _ESCAPES[nxt].encode()
                i += 2
            elif nxt in "01234567":
                m = re.match(r"[0-7]{1,3}", body[i + 1:])
                out.append(int(m.group(0), 8) & 0xFF)
                i += 1 + len(m.group(0))
            elif nxt == "\r":
                i += 3 if body[i + 2:i + 3] == "\n" else 2
            elif nxt == "\n":
                i += 2
            else:  # \( \) \\ and unknown escapes: the character itself
                out += nxt.encode("latin-1", "replace")
                i += 2
        return _bytes_to_text(bytes(out))
    if text.startswith("<") and not text.startswith("<<") and text.endswith(">"):
        digits = re.sub(r"\s+", "", text[1:-1])
        if len(digits) % 2:
            digits += "0"
        try:
            return _bytes_to_text(bytes.fromhex(digits))
        except ValueError:
            return ""
    return ""


def ref_ids(tokens: Optional[List[str]]) -> List[int]:
    """Return the ``N`` of every ``N G R`` triple in a token list."""
    if not isinstance(tokens, list):
        return []
    flat = [t for t in tokens if isinstance(t, str) and t.strip()]
    if flat and flat[0].strip()[0] in "(<":   # a string, not a reference
        return []
    return [int(flat[i - 2]) for i in range(2, len(flat))
            if flat[i] == "R" and flat[i - 2].isdigit() and flat[i - 1].isdigit()]


def _is_dict(value) -> bool:
    return isinstance(value, list) and bool(value) and isinstance(value[0], tuple)


def _items(obj: PdfObject) -> list:
    """Top-level (key, tokens) pairs of the object's dictionary."""
    return obj.items()


def _all(pdf: ParsedPdf) -> Iterator[PdfObject]:
    """Every copy of every object, by id and then in file order."""
    for oid in sorted(pdf.objects):
        yield from pdf.objects[oid]


def _copy(obj: Optional[PdfObject]) -> Optional[int]:
    return obj.copy if obj is not None and obj.duplicated else None


def _segments(items):
    """Split a parsed dict into runs of unique keys.

    pdf_parser flattens dicts that sit inside arrays: the second dict of
    ``[<< A >> << B >>]`` is merged into the parent, so the parent can hold
    two ``/S`` keys. A real PDF dict never repeats a key, so a repeat starts
    a new segment and each merged action is still seen on its own.
    """
    seg, keys = [], set()
    for k, v in items:
        if k in keys:
            yield seg
            seg, keys = [], set()
        seg.append((k, v))
        keys.add(k)
    if seg:
        yield seg


def _walk_dicts(items):
    """Yield every dict nested anywhere in ``items`` (``items`` included).

    Iterative (no recursion), so hostile nesting depth cannot crash it.
    Dicts inside arrays are reached too, because pdf_parser stores them as
    dict values. Each dict is yielded per segment (see ``_segments``).
    """
    stack = [items] if _is_dict(items) else []
    while stack:
        d = stack.pop()
        yield from _segments(d)
        stack.extend(reversed([v for _, v in d if _is_dict(v)]))


def _lookup(items, key: str):
    for k, v in items or []:
        if pdf_parser.EqualCanonical(k, key):
            return v
    return None


def _name(tokens) -> Optional[str]:
    if isinstance(tokens, list):
        for t in tokens:
            if isinstance(t, str) and t.strip():
                return pdf_parser.Canonicalize(t.strip()) if t.startswith("/") else None
    return None


def _resolve(pdf: ParsedPdf, value) -> list:
    """Return ``(items, target)`` pairs for a dict value or a ref to an object.

    A dict gives one pair with target None; a reference gives one pair per
    copy of its target, with that copy's ``PdfObject`` as target; anything
    else gives an empty list.
    """
    if _is_dict(value):
        return [(value, None)]
    ids = ref_ids(value)
    if len(ids) == 1 and ids[0] in pdf.objects and not _is_array(value):
        return [(_items(o), o) for o in pdf.objects[ids[0]]]
    return []


def _value_key(value):
    """Hashable key for a dict value: the target id for a reference ``_resolve`` follows."""
    ids = ref_ids(value)
    if len(ids) == 1 and not _is_array(value) and not _is_dict(value):
        return ("ref", ids[0])
    return repr(value)


def _is_array(value) -> bool:
    return isinstance(value, list) and any(isinstance(t, str) and t.strip() == "[" for t in value)


def _filespec_name(pdf: ParsedPdf, value) -> Optional[str]:
    """Name from a string, an inline filespec dict, or a reference to one.

    For a reference, the first copy of the target that has a name wins.
    """
    resolved = _resolve(pdf, value)
    if not resolved:
        return decode_pdf_string(value) or None
    for items, _ in resolved:
        for key in ("/UF", "/F"):
            s = decode_pdf_string(_lookup(items, key))
            if s:
                return s
    return None


def find_javascript(pdf: ParsedPdf) -> List[dict]:
    """Find JavaScript held in ``/JS`` entries.

    Returns:
        Dicts ``{"object", "objstm", "copy", "source_object", "source_copy",
        "code", "data"}``, one per copy of a referenced script, deduplicated
        by source copy. ``source_copy`` is the copy of ``source_object``
        holding the script when that id has several copies, else None.
        ``data`` is the script stream's bytes, or None for a string script.
    """
    results, seen = [], set()
    for obj in _all(pdf):
        oid = obj.id
        for value in _js_values(_items(obj)):
            ids = ref_ids(value)
            if ids:
                source = ids[0]
                # A dangling reference keeps one empty entry as evidence.
                entries = [((source, ref.copy), ref, None)
                           for ref in pdf.objects.get(source, [])] or [((source, None), None, "")]
            else:
                # Several inline scripts in one object stay distinct.
                code = decode_pdf_string(value)
                source, entries = oid, [((oid, code), obj, code)]
            for key, ref, code in entries:
                if key in seen:
                    continue
                seen.add(key)
                data = None
                if code is None:   # decoded only once the copy is known to be new
                    data = ref.stream()
                    code = _bytes_to_text(data) if data is not None \
                        else decode_pdf_string(_lookup(_items(ref), "/JS")) \
                        or _body_string(ref)
                results.append({"object": oid, "objstm": obj.objstm, "copy": _copy(obj),
                                "source_object": source, "source_copy": _copy(ref),
                                "code": code, "data": data})
    return results


def _body_string(obj: PdfObject) -> str:
    """Decode an object whose whole body is a string (``5 0 obj (...) endobj``), else ''."""
    return decode_pdf_string([tok[1] for tok in obj.element.content])


def _js_values(items):
    """Yield every ``/JS`` value in a dict, including inline nested dicts and arrays."""
    for d in _walk_dicts(items):
        for k, v in d:
            if pdf_parser.EqualCanonical(k, "/JS"):
                yield v


def find_actions(pdf: ParsedPdf) -> List[dict]:
    """Find URI, SubmitForm, GoToR, GoToE, Launch and ImportData actions and their targets.

    Returns:
        Dicts ``{"object", "objstm", "copy", "type", "target"}``.
    """
    results, seen = [], set()
    for obj in _all(pdf):
        oid = obj.id
        for d in _walk_dicts(_items(obj)):   # inline /A, /AA, /Next, arrays ...
            atype = _name(_lookup(d, "/S"))
            if atype not in ACTION_TYPES:
                continue
            if atype == "/URI":
                target = decode_pdf_string(_lookup(d, "/URI"))
            else:
                target = _filespec_name(pdf, _lookup(d, "/F")) or ""
            if (oid, atype, target) in seen:
                continue
            seen.add((oid, atype, target))
            results.append({"object": oid, "objstm": obj.objstm, "copy": _copy(obj),
                            "type": atype, "target": target})
    return results


def _active_action(d) -> Optional[str]:
    """The dict's active action type, or None.

    Any action with a ``/JS`` entry (e.g. ``/Rendition``) runs JavaScript, so
    it counts as ``/JavaScript``.
    """
    atype = _name(_lookup(d, "/S"))
    if atype in _ACTIVE_ACTIONS:
        return atype
    return "/JavaScript" if _lookup(d, "/JS") is not None else None


def _trigger_action(pdf: ParsedPdf, items, target: Optional[int],
                    chains: Dict[tuple, Optional[str]]) -> Optional[str]:
    """Return a trigger's action type, following its ``/Next`` chain.

    The first active action (JavaScript, URI, SubmitForm, GoToR, GoToE,
    Launch, ImportData; any dict with a ``/JS`` entry counts as JavaScript)
    found in the action dict, its nested dicts or the ``/Next`` chain
    (dict, reference or array of either) wins; otherwise the action's own
    ``/S``. A visited set stops reference loops. ``chains`` caches the
    walk of referenced ``/Next`` objects, so the copies of one target that
    share a chain walk it once.
    """
    refs: List[int] = []
    for d in _walk_dicts(items):
        atype = _active_action(d)
        if atype:
            return atype
        refs += ref_ids(_lookup(d, "/Next"))
    key = (target, tuple(refs))
    if key not in chains:
        chains[key] = _chain_action(pdf, refs, target)
    return chains[key] or _name(_lookup(items, "/S"))


def _chain_action(pdf: ParsedPdf, refs: List[int], target: Optional[int]) -> Optional[str]:
    """First active action reached through the referenced ``/Next`` objects, or None."""
    seen = {target} if target is not None else set()
    todo: list = []

    def follow(rids):
        for rid in rids:
            if rid in pdf.objects and rid not in seen:
                seen.add(rid)
                todo.extend(_items(o) for o in pdf.objects[rid])
    follow(refs)
    while todo:
        for d in _walk_dicts(todo.pop(0)):
            atype = _active_action(d)
            if atype:
                return atype
            follow(ref_ids(_lookup(d, "/Next")))
    return None


def _document_js(pdf: ParsedPdf, obj: PdfObject) -> List[Optional[PdfObject]]:
    """Return where each document-level script lives (the object copy, or None if inline).

    Walks the ``/Names`` -> ``/JavaScript`` name tree of a Catalog (inline
    or referenced nodes, ``/Kids`` and ``/Names`` arrays), following every
    copy of a referenced node. These scripts run when the document opens.
    """
    found: List[Optional[PdfObject]] = []
    keys, seen = set(), set()
    todo = [(_lookup(names, "/JavaScript"), None)
            for names, _ in _resolve(pdf, _lookup(_items(obj), "/Names"))]
    while todo:
        value, node = todo.pop(0)
        if node is None and not _is_dict(value):   # a reference or an array of them
            refs = ref_ids(value)
            value = None
        else:
            refs = []
        for d in _walk_dicts(value):
            if _lookup(d, "/JS") is not None or _name(_lookup(d, "/S")) == "/JavaScript":
                key = (node.id, node.copy) if node is not None else None
                if key not in keys:
                    keys.add(key)
                    found.append(node)
                continue
            refs += ref_ids(_lookup(d, "/Kids")) + ref_ids(_lookup(d, "/Names"))
        for rid in refs:
            if rid in pdf.objects and rid not in seen:
                seen.add(rid)
                todo.extend((_items(o), o) for o in pdf.objects[rid])
    return found


def find_triggers(pdf: ParsedPdf) -> List[dict]:
    """Find ``/OpenAction``, ``/AA`` and document-level JavaScript triggers.

    Returns:
        Dicts ``{"object", "objstm", "copy", "keyword", "action",
        "target_object", "target_copy"}``, one per followed copy of a
        referenced target. ``target_copy`` is that copy's number when the
        target id has several copies, else None.
        ``action`` is the ``/S`` name (or the first active action in its
        ``/Next`` chain), or None for a destination array. ``/AA`` yields one
        dict per sub-entry. JavaScript in the Catalog's ``/Names`` ->
        ``/JavaScript`` tree yields ``keyword`` ``/Names`` and ``action``
        ``/JavaScript``, one dict per script location.

        A value repeated across copies of the same object (or of an ``/AA``
        container) is followed once, by its first copy. Otherwise every copy
        multiplies the next level's copies and a small hostile file yields
        millions of results.
    """
    results, done = [], set()
    chains: Dict[tuple, Optional[str]] = {}

    def first(key) -> bool:
        if key in done:
            return False
        done.add(key)
        return True

    for obj in _all(pdf):
        base = {"object": obj.id, "objstm": obj.objstm, "copy": _copy(obj)}
        for keyword in ("/OpenAction", "/AA"):
            value = obj.get(keyword)
            if value is None or not first((obj.id, keyword, _value_key(value))):
                continue
            if keyword == "/OpenAction":
                entries = [value]
            else:
                entries = [v for container, _ in _resolve(pdf, value) for _, v in container
                           if first((obj.id, keyword, "entry", _value_key(v)))]
            for entry in entries:
                for items, target in _resolve(pdf, entry) or [(None, None)]:
                    tid = target.id if target is not None else None
                    action = _trigger_action(pdf, items, tid, chains) if items is not None else None
                    results.append(dict(base, keyword=keyword, action=action,
                                        target_object=tid, target_copy=_copy(target)))
        names = obj.get("/Names")
        if names is None or not first((obj.id, "/Names", _value_key(names))):
            continue
        for node in _document_js(pdf, obj):
            results.append(dict(base, keyword="/Names", action="/JavaScript",
                                target_object=node.id if node is not None else None,
                                target_copy=_copy(node)))
    return results


def find_embedded_files(pdf: ParsedPdf) -> List[dict]:
    """Find embedded file streams (``/Type /EmbeddedFile`` or filespec ``/EF``).

    Filespecs are found at any depth (e.g. inline in a ``/Names`` array).
    Every copy of an ``/EF`` target is returned, but when there are several
    only the copies that look like an attachment get the filespec name (see
    ``_attachment_copies``); the others have name None.

    Returns:
        Dicts ``{"object", "objstm", "copy", "name", "data"}``.
    """
    targets: Set[Tuple[int, int]] = set()              # (id, copy) of every /EF target
    names: Dict[Tuple[int, int], Optional[str]] = {}   # (id, copy) -> filespec name
    for obj in _all(pdf):
        for d in _walk_dicts(_items(obj)):
            ef = _lookup(d, "/EF")
            if ef is None:
                continue
            name = _filespec_name(pdf, [("/UF", _lookup(d, "/UF")), ("/F", _lookup(d, "/F"))])
            for ef_items, _ in _resolve(pdf, ef):
                for _, v in ef_items:
                    for sid in ref_ids(v):
                        copies = pdf.objects.get(sid, [])
                        targets.update((o.id, o.copy) for o in copies)
                        for o in _attachment_copies(copies):
                            names.setdefault((o.id, o.copy), name)
    results = []
    for obj in _all(pdf):
        key = (obj.id, obj.copy)
        if key not in targets and not pdf_parser.EqualCanonical(obj.type(), "/EmbeddedFile"):
            continue
        data = obj.stream()
        if data is None:
            continue
        results.append({"object": obj.id, "objstm": obj.objstm, "copy": _copy(obj),
                        "name": names.get(key), "data": data})
    return results


def _attachment_copies(copies: List[PdfObject]) -> List[PdfObject]:
    """Of several copies, those that look like an attachment; all if none does.

    A copy is ruled out by a ``/Type`` other than ``/EmbeddedFile`` or an
    image or form ``/Subtype``. A single copy is always kept.
    """
    if len(copies) < 2:
        return copies
    looks = [o for o in copies
             if (not o.type() or pdf_parser.EqualCanonical(o.type(), "/EmbeddedFile"))
             and _name(o.get("/Subtype")) not in ("/Image", "/Form")]
    return looks or copies


def find_keywords(pdf: ParsedPdf) -> Dict[str, List[int]]:
    """Map ``/RichMedia``, ``/XFA``, ``/ObjStm`` and ``/XObject`` to the objects containing them."""
    out = {"/RichMedia": [], "/XFA": [], "/ObjStm": [], "/XObject": []}
    for obj in _all(pdf):
        for name in out:
            # Ids come in order, so a repeat can only be the last one added.
            if obj.has_name(name) and out[name][-1:] != [obj.id]:
                out[name].append(obj.id)
    return out


def find_richmedia_streams(pdf: ParsedPdf) -> List[dict]:
    """Return streams referenced one level deep from ``/RichMedia`` objects."""
    results, seen = [], set()
    for obj in _all(pdf):
        if not obj.has_name("/RichMedia"):
            continue
        for rid in obj.refs():
            if rid == obj.id or rid not in pdf.objects:
                continue
            for ref in pdf.objects[rid]:
                if (rid, ref.copy) in seen:
                    continue
                data = ref.stream()
                if data is None:
                    continue
                seen.add((rid, ref.copy))
                results.append({"object": rid, "objstm": ref.objstm, "copy": _copy(ref),
                                "data": data})
    return results


def find_duplicates(pdf: ParsedPdf) -> List[dict]:
    """Find object ids defined more than once.

    Returns:
        Dicts ``{"object", "count", "active"}``; ``active`` lists the names
        from ``DUPLICATE_ACTIVE_NAMES`` found in any copy.
    """
    results = []
    for oid in sorted(pdf.objects):
        copies = pdf.objects[oid]
        if len(copies) < 2:
            continue
        active = [n for n in DUPLICATE_ACTIVE_NAMES if any(o.has_name(n) for o in copies)]
        results.append({"object": oid, "count": len(copies), "active": active})
    return results

"""Structural import gate for models and training data.

This is a NON-disclaimable security control. A user may import their own model or dataset,
and we cannot vet whether it is good or poisoned (that risk is theirs, disclaimed, and gated
by a human review plus behavioral quarantine). But we CAN and MUST refuse formats that
execute code at load time, because "at your own risk" does not cover a naive user clicking
import and getting remote code execution.

Accepted, data-only formats (carry no code):
  * .safetensors | tensors + a length-prefixed JSON header, zero code
  * .gguf         | the llama.cpp container, zero code
  * .json         | our own classifier params (Naive Bayes to_dict), plain data

Rejected because they can execute code or carry pickled objects at load:
  * .pkl .pickle .pt .pth .ckpt .bin .joblib .dill .npz .h5 .pb .model
  (.npz is rejected too: numpy.load with allow_pickle can run pickled code.)

This module only inspects the file NAME/extension. Deeper structural validation of the
container header, and the behavioral quarantine (shadow-run against our own validated ground
truth before any authority is granted), come with the import feature in v12.3.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath

ACCEPTED_MODEL_EXTS = frozenset({".safetensors", ".gguf", ".json"})

REJECTED_EXECUTABLE_EXTS = frozenset({
    ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".bin", ".joblib",
    ".dill", ".npz", ".h5", ".hdf5", ".pb", ".model", ".pt.tar",
})


@dataclass(frozen=True)
class ImportVerdict:
    accepted: bool
    reason: str


def _ext(filename: str) -> str:
    # handle both separators regardless of host, then lowercase the final suffix
    name = PureWindowsPath(PurePosixPath(filename).name).name
    dot = name.rfind(".")
    return name[dot:].lower() if dot != -1 else ""


def check_import_format(filename: str) -> ImportVerdict:
    """Structural, default-deny gate. Accept only known data-only extensions; reject the
    pickle/executable family explicitly; reject everything else by default."""
    if not filename or not str(filename).strip():
        return ImportVerdict(False, "empty filename")
    ext = _ext(str(filename))
    if ext in REJECTED_EXECUTABLE_EXTS:
        return ImportVerdict(
            False, "format %s can execute code at load and is refused (structural gate)" % ext)
    if ext in ACCEPTED_MODEL_EXTS:
        return ImportVerdict(True, "accepted data-only format %s" % ext)
    return ImportVerdict(False, "unknown format %r refused by default (allowlist only)" % ext)


# -- structural header validation (parse bytes, never execute) ------------------------------
import json as _json
import struct as _struct

MAX_HEADER_BYTES = 8 * 1024 * 1024   # a model header should be small; cap it hard


def validate_safetensors_header(data: bytes) -> ImportVerdict:
    """safetensors layout: 8-byte little-endian uint64 header length N, then N bytes of a JSON
    object describing tensors, then the tensor bytes. We parse ONLY the header JSON; we never
    load tensors and never execute anything. A malformed or oversized header is rejected."""
    if len(data) < 8:
        return ImportVerdict(False, "file too short to be safetensors")
    (n,) = _struct.unpack("<Q", data[:8])
    if n <= 0 or n > MAX_HEADER_BYTES:
        return ImportVerdict(False, "safetensors header length out of range (%d)" % n)
    if 8 + n > len(data):
        return ImportVerdict(False, "safetensors header extends past end of file")
    try:
        header = _json.loads(data[8:8 + n].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return ImportVerdict(False, "safetensors header is not valid JSON")
    if not isinstance(header, dict):
        return ImportVerdict(False, "safetensors header is not a JSON object")
    return ImportVerdict(True, "safetensors header parsed (%d tensors declared)"
                         % max(0, len(header) - (1 if "__metadata__" in header else 0)))


def validate_gguf_header(data: bytes) -> ImportVerdict:
    """GGUF starts with the ASCII magic 'GGUF' followed by a uint32 version. We check the
    magic and a plausible version only; we never load the model."""
    if len(data) < 8:
        return ImportVerdict(False, "file too short to be GGUF")
    if data[:4] != b"GGUF":
        return ImportVerdict(False, "not a GGUF file (bad magic)")
    (version,) = _struct.unpack("<I", data[4:8])
    if version == 0 or version > 100:
        return ImportVerdict(False, "implausible GGUF version %d" % version)
    return ImportVerdict(True, "GGUF magic and version %d ok" % version)


def validate_classifier_json(text: str) -> ImportVerdict:
    """Our own classifier export format is plain JSON (NaiveBayes.to_dict). Validate the
    shape without instantiating anything. JSON carries no code, so this is safe by
    construction; we only guard against a wrong or malformed document."""
    try:
        d = _json.loads(text)
    except ValueError:
        return ImportVerdict(False, "not valid JSON")
    if not isinstance(d, dict):
        return ImportVerdict(False, "classifier params must be a JSON object")
    if d.get("kind") != "naive_bayes":
        return ImportVerdict(False, "unexpected model kind %r" % d.get("kind"))
    required = ("classes", "vocab", "tok_count", "class_doc_count", "class_tok_total")
    missing = [k for k in required if k not in d]
    if missing:
        return ImportVerdict(False, "classifier params missing fields: %s" % ", ".join(missing))
    if not isinstance(d["classes"], list) or not d["classes"]:
        return ImportVerdict(False, "classifier has no classes")
    return ImportVerdict(True, "classifier params valid (%d classes)" % len(d["classes"]))

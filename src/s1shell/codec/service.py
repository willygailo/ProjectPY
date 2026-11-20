"""Offline service orchestrator for `s1shell codec` (decode, encode, inspect, hash)."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Sequence
from pathlib import Path

from s1shell.codec.codecs import (
    MAX_INPUT_BYTES,
    auto_decode_bytes,
    caesar_all_shifts,
    compute_hashes,
    decode_jwt_details,
    decode_single,
    detect_unix_timestamp,
    encode_single,
    identify_hashes,
    inspect_x509_pem_or_der,
    normalize_codec_name,
    shannon_entropy,
)
from s1shell.codec.models import (
    CodecHashResult,
    CodecInspectResult,
    CodecStep,
    CodecTransformResult,
)
from s1shell.errors import ValidationError


def _check_size(data: bytes) -> bytes:
    if len(data) > MAX_INPUT_BYTES:
        raise ValidationError(
            f"Input size ({len(data)} bytes) exceeds {MAX_INPUT_BYTES // (1024 * 1024)} MiB limit."
        )
    return data


def _format_transform_result(
    *,
    operation: str,
    steps: list[CodecStep],
    output: bytes,
    variants: list[dict[str, str]] | None = None,
) -> CodecTransformResult:
    try:
        out_text = output.decode("utf-8")
        is_utf8 = True
    except UnicodeDecodeError:
        out_text = output.decode("utf-8", errors="replace")
        is_utf8 = False
    return CodecTransformResult(
        operation=operation,
        steps=steps,
        output_text=out_text,
        output_hex=output[:4096].hex(),
        output_base64=base64.b64encode(output[:4096]).decode("ascii"),
        is_utf8=is_utf8,
        byte_length=len(output),
        sha256=hashlib.sha256(output).hexdigest(),
        entropy=shannon_entropy(output),
        variants=variants or [],
    )


class CodecService:
    """100% offline codec transformation, smart token/cert/hash inspection, and hashing."""

    def read_input_bytes(
        self,
        *,
        text: str | None = None,
        file_path: Path | None = None,
        stdin_bytes: bytes | None = None,
    ) -> tuple[bytes, str]:
        """Resolve bounded raw bytes from `--file`, piped stdin, or inline text."""
        if file_path is not None:
            resolved = file_path.expanduser().resolve()
            try:
                raw = resolved.read_bytes()
            except OSError as exc:
                raise ValidationError(f"Failed to read file '{file_path}': {exc}") from exc
            return _check_size(raw), str(file_path)
        if text == "-":
            if stdin_bytes is None:
                raise ValidationError("No input received from stdin (`-`).")
            return _check_size(stdin_bytes), "stdin"
        if text is not None:
            return _check_size(text.encode("utf-8")), "inline"
        if stdin_bytes is not None:
            return _check_size(stdin_bytes), "stdin"
        raise ValidationError("Provide input text, `-` for stdin, or `--file PATH`.")

    def decode(
        self,
        data: bytes,
        *,
        encoding: str = "auto",
        chain: Sequence[str] | None = None,
        shift: int = 13,
        all_shifts: bool = False,
        max_depth: int = 6,
    ) -> CodecTransformResult:
        """Decode bytes via explicit codec, ordered `--chain`, or magic recursive `auto`."""
        _check_size(data)
        if max_depth <= 0 or max_depth > 12:
            raise ValidationError("--max-depth must be between 1 and 12.")

        if chain:
            current = data
            steps: list[CodecStep] = []
            for idx, codec_name in enumerate(chain, start=1):
                before = len(current)
                current, note = decode_single(current, codec_name, shift=shift)
                steps.append(
                    CodecStep(
                        stage=idx,
                        codec=normalize_codec_name(codec_name),
                        input_bytes=before,
                        output_bytes=len(current),
                        note=note,
                    )
                )
            return _format_transform_result(operation="decode", steps=steps, output=current)

        norm = normalize_codec_name(encoding)
        if norm == "auto":
            decoded, raw_trace = auto_decode_bytes(data, max_depth=max_depth)
            steps = [
                CodecStep(
                    stage=idx,
                    codec=codec_name,
                    input_bytes=in_len,
                    output_bytes=out_len,
                    note=note,
                )
                for idx, (codec_name, in_len, out_len, note) in enumerate(raw_trace, start=1)
            ]
            if not steps:
                steps.append(
                    CodecStep(
                        stage=1,
                        codec="none",
                        input_bytes=len(data),
                        output_bytes=len(data),
                        note="No nested encoding detected; returning original input.",
                    )
                )
            return _format_transform_result(operation="decode", steps=steps, output=decoded)

        if norm == "caesar" and all_shifts:
            src_text = data.decode("utf-8", errors="replace")
            variants = caesar_all_shifts(src_text)
            decoded_default, note = decode_single(data, "caesar", shift=shift)
            return _format_transform_result(
                operation="decode",
                steps=[
                    CodecStep(
                        stage=1,
                        codec="caesar",
                        input_bytes=len(data),
                        output_bytes=len(decoded_default),
                        note=f"{note} (plus all 25 shift candidates)",
                    )
                ],
                output=decoded_default,
                variants=variants,
            )

        decoded, note = decode_single(data, norm, shift=shift)
        return _format_transform_result(
            operation="decode",
            steps=[
                CodecStep(
                    stage=1,
                    codec=norm,
                    input_bytes=len(data),
                    output_bytes=len(decoded),
                    note=note,
                )
            ],
            output=decoded,
        )

    def encode(
        self,
        data: bytes,
        *,
        encoding: str | None = None,
        chain: Sequence[str] | None = None,
        shift: int = 13,
    ) -> CodecTransformResult:
        """Encode bytes using a single codec or ordered `--chain` pipeline."""
        _check_size(data)
        stages = list(chain) if chain else ([encoding] if encoding else [])
        if not stages:
            raise ValidationError("Specify `-e/--encoding` or `--chain` for `codec encode`.")

        current = data
        steps: list[CodecStep] = []
        for idx, codec_name in enumerate(stages, start=1):
            before = len(current)
            current, note = encode_single(current, codec_name, shift=shift)
            steps.append(
                CodecStep(
                    stage=idx,
                    codec=normalize_codec_name(codec_name),
                    input_bytes=before,
                    output_bytes=len(current),
                    note=note,
                )
            )
        return _format_transform_result(operation="encode", steps=steps, output=current)

    def inspect(self, data: bytes, *, max_depth: int = 6) -> CodecInspectResult:
        """Smart offline analysis: JWT, X.509 cert, hash format, epoch timestamp, & auto-decode."""
        _check_size(data)
        detected: list[str] = []
        notes: list[str] = []
        ent = shannon_entropy(data)
        sha = hashlib.sha256(data).hexdigest()

        try:
            text = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            text = ""

        jwt_info = decode_jwt_details(text) if text else None
        if jwt_info is not None:
            detected.append("jwt")
            notes.extend(jwt_info.get("warnings", []))

        cert_info = inspect_x509_pem_or_der(data)
        if cert_info is not None:
            detected.append("x509_certificate")
            days_rem = cert_info.get("days_remaining")
            if isinstance(days_rem, int) and days_rem < 0:
                notes.append(f"X.509 certificate expired ({days_rem}d).")
            elif isinstance(days_rem, int) and days_rem < 30:
                notes.append(f"X.509 certificate expires soon ({days_rem}d).")

        hash_cands = identify_hashes(text) if text and jwt_info is None else []
        if hash_cands:
            detected.append("hash_or_id")

        ts_utc = detect_unix_timestamp(text) if text else None
        if ts_utc is not None:
            detected.append("unix_timestamp")

        auto_res: CodecTransformResult | None = None
        if cert_info is None and jwt_info is None:
            decoded, raw_trace = auto_decode_bytes(data, max_depth=max_depth)
            if raw_trace:
                for c_name, _, _, _ in raw_trace:
                    if c_name not in detected:
                        detected.append(c_name)
                auto_res = _format_transform_result(
                    operation="decode",
                    steps=[
                        CodecStep(
                            stage=idx,
                            codec=c_name,
                            input_bytes=in_b,
                            output_bytes=out_b,
                            note=note,
                        )
                        for idx, (c_name, in_b, out_b, note) in enumerate(raw_trace, start=1)
                    ],
                    output=decoded,
                )

        if ent >= 7.5 and len(data) >= 32:
            notes.append(
                f"High Shannon entropy ({ent:.2f} bits/byte): likely compressed/encrypted."
            )
        if not detected:
            detected.append("raw_text" if text else "binary_data")

        return CodecInspectResult(
            detected_types=detected,
            byte_length=len(data),
            sha256=sha,
            entropy=ent,
            jwt=jwt_info,
            x509=cert_info,
            hash_candidates=hash_cands,
            timestamp_utc=ts_utc,
            auto_decoded=auto_res,
            notes=notes,
        )

    def hash_data(
        self,
        data: bytes,
        *,
        source: str = "inline",
        algos: Sequence[str] | None = None,
    ) -> CodecHashResult:
        """Compute multi-algorithm checksums and Shannon entropy offline."""
        _check_size(data)
        return CodecHashResult(
            source=source,
            byte_length=len(data),
            entropy=shannon_entropy(data),
            hashes=compute_hashes(data, algos),
        )

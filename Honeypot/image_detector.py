from __future__ import annotations

import hashlib
import io
import math
from dataclasses import dataclass
from typing import Any, Iterable

from PIL import Image


@dataclass(frozen=True)
class ImageSample:
    sample_id: str
    decision: str
    sha256: str
    phash: str
    dhash: str
    ahash: str


def hash_distance(left: str, right: str) -> int:
    return (int(left, 16) ^ int(right, 16)).bit_count()


def _bits_to_hex(bits: Iterable[bool]) -> str:
    value = 0
    count = 0
    for bit in bits:
        value = (value << 1) | int(bool(bit))
        count += 1
    width = max(1, count // 4)
    return f"{value:0{width}x}"


def _average_hash(image: Image.Image) -> str:
    pixels = _image_pixels(image.convert("L").resize((8, 8), Image.Resampling.LANCZOS))
    average = sum(pixels) / len(pixels)
    return _bits_to_hex(pixel >= average for pixel in pixels)


def _difference_hash(image: Image.Image) -> str:
    pixels = _image_pixels(image.convert("L").resize((9, 8), Image.Resampling.LANCZOS))
    bits = []
    for row in range(8):
        offset = row * 9
        for column in range(8):
            bits.append(pixels[offset + column] > pixels[offset + column + 1])
    return _bits_to_hex(bits)


def _dct_2d(values: list[list[float]], size: int = 32) -> list[list[float]]:
    coefficients: list[list[float]] = []
    factor = math.pi / (2 * size)
    for u in range(8):
        row: list[float] = []
        au = math.sqrt(1 / size) if u == 0 else math.sqrt(2 / size)
        for v in range(8):
            av = math.sqrt(1 / size) if v == 0 else math.sqrt(2 / size)
            total = 0.0
            for x in range(size):
                cos_x = math.cos((2 * x + 1) * u * factor)
                for y in range(size):
                    total += values[x][y] * cos_x * math.cos((2 * y + 1) * v * factor)
            row.append(au * av * total)
        coefficients.append(row)
    return coefficients


def _perceptual_hash(image: Image.Image) -> str:
    pixels = _image_pixels(image.convert("L").resize((32, 32), Image.Resampling.LANCZOS))
    values = [
        [float(pixels[row * 32 + column]) for column in range(32)]
        for row in range(32)
    ]
    dct = _dct_2d(values)
    low_freq = [dct[row][column] for row in range(8) for column in range(8) if row or column]
    median = sorted(low_freq)[len(low_freq) // 2]
    bits = []
    for row in range(8):
        for column in range(8):
            value = dct[row][column]
            bits.append(value >= median if row or column else False)
    return _bits_to_hex(bits)


def _image_pixels(image: Image.Image) -> list[int]:
    get_flattened_data = getattr(image, "get_flattened_data", None)
    if callable(get_flattened_data):
        return list(get_flattened_data())
    return list(image.getdata())


def image_hashes_from_bytes(data: bytes) -> dict[str, str]:
    with Image.open(io.BytesIO(data)) as image:
        image.load()
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "phash": _perceptual_hash(image),
            "dhash": _difference_hash(image),
            "ahash": _average_hash(image),
        }


def score_sample(hashes: dict[str, str], sample: ImageSample) -> int:
    return (
        hash_distance(hashes["phash"], sample.phash)
        + hash_distance(hashes["dhash"], sample.dhash)
        + hash_distance(hashes["ahash"], sample.ahash)
    )


def _nearest_score(sample: ImageSample, candidates: Iterable[ImageSample]) -> int | None:
    scores = [
        score_sample(
            {"phash": sample.phash, "dhash": sample.dhash, "ahash": sample.ahash},
            candidate,
        )
        for candidate in candidates
        if candidate.sample_id != sample.sample_id
    ]
    return min(scores) if scores else None


def rebuild_model_state(samples: list[ImageSample], configured_threshold: int) -> dict[str, Any]:
    active_samples = [sample for sample in samples if sample.decision in {"true_positive", "false_positive"}]
    tp_samples = [sample for sample in active_samples if sample.decision == "true_positive"]
    fp_samples = [sample for sample in active_samples if sample.decision == "false_positive"]

    tp_nearest_scores = [
        score
        for sample in tp_samples
        if (score := _nearest_score(sample, tp_samples)) is not None
    ]
    max_tp_nearest_score = max(tp_nearest_scores) if tp_nearest_scores else 0

    fp_to_tp_scores = [
        score
        for sample in fp_samples
        if (score := _nearest_score(sample, tp_samples)) is not None
    ]
    min_fp_to_tp_score = min(fp_to_tp_scores) if fp_to_tp_scores else None

    state: dict[str, Any] = {
        "valid": True,
        "reason": None,
        "configured_threshold": configured_threshold,
        "effective_threshold": configured_threshold,
        "max_tp_nearest_score": max_tp_nearest_score,
        "min_fp_to_tp_score": min_fp_to_tp_score,
        "gap": None,
        "sample_count_tp": len(tp_samples),
        "sample_count_fp": len(fp_samples),
    }
    if min_fp_to_tp_score is None:
        return state

    state["gap"] = min_fp_to_tp_score - max_tp_nearest_score
    if max_tp_nearest_score >= min_fp_to_tp_score:
        state["valid"] = False
        state["reason"] = "TP/FP overlap"
        return state

    state["effective_threshold"] = min(configured_threshold, min_fp_to_tp_score - 1)
    return state


def _best_sample(
    hashes: dict[str, str],
    samples: Iterable[ImageSample],
    decision: str,
) -> tuple[ImageSample | None, int | None]:
    best_sample: ImageSample | None = None
    best_score: int | None = None
    for sample in samples:
        if sample.decision != decision:
            continue
        score = score_sample(hashes, sample)
        if best_score is None or score < best_score:
            best_sample = sample
            best_score = score
    return best_sample, best_score


def match_image(
    hashes: dict[str, str],
    samples: list[ImageSample],
    effective_threshold: int,
) -> dict[str, Any]:
    for sample in samples:
        if sample.sha256 != hashes["sha256"]:
            continue
        if sample.decision == "true_positive":
            return {
                "matched": True,
                "ambiguous": False,
                "exact_decision": "true_positive",
                "score": 0,
                "threshold": effective_threshold,
                "best_tp_sample_id": sample.sample_id,
                "best_fp_sample_id": None,
                "best_tp_score": 0,
                "best_fp_score": None,
            }
        if sample.decision == "false_positive":
            return {
                "matched": False,
                "ambiguous": False,
                "exact_decision": "false_positive",
                "score": None,
                "threshold": effective_threshold,
                "best_tp_sample_id": None,
                "best_fp_sample_id": sample.sample_id,
                "best_tp_score": None,
                "best_fp_score": 0,
            }

    best_tp_sample, best_tp_score = _best_sample(hashes, samples, "true_positive")
    best_fp_sample, best_fp_score = _best_sample(hashes, samples, "false_positive")
    ambiguous = (
        best_tp_score is not None
        and best_fp_score is not None
        and best_fp_score <= best_tp_score
    )
    matched = (
        best_tp_score is not None
        and best_tp_score <= effective_threshold
        and not ambiguous
    )
    return {
        "matched": matched,
        "ambiguous": ambiguous,
        "exact_decision": None,
        "score": best_tp_score,
        "threshold": effective_threshold,
        "best_tp_sample_id": best_tp_sample.sample_id if best_tp_sample else None,
        "best_fp_sample_id": best_fp_sample.sample_id if best_fp_sample else None,
        "best_tp_score": best_tp_score,
        "best_fp_score": best_fp_score,
    }

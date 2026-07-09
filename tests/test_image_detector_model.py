import unittest
import sys
from io import BytesIO
from importlib import util
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "Honeypot" / "image_detector.py"
spec = util.spec_from_file_location("honeypot_image_detector", MODULE_PATH)
image_detector = util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = image_detector
spec.loader.exec_module(image_detector)

ImageSample = image_detector.ImageSample
hash_distance = image_detector.hash_distance
match_image = image_detector.match_image
rebuild_model_state = image_detector.rebuild_model_state
score_sample = image_detector.score_sample
image_hashes_from_bytes = image_detector.image_hashes_from_bytes


class ImageDetectorModelTests(unittest.TestCase):
    def _png_bytes(self, color: tuple[int, int, int]) -> bytes:
        from PIL import Image

        handle = BytesIO()
        Image.new("RGB", (16, 16), color).save(handle, format="PNG")
        return handle.getvalue()

    def test_image_hashes_are_fixed_width_and_content_sensitive(self) -> None:
        red = image_hashes_from_bytes(self._png_bytes((255, 0, 0)))
        blue = image_hashes_from_bytes(self._png_bytes((0, 0, 255)))

        self.assertEqual(len(red["sha256"]), 64)
        self.assertEqual(len(red["phash"]), 16)
        self.assertEqual(len(red["dhash"]), 16)
        self.assertEqual(len(red["ahash"]), 16)
        self.assertNotEqual(red["sha256"], blue["sha256"])

    def test_hash_distance_counts_changed_bits(self) -> None:
        self.assertEqual(hash_distance("00", "0f"), 4)
        self.assertEqual(hash_distance("ff", "0f"), 4)

    def test_score_sample_sums_all_hash_distances(self) -> None:
        sample = ImageSample("tp1", "true_positive", "aa", "00", "ff", "0f")
        self.assertEqual(
            score_sample({"phash": "0f", "dhash": "f0", "ahash": "0e"}, sample),
            4 + 4 + 1,
        )

    def test_rebuild_state_tightens_threshold_below_nearest_fp(self) -> None:
        samples = [
            ImageSample("tp1", "true_positive", "tp-sha-1", "00", "00", "00"),
            ImageSample("tp2", "true_positive", "tp-sha-2", "01", "01", "01"),
            ImageSample("fp1", "false_positive", "fp-sha-1", "f0", "f0", "f0"),
        ]

        state = rebuild_model_state(samples, configured_threshold=20)

        self.assertTrue(state["valid"])
        self.assertEqual(state["max_tp_nearest_score"], 3)
        self.assertEqual(state["min_fp_to_tp_score"], 12)
        self.assertEqual(state["effective_threshold"], 11)

    def test_rebuild_state_rejects_tp_fp_overlap(self) -> None:
        samples = [
            ImageSample("tp1", "true_positive", "tp-sha-1", "00", "00", "00"),
            ImageSample("tp2", "true_positive", "tp-sha-2", "0f", "0f", "0f"),
            ImageSample("fp1", "false_positive", "fp-sha-1", "01", "01", "01"),
        ]

        state = rebuild_model_state(samples, configured_threshold=20)

        self.assertFalse(state["valid"])
        self.assertEqual(state["reason"], "TP/FP overlap")

    def test_match_exact_tp_before_distance(self) -> None:
        samples = [
            ImageSample("tp1", "true_positive", "same-sha", "ff", "ff", "ff"),
            ImageSample("fp1", "false_positive", "other-sha", "00", "00", "00"),
        ]

        result = match_image(
            {"sha256": "same-sha", "phash": "00", "dhash": "00", "ahash": "00"},
            samples,
            effective_threshold=1,
        )

        self.assertTrue(result["matched"])
        self.assertEqual(result["exact_decision"], "true_positive")
        self.assertEqual(result["score"], 0)

    def test_match_rejects_exact_fp(self) -> None:
        samples = [
            ImageSample("tp1", "true_positive", "tp-sha", "00", "00", "00"),
            ImageSample("fp1", "false_positive", "same-sha", "00", "00", "00"),
        ]

        result = match_image(
            {"sha256": "same-sha", "phash": "00", "dhash": "00", "ahash": "00"},
            samples,
            effective_threshold=20,
        )

        self.assertFalse(result["matched"])
        self.assertEqual(result["exact_decision"], "false_positive")

    def test_match_unknown_tp_within_threshold(self) -> None:
        samples = [
            ImageSample("tp1", "true_positive", "tp-sha", "00", "00", "00"),
        ]

        result = match_image(
            {"sha256": "new-sha", "phash": "01", "dhash": "01", "ahash": "01"},
            samples,
            effective_threshold=3,
        )

        self.assertTrue(result["matched"])
        self.assertIsNone(result["exact_decision"])
        self.assertEqual(result["score"], 3)

    def test_match_rejects_when_fp_is_closer_or_equal(self) -> None:
        samples = [
            ImageSample("tp1", "true_positive", "tp-sha", "00", "00", "00"),
            ImageSample("fp1", "false_positive", "fp-sha", "01", "01", "01"),
        ]

        result = match_image(
            {"sha256": "new-sha", "phash": "01", "dhash": "01", "ahash": "01"},
            samples,
            effective_threshold=10,
        )

        self.assertFalse(result["matched"])
        self.assertTrue(result["ambiguous"])


if __name__ == "__main__":
    unittest.main()

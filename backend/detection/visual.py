from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import imagehash
import numpy as np
from PIL import Image


BRANDS_DIR = Path(__file__).parents[2] / "brands"


# ============================================================
# Brand reference images
# ============================================================

@lru_cache(maxsize=1)
def _brand_hashes() -> dict[str, list[imagehash.ImageHash]]:
    """
    Load perceptual hashes for all brand reference images.

    Expected structure:

        brands/
            paytm/
                reference.png
            phonepe/
                reference.png
            gpay/
                reference.png
    """

    hashes: dict[str, list[imagehash.ImageHash]] = {}

    if not BRANDS_DIR.exists():
        return hashes

    for brand_dir in BRANDS_DIR.iterdir():
        if not brand_dir.is_dir():
            continue

        for image_path in brand_dir.glob("*.png"):
            try:
                with Image.open(image_path) as image:
                    hashes.setdefault(
                        brand_dir.name,
                        [],
                    ).append(
                        imagehash.phash(
                            image.convert("RGB")
                        )
                    )

            except (OSError, ValueError):
                continue

    return hashes


# ============================================================
# Basic pHash
# ============================================================

def perceptual_hash(
    path: str | Path,
) -> str:
    """
    Return a hexadecimal perceptual hash.
    """

    with Image.open(path) as image:
        return str(
            imagehash.phash(
                image.convert("RGB")
            )
        )


# ============================================================
# OCR
# ============================================================

def _ocr_text(
    path: str | Path,
) -> str:
    """
    Extract visible text from a screenshot.

    OCR failures are intentionally non-fatal because
    Tesseract may not be installed/configured on every
    analyst workstation.
    """

    try:
        import pytesseract

        with Image.open(path) as image:
            text = pytesseract.image_to_string(
                image
            )

        return text[:6000]

    except Exception:
        return ""


def _normalise_ocr(text: str) -> set[str]:
    """
    Convert OCR text into normalized tokens.
    """

    tokens = []

    for token in text.lower().split():
        cleaned = "".join(
            character
            for character in token
            if character.isalnum()
        )

        if len(cleaned) >= 3:
            tokens.append(cleaned)

    return set(tokens)


# ============================================================
# Image layout features
# ============================================================

def _layout_signature(
    path: str | Path,
) -> np.ndarray | None:
    """
    Generate a lightweight layout signature.

    This is deliberately model-independent.

    It captures:
      - grayscale spatial structure
      - major visual regions
      - approximate page layout

    It is not intended to replace an embedding model.
    """

    try:
        with Image.open(path) as image:
            image = image.convert("L")
            image = image.resize(
                (32, 32)
            )

            array = np.asarray(
                image,
                dtype=np.float32,
            )

        # Normalize brightness.
        array -= array.mean()

        std = array.std()

        if std > 1e-6:
            array /= std

        return array.flatten()

    except (OSError, ValueError):
        return None


def _cosine_similarity(
    first: np.ndarray | None,
    second: np.ndarray | None,
) -> float:
    """
    Calculate cosine similarity.
    """

    if first is None or second is None:
        return 0.0

    denominator = (
        np.linalg.norm(first)
        * np.linalg.norm(second)
    )

    if denominator <= 1e-12:
        return 0.0

    similarity = float(
        np.dot(first, second)
        / denominator
    )

    return round(
        max(
            0.0,
            min(1.0, similarity),
        ),
        4,
    )


# ============================================================
# Optional deep image embedding
# ============================================================

@lru_cache(maxsize=1)
def _embedding_model():
    """
    Lazily load a pretrained visual embedding model.

    timm is already part of the ML environment.

    If model weights cannot be loaded, the detector
    continues using pHash + layout + OCR instead of
    failing the entire detection request.
    """

    try:
        import timm
        import torch

        model = timm.create_model(
            "resnet18",
            pretrained=True,
            num_classes=0,
            global_pool="avg",
        )

        model.eval()

        config = timm.data.resolve_data_config(
            {},
            model=model,
        )

        transform = timm.data.create_transform(
            **config,
            is_training=False,
        )

        return model, transform, torch

    except Exception:
        return None


def _image_embedding(
    path: str | Path,
) -> np.ndarray | None:
    """
    Generate a normalized image embedding.

    Returns None if the optional deep-learning
    model is unavailable.
    """

    loaded = _embedding_model()

    if loaded is None:
        return None

    model, transform, torch = loaded

    try:
        with Image.open(path) as image:
            image = image.convert("RGB")

            tensor = transform(
                image
            ).unsqueeze(0)

        with torch.no_grad():
            embedding = model(
                tensor
            )

        embedding = embedding.detach().cpu().numpy()

        embedding = embedding.reshape(-1)

        norm = np.linalg.norm(
            embedding
        )

        if norm <= 1e-12:
            return None

        return (
            embedding / norm
        ).astype(np.float32)

    except Exception:
        return None


# ============================================================
# Reference feature cache
# ============================================================

@lru_cache(maxsize=1)
def _brand_reference_features():
    """
    Pre-compute visual features for brand references.

    This keeps repeated detections fast after the first run.
    """

    references: dict[
        str,
        list[dict],
    ] = {}

    if not BRANDS_DIR.exists():
        return references

    for brand_dir in BRANDS_DIR.iterdir():

        if not brand_dir.is_dir():
            continue

        brand = brand_dir.name

        for image_path in brand_dir.glob(
            "*.png"
        ):
            try:
                references.setdefault(
                    brand,
                    [],
                ).append(
                    {
                        "path": str(
                            image_path
                        ),
                        "layout":
                            _layout_signature(
                                image_path
                            ),
                        "embedding":
                            _image_embedding(
                                image_path
                            ),
                    }
                )

            except Exception:
                continue

    return references


# ============================================================
# OCR brand evidence
# ============================================================

def _ocr_brand_score(
    ocr_text: str,
    brand: str | None,
) -> float:
    """
    Determine whether the detected brand name appears
    in the screenshot OCR text.
    """

    if not ocr_text or not brand:
        return 0.0

    text = ocr_text.lower()

    brand_normalized = (
        brand.lower()
        .replace("-", "")
        .replace("_", "")
        .replace(" ", "")
    )

    compact_text = "".join(
        character
        for character in text
        if character.isalnum()
    )

    if brand_normalized in compact_text:
        return 1.0

    tokens = _normalise_ocr(
        ocr_text
    )

    if brand.lower() in tokens:
        return 1.0

    return 0.0


# ============================================================
# Multi-signal visual matching
# ============================================================

def phash_match(
    path: str | Path,
    threshold: int = 16,
    brand_hint: str | None = None,
) -> dict:
    """
    Compare a suspicious screenshot against the
    legitimate brand reference corpus.

    Signals:

      1. pHash distance
      2. deep image embedding similarity
      3. layout similarity
      4. OCR brand evidence

    Important design principle:

      Generic visual similarity does NOT automatically
      mean the page belongs to that specific brand.

    Brand attribution requires stronger evidence.
    """

    try:
        with Image.open(path) as image:
            suspect_hash = imagehash.phash(
                image.convert("RGB")
            )

    except (
        OSError,
        ValueError,
    ) as error:

        return {
            "matched": False,
            "brand": None,
            "distance": None,
            "ocr_text": "",
            "embedding_similarity": 0.0,
            "layout_similarity": 0.0,
            "ocr_brand_match": 0.0,
            "visual_similarity": 0.0,
            "reference_count": 0,
            "error": str(error),
        }

    ocr_text = _ocr_text(path)

    suspect_layout = _layout_signature(
        path
    )

    suspect_embedding = _image_embedding(
        path
    )

    references = _brand_reference_features()

    best = None

    reference_count = sum(
        len(items)
        for items in references.values()
    )

    # --------------------------------------------------------
    # Compare against every reference image
    # --------------------------------------------------------

    for brand, brand_references in references.items():

        for reference in brand_references:

            reference_path = reference[
                "path"
            ]

            try:
                with Image.open(
                    reference_path
                ) as reference_image:

                    reference_hash = (
                        imagehash.phash(
                            reference_image.convert(
                                "RGB"
                            )
                        )
                    )

            except (
                OSError,
                ValueError,
            ):
                continue

            distance = (
                suspect_hash
                - reference_hash
            )

            # ------------------------------------------------
            # pHash similarity
            # ------------------------------------------------

            phash_similarity = max(
                0.0,
                1.0
                - (
                    distance / 64.0
                ),
            )

            # ------------------------------------------------
            # Layout similarity
            # ------------------------------------------------

            layout_similarity = (
                _cosine_similarity(
                    suspect_layout,
                    reference[
                        "layout"
                    ],
                )
            )

            # ------------------------------------------------
            # Deep embedding similarity
            # ------------------------------------------------

            embedding_similarity = (
                _cosine_similarity(
                    suspect_embedding,
                    reference[
                        "embedding"
                    ],
                )
            )

            # ------------------------------------------------
            # OCR brand evidence
            # ------------------------------------------------

            ocr_brand_match = (
                _ocr_brand_score(
                    ocr_text,
                    brand,
                )
            )

            # ------------------------------------------------
            # Generic visual similarity
            # ------------------------------------------------
            #
            # pHash:
            #   40%
            #
            # Embedding:
            #   30%
            #
            # Layout:
            #   20%
            #
            # OCR:
            #   10%
            #
            # OCR is deliberately kept separate because
            # it represents explicit brand evidence.
            # ------------------------------------------------

            base_visual_similarity = (
                phash_similarity * 0.40
                + embedding_similarity * 0.30
                + layout_similarity * 0.20
            )

            visual_similarity = (
                base_visual_similarity
                + ocr_brand_match * 0.10
            )

            candidate = {
                "brand": brand,

                "distance": int(
                    distance
                ),

                "phash_similarity": round(
                    phash_similarity,
                    4,
                ),

                "embedding_similarity": round(
                    embedding_similarity,
                    4,
                ),

                "layout_similarity": round(
                    layout_similarity,
                    4,
                ),

                "ocr_brand_match": round(
                    ocr_brand_match,
                    4,
                ),

                "visual_similarity": round(
                    visual_similarity,
                    4,
                ),
            }

            if (
                best is None
                or candidate[
                    "visual_similarity"
                ]
                > best[
                    "visual_similarity"
                ]
            ):
                best = candidate

    # --------------------------------------------------------
    # No reference available
    # --------------------------------------------------------

    if best is None:

        result = {
            "matched": False,
            "brand": None,
            "distance": None,
            "ocr_text": ocr_text,
            "embedding_similarity": 0.0,
            "layout_similarity": 0.0,
            "ocr_brand_match": 0.0,
            "visual_similarity": 0.0,
            "reference_count": reference_count,
        }

    else:

        matched = (
            best["distance"]
            <= threshold
        )

        # ----------------------------------------------------
        # IMPORTANT:
        #
        # Do NOT assign the highest-scoring brand automatically.
        #
        # A generic payment page can have high ResNet
        # similarity because payment interfaces share common
        # visual structures.
        #
        # Brand attribution therefore requires either:
        #
        # 1. Strong visual match
        #    AND
        #    sufficient combined similarity
        #
        # OR
        #
        # 2. Explicit OCR evidence for that brand.
        #
        # This separates:
        #
        #     "Looks like a payment page"
        #
        # from:
        #
        #     "Looks like Paytm/GPay/PhonePe specifically"
        # ----------------------------------------------------

        brand_confident = (
            (
                matched
                and best["visual_similarity"] >= 0.75
            )
            or
            (
                best["ocr_brand_match"] >= 1.0
            )
        )

        result = {
            "matched": matched,

            "brand":
                best["brand"]
                if brand_confident
                else None,

            "distance":
                best["distance"],

            "phash_similarity":
                best["phash_similarity"],

            "embedding_similarity":
                best["embedding_similarity"],

            "layout_similarity":
                best["layout_similarity"],

            "ocr_brand_match":
                best["ocr_brand_match"],

            "visual_similarity":
                best["visual_similarity"],

            "ocr_text":
                ocr_text,

            "reference_count":
                reference_count,
        }

    # --------------------------------------------------------
    # Official domain brand attribution
    # --------------------------------------------------------
    #
    # If the URL itself belongs to an official brand domain,
    # the domain is authoritative for attribution.
    #
    # Example:
    #
    # https://paytm.com/...
    #
    # -> paytm
    #
    # This does NOT mean an arbitrary domain containing the
    # brand name is considered official.
    # --------------------------------------------------------

    if brand_hint:
        result["brand"] = brand_hint

    return result


# ============================================================
# Official brand detection
# ============================================================

def official_brand_for_url(
    url: str,
) -> str | None:

    hostname = (
        urlparse(url).hostname
        or ""
    ).lower()

    official_domains = {
        "paytm.com": "paytm",
        "phonepe.com": "phonepe",
        "google.com": "gpay",
        "sbi.co.in": "sbi",
        "hdfcbank.com": "hdfc",
        "icicibank.com": "icici",
        "axisbank.com": "axis",
    }

    for domain, brand in (
        official_domains.items()
    ):

        if (
            hostname == domain
            or hostname.endswith(
                f".{domain}"
            )
        ):
            return brand

    return None
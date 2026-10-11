from .behavioral import BehavioralSignals, inspect_dom
from .visual import official_brand_for_url, phash_match
from ..intelligence import domain_risk


# ============================================================
# Visual scoring helpers
# ============================================================

def _visual_score(distance: int | None) -> float:
    """
    Backward-compatible pHash-only score.

    Used only when the advanced visual engine does not
    provide a combined visual score.
    """
    if distance is None:
        return 0.0

    return round(
        max(
            0.0,
            1.0 - distance / 64,
        ),
        4,
    )


def _advanced_visual_score(
    visual: dict,
) -> float:
    """
    Prefer the advanced visual engine score which combines:

    - pHash similarity
    - image embedding similarity
    - layout similarity
    - OCR/brand similarity

    Falls back to pHash when the advanced score is unavailable.
    """

    advanced = visual.get("visual_similarity")

    if advanced is not None:
        try:
            return round(
                max(
                    0.0,
                    min(
                        1.0,
                        float(advanced),
                    ),
                ),
                4,
            )
        except (
            TypeError,
            ValueError,
        ):
            pass

    return _visual_score(
        visual.get("distance")
    )


# ============================================================
# Brand confidence
# ============================================================

def _confident_brand(
    visual: dict,
    official_brand: str | None,
) -> str | None:
    """
    Determine whether the visual engine has enough evidence
    to attribute the suspicious page to a specific brand.

    A brand is considered confident when:

    1. The URL is an official brand domain, OR
    2. The visual engine reports a matched result and
       visual similarity is >= 0.75, OR
    3. OCR explicitly identifies the brand.

    Generic visual similarity is NOT sufficient to identify
    a specific financial/payment brand.
    """

    # Official domain is authoritative.
    if official_brand:
        return official_brand

    if not visual:
        return None

    candidate_brand = visual.get("brand")

    if not candidate_brand:
        return None

    visual_similarity = float(
        visual.get(
            "visual_similarity",
            0.0,
        )
        or 0.0
    )

    matched = bool(
        visual.get(
            "matched",
            False,
        )
    )

    ocr_brand_match = float(
        visual.get(
            "ocr_brand_match",
            0.0,
        )
        or 0.0
    )

    # Explicit OCR brand evidence.
    if ocr_brand_match >= 1.0:
        return candidate_brand

    # Strong visual clone evidence.
    if (
        matched
        and visual_similarity >= 0.75
    ):
        return candidate_brand

    # Weak/generic resemblance.
    return None


# ============================================================
# Signal combination
# ============================================================

def combine_signals(
    visual_similarity: float,
    behavioral: BehavioralSignals,
    domain_score: float,
) -> tuple[float, dict]:

    behavioral_score = min(
        1.0,
        (
            int(
                behavioral.external_form_action
            ) * 0.35

            + int(
                behavioral.suspicious_redirect
            ) * 0.20

            + int(
                bool(
                    behavioral.sensitive_inputs
                )
            ) * 0.25

            + int(
                behavioral.iframe_count > 0
            ) * 0.05

            + min(
                behavioral.brand_keyword_count,
                5,
            )
            / 5
            * 0.10

            + int(
                bool(
                    behavioral.external_resources
                )
            ) * 0.05
        ),
    )

    # ---------------------------------------------------------
    # Main risk model
    #
    # Visual similarity  : 45%
    # Behavioral signals : 35%
    # Domain intelligence: 20%
    # ---------------------------------------------------------

    final = min(
        1.0,
        visual_similarity * 0.45
        + behavioral_score * 0.35
        + domain_score * 0.20,
    )

    return round(
        final,
        4,
    ), {
        "visual_similarity": round(
            visual_similarity,
            4,
        ),
        "behavioral_score": round(
            behavioral_score,
            4,
        ),
        "domain_score": round(
            domain_score,
            4,
        ),
    }


# ============================================================
# Main detection function
# ============================================================

def score(
    url: str,
    screenshot: str,
    dom: str,
    brand_keywords: list[str] | None = None,
    phishing_threshold: float = 0.60,
    suspicious_threshold: float = 0.35,
    domain_intel: dict | None = None,
) -> dict:

    # ---------------------------------------------------------
    # Default detection keywords
    # ---------------------------------------------------------

    brand_keywords = brand_keywords or [
        "upi",
        "payment",
        "paytm",
        "phonepe",
        "google pay",
        "gpay",
        "bank",
        "verify",
        "secure",
        "login",
        "account",
        "transaction",
    ]

    # ---------------------------------------------------------
    # 1. Determine official brand from URL
    # ---------------------------------------------------------

    official_brand = official_brand_for_url(url)

    # ---------------------------------------------------------
    # 2. Advanced visual analysis
    # ---------------------------------------------------------

    visual = phash_match(
        screenshot,
        brand_hint=official_brand,
    )

    # ---------------------------------------------------------
    # 3. Calculate visual similarity
    # ---------------------------------------------------------

    visual_similarity = _advanced_visual_score(
        visual
    )

    # ---------------------------------------------------------
    # 4. Determine confident brand
    # ---------------------------------------------------------

    detected_brand = _confident_brand(
        visual=visual,
        official_brand=official_brand,
    )

    # ---------------------------------------------------------
    # 5. DOM / behavioral analysis
    # ---------------------------------------------------------

    with open(
        dom,
        encoding="utf-8",
        errors="ignore",
    ) as stream:
        html = stream.read()

    behavioral = inspect_dom(
        html,
        brand_keywords,
        url,
    )

    # ---------------------------------------------------------
    # 6. Domain intelligence
    # ---------------------------------------------------------

    if domain_intel is None:
        domain_intel = {
            "lexical": {}
        }

    domain_score, domain_reasons = domain_risk(
        domain_intel
    )

    # ---------------------------------------------------------
    # 7. Combine core signals
    # ---------------------------------------------------------

    final_score, components = combine_signals(
        visual_similarity=visual_similarity,
        behavioral=behavioral,
        domain_score=domain_score,
    )

    # ---------------------------------------------------------
    # 8. Threat intelligence
    # ---------------------------------------------------------

    threat_intel = (
        domain_intel or {}
    ).get(
        "threat_intel",
        {},
    )

    ti_score = 0.0

    if threat_intel.get("matched"):
        try:
            ti_confidence = float(
                threat_intel.get(
                    "confidence",
                    0.0,
                )
            )
        except (
            TypeError,
            ValueError,
        ):
            ti_confidence = 0.0

        ti_score = min(
            1.0,
            max(
                0.0,
                ti_confidence,
            ),
        )

        # Threat intelligence contributes up to 15%
        # to the final risk score.
        final_score = min(
            1.0,
            final_score + (
                ti_score * 0.15
            ),
        )

    # Store TI contribution for explainability.
    components["threat_intel_score"] = round(
        ti_score,
        4,
    )

    # ---------------------------------------------------------
    # 9. Safety / confidence adjustments
    # ---------------------------------------------------------

    suspicious_behavior = (
        behavioral.external_form_action
        or behavioral.suspicious_redirect
        or bool(
            behavioral.sensitive_inputs
        )
    )

    # ---------------------------------------------------------
    # Official domains without suspicious behavior
    # ---------------------------------------------------------

    if (
        official_brand
        and not suspicious_behavior
    ):
        final_score = min(
            final_score,
            0.25,
        )

    # ---------------------------------------------------------
    # Strong phishing-like behavior
    #
    # Do not allow weak visual/domain signals to hide
    # a page that collects sensitive payment/authentication
    # information and submits it externally.
    # ---------------------------------------------------------

    if (
        behavioral.external_form_action
        and behavioral.sensitive_inputs
    ):
        final_score = max(
            final_score,
            0.65,
        )

    # Always keep score inside [0, 1].
    final_score = min(
        1.0,
        max(
            0.0,
            final_score,
        ),
    )

    # ---------------------------------------------------------
    # 10. Verdict
    # ---------------------------------------------------------

    if final_score >= phishing_threshold:
        verdict = "phishing"

    elif final_score >= suspicious_threshold:
        verdict = "suspicious"

    else:
        verdict = "benign"

    # ---------------------------------------------------------
    # 11. Explainable reasons
    # ---------------------------------------------------------

    reasons: list[str] = []

    # Visual similarity.
    if visual_similarity >= 0.70:
        reasons.append(
            "Strong visual similarity to a known payment/financial brand"
        )

    elif visual_similarity >= 0.45:
        reasons.append(
            "Moderate visual similarity to a known payment/financial brand"
        )

    # Embedding.
    if (
        visual.get(
            "embedding_similarity",
            0,
        )
        >= 0.70
    ):
        reasons.append(
            "Strong image embedding similarity detected"
        )

    # Layout.
    if (
        visual.get(
            "layout_similarity",
            0,
        )
        >= 0.70
    ):
        reasons.append(
            "Strong page layout similarity detected"
        )

    # OCR.
    if (
        visual.get(
            "ocr_brand_match",
            0,
        )
        >= 0.70
    ):
        reasons.append(
            "Brand text detected through OCR"
        )

    # Domain intelligence.
    if domain_reasons:
        reasons.extend(
            domain_reasons
        )

    # Threat intelligence.
    if threat_intel.get("matched"):
        source = threat_intel.get(
            "source",
            "unknown source",
        )

        confidence = float(
            threat_intel.get(
                "confidence",
                0.0,
            )
            or 0.0
        )

        reasons.append(
            f"Threat-intelligence match detected "
            f"from {source} "
            f"with {confidence:.0%} confidence"
        )

    # External form.
    if behavioral.external_form_action:
        reasons.append(
            "Form submits data to an external origin"
        )

    # Redirect.
    if behavioral.suspicious_redirect:
        reasons.append(
            "Suspicious redirect behavior detected"
        )

    # Sensitive inputs.
    if behavioral.sensitive_inputs:
        reasons.append(
            "Sensitive payment/authentication input detected"
        )

    # Iframe.
    if behavioral.iframe_count > 0:
        reasons.append(
            "Embedded iframe detected"
        )

    # External resources.
    if behavioral.external_resources:
        reasons.append(
            "External resources detected"
        )

    # Keywords.
    if behavioral.brand_keyword_count:
        reasons.append(
            f"{behavioral.brand_keyword_count} "
            "payment/brand keywords detected"
        )

    # ---------------------------------------------------------
    # Brand attribution explanation
    # ---------------------------------------------------------

    if (
        detected_brand is None
        and visual.get("brand")
    ):
        reasons.append(
            "Visual resemblance was insufficient "
            "for confident brand attribution"
        )

    # ---------------------------------------------------------
    # 12. Final result
    # ---------------------------------------------------------

    return {
        "url": url,

        # Confidence-gated brand.
        "brand": detected_brand,

        # Legacy pHash information.
        "phash_distance": visual.get(
            "distance"
        ),

        # Complete visual engine output.
        "visual": visual,

        # Behavioral analysis.
        "behavioral": behavioral.to_dict(),

        # Domain intelligence.
        "domain_intel": domain_intel,

        # Explainable model components.
        "components": components,

        # Human-readable reasons.
        "reasons": reasons,

        # Final classification.
        "score": round(
            final_score,
            4,
        ),

        "verdict": verdict,
    }
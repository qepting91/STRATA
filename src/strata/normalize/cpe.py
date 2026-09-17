"""CPE 2.3 parsing -- pure function, no I/O.

Parses a CPE 2.3 formatted string
(``cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:
target_sw:target_hw:other``) into a ``(vendor, product)`` slug pair safe for
use as SQLite node ids (lowercase, non-alphanumeric runs collapsed to a
single underscore).

CPE 2.3's binding rules allow backslash-escaped colons/underscores/etc.
within a single field (e.g. a product name that legitimately contains a
colon). This parser respects that escaping when splitting fields, so an
escaped colon does not get misread as a field separator. It does not
otherwise interpret CPE's other special values (``*`` any, ``-`` n/a) beyond
treating them as "no value" for slugging purposes.
"""

from __future__ import annotations

import re

_CPE_PREFIX = "cpe:2.3:"
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


def _split_cpe_fields(body: str) -> list[str]:
    """Split the CPE body on unescaped colons, honoring backslash escapes."""
    fields: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            # Keep the escaped character literally (drop the backslash),
            # matching CPE 2.3's binding semantics for special characters.
            current.append(body[i + 1])
            i += 2
            continue
        if ch == ":":
            fields.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    fields.append("".join(current))
    return fields


def _slugify(value: str) -> str:
    slug = _NON_ALNUM_RE.sub("_", value.lower()).strip("_")
    return slug


def parse_cpe23(cpe: str) -> tuple[str, str]:
    """Parse a CPE 2.3 string into ``(vendor_slug, product_slug)``.

    Args:
        cpe: A well-formed CPE 2.3 URI, e.g.
            ``cpe:2.3:a:ivanti:connect_secure:9.1:r18:*:*:*:*:*:*``.

    Returns:
        A ``(vendor, product)`` tuple of lowercase, underscore-safe slugs
        suitable for use as node ids (e.g. ``("ivanti", "connect_secure")``).

    Raises:
        ValueError: If ``cpe`` does not start with the ``cpe:2.3:`` prefix,
            does not carry at least a vendor and product field, or either
            of those fields is empty/a CPE wildcard (``*``) or "not
            applicable" (``-``) after unescaping.
    """
    if not isinstance(cpe, str) or not cpe.startswith(_CPE_PREFIX):
        raise ValueError(f"not a CPE 2.3 string (missing {_CPE_PREFIX!r} prefix): {cpe!r}")

    body = cpe[len(_CPE_PREFIX) :]
    fields = _split_cpe_fields(body)

    # fields = [part, vendor, product, version, update, edition, language,
    #           sw_edition, target_sw, target_hw, other]
    if len(fields) < 3:
        raise ValueError(f"malformed CPE 2.3 string, too few fields: {cpe!r}")

    _part, vendor_raw, product_raw = fields[0], fields[1], fields[2]

    if not vendor_raw or vendor_raw in ("*", "-"):
        raise ValueError(f"CPE 2.3 string has no concrete vendor field: {cpe!r}")
    if not product_raw or product_raw in ("*", "-"):
        raise ValueError(f"CPE 2.3 string has no concrete product field: {cpe!r}")

    vendor = _slugify(vendor_raw)
    product = _slugify(product_raw)

    if not vendor or not product:
        raise ValueError(f"CPE 2.3 vendor/product slugified to empty string: {cpe!r}")

    return vendor, product

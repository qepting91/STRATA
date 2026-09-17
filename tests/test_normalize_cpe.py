"""Tests for strata.normalize.cpe.parse_cpe23."""

from __future__ import annotations

import pytest

from strata.normalize.cpe import parse_cpe23


def test_parse_well_formed_cpe() -> None:
    vendor, product = parse_cpe23("cpe:2.3:a:ivanti:connect_secure:9.1:r18:*:*:*:*:*:*")
    assert vendor == "ivanti"
    assert product == "connect_secure"


def test_parse_cpe_with_spaces_and_mixed_case() -> None:
    vendor, product = parse_cpe23("cpe:2.3:a:Some-Vendor:Some Product Name:1.0:*:*:*:*:*:*:*")
    assert vendor == "some_vendor"
    assert product == "some_product_name"


def test_parse_cpe_with_escaped_colon_in_product() -> None:
    # A product field containing a literal colon, escaped per CPE 2.3
    # binding rules.
    vendor, product = parse_cpe23(r"cpe:2.3:a:vendor:product\:sub:1.0:*:*:*:*:*:*:*")
    assert vendor == "vendor"
    assert product == "product_sub"


def test_parse_minimal_cpe_without_trailing_fields() -> None:
    vendor, product = parse_cpe23("cpe:2.3:a:acme:widget")
    assert vendor == "acme"
    assert product == "widget"


@pytest.mark.parametrize(
    "bad_cpe",
    [
        "not-a-cpe-string",
        "cpe:2.3:a:*:widget:1.0:*:*:*:*:*:*:*",  # wildcard vendor
        "cpe:2.3:a:acme:-:1.0:*:*:*:*:*:*:*",  # n/a product
        "cpe:2.3:a:acme",  # missing product field entirely
        "cpe:2.3:a::1.0",  # empty vendor
        123,  # not a string at all
    ],
)
def test_parse_malformed_cpe_raises_value_error(bad_cpe) -> None:
    with pytest.raises(ValueError):
        parse_cpe23(bad_cpe)

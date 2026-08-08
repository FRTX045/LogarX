"""Tests for evasion-aware normalisation.

Every one of these corresponds to a technique used to slip a payload past a
signature. If normalisation misses one, every rule downstream misses it too.
"""

from __future__ import annotations

import pytest

from logarc.normalize.decode import normalize


def test_plain_text_is_unchanged_apart_from_case() -> None:
    result = normalize("/index.html")

    assert result.text == "/index.html"
    assert result.decode_depth == 0


def test_percent_encoding_is_decoded() -> None:
    result = normalize("/a%2Fb")

    assert result.text == "/a/b"
    assert result.decode_depth == 1


def test_double_encoding_is_decoded_and_counted() -> None:
    """`%2553ELECT` is `%53ELECT` once decoded, and `SELECT` twice decoded.
    A rule matching only the single-decoded form would miss it entirely."""
    result = normalize("%2553ELECT")

    assert result.text == "select"
    assert result.decode_depth == 2


def test_decoding_is_bounded_and_says_so_when_it_gives_up() -> None:
    """Each `25` adds one layer: %2525252541 takes five rounds to reach "A".
    Stopping early is fine, but the caller must be told it happened rather than
    handed a half-decoded string that looks canonical."""
    deeply_encoded = "%" + "25" * 4 + "41"

    result = normalize(deeply_encoded, max_depth=3)

    assert result.decode_depth == 3
    assert result.truncated_decoding is True
    assert result.text != "a"


def test_decoding_stops_early_when_the_text_settles() -> None:
    result = normalize("%" + "25" * 4 + "41", max_depth=10)

    assert result.text == "a"
    assert result.decode_depth == 5
    assert result.truncated_decoding is False


def test_depth_beyond_one_is_flagged_as_suspicious_in_itself() -> None:
    """Ordinary traffic is encoded once. More than that is deliberate."""
    assert normalize("/a%2Fb").multiply_encoded is False
    assert normalize("%2553ELECT").multiply_encoded is True


def test_case_is_folded() -> None:
    assert normalize("/AdMiN").text == "/admin"


def test_fullwidth_characters_fold_to_ascii() -> None:
    """Unicode lookalikes are a standard way to dodge a literal match."""
    assert normalize("ＳＥＬＥＣＴ").text == "select"


def test_sql_block_comments_are_removed() -> None:
    """`UNI/**/ON` defeats a naive `union` match while still executing."""
    assert normalize("UNI/**/ON SELECT").text == "union select"


def test_unterminated_comment_does_not_swallow_the_rest() -> None:
    assert "select" in normalize("/*x SELECT").text


def test_runs_of_whitespace_collapse() -> None:
    assert normalize("union   \t select").text == "union select"


def test_encoded_whitespace_collapses_too() -> None:
    assert normalize("union%20%20%09select").text == "union select"


def test_invalid_percent_sequences_are_left_alone() -> None:
    """`%zz` is not an escape; treating it as one would corrupt the evidence."""
    assert normalize("/a%zzb").text == "/a%zzb"


def test_null_bytes_are_preserved_because_they_are_signal() -> None:
    assert "\x00" in normalize("/a%00.jpg").text


def test_plus_is_not_treated_as_a_space_in_a_path() -> None:
    """`+` only means space in a query string, and paths run through here too."""
    assert normalize("/a+b").text == "/a+b"


def test_empty_input_is_handled() -> None:
    result = normalize("")

    assert result.text == ""
    assert result.decode_depth == 0


def test_none_input_normalises_to_empty() -> None:
    assert normalize(None).text == ""


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ("%27%20OR%20%271%27%3D%271", "' or '1'='1"),
        ("..%2f..%2f..%2fetc%2fpasswd", "../../../etc/passwd"),
        ("%252e%252e%252fetc", "../etc"),
        ("<ScRiPt>alert(1)</ScRiPt>", "<script>alert(1)</script>"),
    ],
)
def test_known_evasions_reach_their_canonical_form(payload: str, expected: str) -> None:
    assert normalize(payload).text == expected


def test_a_plus_is_a_space_when_the_text_is_form_encoded() -> None:
    """Every HTML form and most attack tools write spaces as `+`.

    Without this, `id=1%27+OR+%271%27%3D%271` reaches the rules as
    `1'+or+'1'='1`, no whitespace class matches, and a payload that any browser
    would send passes every signature untouched.
    """
    result = normalize("id=1%27+OR+%271%27%3D%271", plus_is_space=True)

    assert result.text == "id=1' or '1'='1"


def test_a_plus_stays_a_plus_where_it_is_not_form_encoded() -> None:
    """A path and a User-Agent are not form data; `+` there means `+`."""
    assert normalize("/a+b/c").text == "/a+b/c"
    assert "+http://" in normalize("Mozilla/5.0 (compatible; Googlebot/2.1; +http://x/)").text

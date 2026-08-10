"""Tests for evasion-aware normalisation.

Every one of these corresponds to a technique used to slip a payload past a
signature. If normalisation misses one, every rule downstream misses it too.
"""

from __future__ import annotations

import pytest

from logarc.normalize.decode import canonical_path, normalize


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


def test_null_bytes_are_stripped_but_the_fact_of_one_is_kept() -> None:
    """Reverses an earlier decision, deliberately.

    This test used to assert the null stayed in the text, on the reasoning that
    it is signal. The reasoning was right and the conclusion was wrong: keeping
    it in the matched text means `/etc/passwd%00.jpg` never reaches
    `sensitive_file_access`, because the rule is written against the path the
    server actually opens. Both wants are satisfiable — strip it from the text,
    keep the fact on the result — which is the same shape as `decode_depth`,
    where the encoding is undone and the fact of it survives.
    """
    result = normalize("/a%00.jpg")

    assert "\x00" not in result.text
    assert result.text == "/a.jpg"
    assert result.had_null is True


def test_text_without_a_null_says_so() -> None:
    assert normalize("/a.jpg").had_null is False


def test_html_entities_are_decoded() -> None:
    """`&#60;script&#62;` is `<script>` to a browser and a different string to a
    rule written against the tag."""
    assert normalize("&#60;script&#62;alert(1)").text == "<script>alert(1)"
    assert normalize("&lt;script&gt;").text == "<script>"


def test_entity_leading_zeros_are_tolerated() -> None:
    """Padding the codepoint is itself the evasion; the corpus writes 47 zeros."""
    assert normalize("&#x24;&#00000000000000000000000000000000000000000000000123;jndi:").text == (
        "${jndi:"
    )


def test_unterminated_named_entities_are_left_alone() -> None:
    """Why this is hand-rolled rather than `html.unescape`, which decodes
    `&notit;` to `¬it;` and would invent payloads in ordinary query strings."""
    assert normalize("a&notit;b").text == "a&notit;b"
    assert normalize("q=cats&dogs=1").text == "q=cats&dogs=1"


def test_javascript_escapes_are_decoded() -> None:
    assert normalize(r"\u0076\u0061lue\u004Ff").text == "valueof"
    assert normalize(r"\x3cscript\x3e").text == "<script>"


def test_octal_escapes_are_left_alone_so_windows_paths_survive() -> None:
    r"""`\123` would become `S`, and a Windows path is exactly what a traversal
    payload in a request line looks like."""
    assert r"\123" in normalize(r"c:\windows\123").text


def test_encodings_nested_in_each_other_are_all_undone() -> None:
    """One loop rather than one pass each: these nest in both directions."""
    assert normalize("%26lt%3Bscript%26gt%3B").text == "<script>"
    assert normalize("&#x25;3Cscript").text == "<script"


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


@pytest.mark.parametrize(
    ("written", "resource"),
    [
        ("/a/b", "/a/b"),
        ("/a//b", "/a/b"),
        ("/a/./b", "/a/b"),
        ("/a///.//b", "/a/b"),
        ("/a/c/../b", "/a/b"),
        ("/a/b/", "/a/b"),
        # The root is a resource in its own right, and must stay distinct from
        # "this request had no path at all".
        ("/", "/"),
        ("", ""),
        (None, ""),
    ],
)
def test_one_resource_written_several_ways_counts_once(written: str | None, resource: str) -> None:
    """`distinct_paths` gates three window rules, so writing a path unusually
    must not move the count that decides whether a behaviour is detected."""
    assert canonical_path(written) == resource


def test_traversal_above_the_root_is_clamped_not_escaped() -> None:
    assert canonical_path("/../../etc/passwd") == "/etc/passwd"


def test_path_case_is_preserved_because_servers_distinguish_it() -> None:
    """Folding these together would undercount real enumeration."""
    assert canonical_path("/Admin") != canonical_path("/admin")


def test_canonical_path_leaves_percent_encoding_alone() -> None:
    """A deliberate limit: folding these is a wider change to what a path count
    means, and it belongs with its own measurement."""
    assert canonical_path("/%61dmin") == "/%61dmin"


def test_several_writings_collapse_to_a_single_count() -> None:
    written = ["/a/b", "/a//b", "/a/./b", "/a/b/"]

    assert len({canonical_path(path) for path in written}) == 1
    assert len(set(written)) == 4


def test_canonicalisation_is_not_wired_into_matching_normalisation() -> None:
    """The trap this function exists to avoid.

    `path_traversal` matches on the `..` itself. If `normalize` ever routed a
    path through `canonical_path`, `../../etc/passwd` would arrive as
    `/etc/passwd` and the rule would stop firing entirely.
    """
    assert ".." in normalize("/../../etc/passwd").text

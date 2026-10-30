"""Write the icon set the desktop application ships, from a Lucide release.

    python tools/lucide_data.py ICON_NODES TAGS OUT

ICON_NODES and TAGS are `icon-nodes.json` and `tags.json` from the npm package
`lucide-static@0.452.0` (for instance from
https://unpkg.com/lucide-static@0.452.0/icon-nodes.json). OUT is normally
`src/zodiarc/gui/lucide.json`.

Each icon becomes one SVG, its shapes inside Lucide's own frame, so the
application draws it without knowing anything about Lucide's formats. The two
inputs' SHA-256 digests are recorded beside the icons: the inputs are not kept
in this repository, and the digests are what lets anyone holding a copy check
that the shipped file came from them, by writing it again and comparing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Final
from xml.sax.saxutils import quoteattr

VERSION: Final = "0.452.0"
SOURCE: Final = f"lucide-static@{VERSION}"

#: Lucide's frame, as its own SVGs open: a 24 unit square, drawn in outline with
#: the colour left to whoever draws it.
FRAME: Final = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" '
    'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" '
    'stroke-linejoin="round">'
)


#: `"` escaped too, so every value is double-quoted: left alone, `quoteattr`
#: switches to single quotes for a value holding one.
_QUOTE: Final = {'"': "&quot;"}


def _element(tag: str, attributes: dict[str, str]) -> str:
    written = "".join(
        f" {name}={quoteattr(str(value), _QUOTE)}" for name, value in attributes.items()
    )
    return f"<{tag}{written}/>"


def build(nodes: Path, tags: Path) -> dict[str, object]:
    """The shipped file's contents, from the two inputs."""
    shapes = json.loads(nodes.read_text(encoding="utf-8"))
    tagged = json.loads(tags.read_text(encoding="utf-8"))
    icons = {
        name: {
            "svg": FRAME + "".join(_element(tag, attrs) for tag, attrs in elements) + "</svg>",
            "tags": list(tagged.get(name, [])),
        }
        for name, elements in shapes.items()
    }
    return {
        "version": VERSION,
        "source": SOURCE,
        "sha256": {
            "icon-nodes.json": hashlib.sha256(nodes.read_bytes()).hexdigest(),
            "tags.json": hashlib.sha256(tags.read_bytes()).hexdigest(),
        },
        "icons": icons,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("icon_nodes", type=Path, help="lucide-static's icon-nodes.json")
    parser.add_argument("tags", type=Path, help="lucide-static's tags.json")
    parser.add_argument(
        "out", type=Path, help="where to write, normally src/zodiarc/gui/lucide.json"
    )
    arguments = parser.parse_args(argv)
    data = build(arguments.icon_nodes, arguments.tags)
    # `\n` whatever the platform: written on Windows with the default, the
    # file would change on every machine that regenerated it.
    with arguments.out.open("w", encoding="utf-8", newline="\n") as out:
        json.dump(data, out, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        out.write("\n")
    count = len(json.loads(arguments.out.read_text(encoding="utf-8"))["icons"])
    print(f"{count} icons from {SOURCE} written to {arguments.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

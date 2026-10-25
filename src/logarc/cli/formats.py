"""`logarc formats`: see, write and try out log formats.

The second half of the command line, on its own because it is a different
job from the first: the commands in `cli.main` read and analyse a case, and
these write the definitions a case is read with. `main` registers the group.
"""

from __future__ import annotations

import json
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Final

import typer
from rich.table import Table

from logarc.cli.support import console, fail, path_line
from logarc.core.evidence import EvidenceRef
from logarc.ingest.reader import LogSourceError, open_log
from logarc.parsers.base import LogParser
from logarc.parsers.columns import ColumnsFormatError, declared_columns
from logarc.parsers.fieldnames import guess_mapping as guess_from_names
from logarc.parsers.json_format import JsonFormatError, guess_mapping
from logarc.parsers.library import (
    FormatLibraryError,
    library_path,
    load_library,
    save_library,
)
from logarc.parsers.logformat import LogFormatError
from logarc.parsers.pattern import PatternFormatError
from logarc.parsers.registry import (
    DEFAULT_SAMPLE_SIZE,
    UnknownFormatError,
    get_spec,
    is_built_in,
    registered_formats,
)
from logarc.parsers.spec import (
    ColumnsFormatSpec,
    FormatSpec,
    JsonFormatSpec,
    LogFormatSpec,
    PatternFormatSpec,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["formats_app"]

formats_app = typer.Typer(
    help="See, write and try out log formats.",
    invoke_without_command=True,
    add_completion=False,
)


@formats_app.callback(invoke_without_command=True)
def formats(ctx: typer.Context) -> None:
    """List the log formats that can be parsed.

    Kept as the group's own behaviour rather than a `list` subcommand, so that
    `logarc formats` keeps doing what it did before there were subcommands.
    """
    if ctx.invoked_subcommand is not None:
        return

    table = Table(title="Known log formats")
    table.add_column("Name")
    table.add_column("Source")
    table.add_column("What it reads")
    for entry in registered_formats():
        # What it is for, not what it says. With three formats the definitions
        # fitted; with seventeen they are a wall of mappings nine lines deep,
        # and a list exists to help someone pick. `formats show` is where the
        # definition lives, and the line under this table points at it.
        note = entry.spec.description if entry.spec is not None else ""
        table.add_row(
            entry.name,
            "built-in" if is_built_in(entry.name) else "saved",
            note or entry.description,
        )
    console.print(table)
    console.print(
        "\n[bold]logarc formats show <name>[/bold] prints the definition behind one. "
        "Write your own with [bold]add[/bold], [bold]add-json[/bold], "
        "[bold]add-columns[/bold] or [bold]add-pattern[/bold] — and try it against a "
        "real log first with the matching [bold]check[/bold]."
    )
    path_line(f"Saved formats: {library_path()}")


@formats_app.command("add")
def formats_add(
    name: Annotated[str, typer.Argument(help="What to call this format.")],
    directive: Annotated[str, typer.Argument(help="The Apache LogFormat directive string.")],
    note: Annotated[
        str, typer.Option("--note", help="A reminder of what this format is for.")
    ] = "",
    replace: Annotated[
        bool, typer.Option("--replace", help="Overwrite a saved format of the same name.")
    ] = False,
) -> None:
    """Save a log format so later cases can be ingested with it by name."""
    _save_spec(LogFormatSpec(name=name, directive=directive, description=note), replace=replace)


def _save_spec(spec: FormatSpec, *, replace: bool) -> None:
    """Put `spec` in the library, or refuse and say why.

    Shared by both kinds. Two copies of these three refusals would be one edit
    away from `add` and `add-json` disagreeing about what a name may be.
    """
    saved = _load_orfail()
    existing = {item.name for item in saved}

    if is_built_in(spec.name):
        raise fail(
            f"{spec.name!r} is a built-in format. Built-ins are matched first, so a saved "
            "format of the same name would never be reached; pick another name."
        )
    if spec.name in existing and not replace:
        raise fail(f"{spec.name!r} is already saved; pass --replace to overwrite it")

    kept = [item for item in saved if item.name != spec.name]
    try:
        save_library([*kept, spec])
    except FormatLibraryError as exc:
        raise fail(str(exc)) from exc

    console.print(f"Saved [bold]{spec.name}[/bold]: {spec.summary}")
    path_line(f"Saved formats: {library_path()}")


def _mapping_from(pairs: Sequence[str]) -> list[tuple[str, str]]:
    """Read `--map ours=theirs` options into a mapping."""
    mapping: list[tuple[str, str]] = []
    for pair in pairs:
        ours, separator, theirs = pair.partition("=")
        if not separator or not ours.strip() or not theirs.strip():
            raise fail(f"--map wants ours=theirs, not {pair!r}")
        mapping.append((ours.strip(), theirs.strip()))
    return mapping


def _first_json_object(log: Path) -> dict[str, Any]:
    """The first line of `log` that is a JSON object, for guessing from."""
    try:
        with open_log(log) as stream:
            for _number, text in islice(stream, DEFAULT_SAMPLE_SIZE):
                if not text.strip():
                    continue
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    return payload
    except LogSourceError as exc:
        raise fail(str(exc)) from exc
    raise fail(f"no line of {log} is a JSON object; is this a JSON log?")


def _read_back(parser: LogParser, log: Path, lines: int, title: str) -> int:
    """Show what `parser` pulls out of the first lines of `log`. Returns how
    many of them it read."""
    try:
        with open_log(log) as stream:
            # The log's own bookkeeping is skipped, not shown as a row that did
            # not match: four directives open every IIS file and reporting them
            # as failures would bury the two rows the reader came to look at.
            sample = [
                (number, text)
                for number, text in islice(stream, lines + _HEADER_ROOM)
                if text.strip() and not parser.is_metadata(text)
            ][:lines]
    except LogSourceError as exc:
        raise fail(str(exc)) from exc

    table = Table(title=title)
    for column in ("Line", "Client", "When", "Method", "Path", "Status"):
        table.add_column(column)

    parsed = 0
    for number, text in sample:
        event = parser.parse_line(text, EvidenceRef(log.name, number))
        if event is None:
            table.add_row(str(number), "[red]did not match[/red]", "", "", "", "")
            continue
        parsed += 1
        table.add_row(
            str(number),
            event.client_ip,
            event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            event.method or "",
            event.path or "",
            str(event.status) if event.status is not None else "",
        )
    console.print(table)
    console.print(f"Read [bold]{parsed} of {len(sample)}[/bold] lines.")
    return parsed


def _merge_mapping(
    written: Sequence[tuple[str, str]], guessed: Sequence[tuple[str, str]]
) -> list[tuple[str, str]]:
    """What the reader wrote, then whatever was guessed that they did not override."""
    overridden = {ours for ours, _theirs in written}
    return [*written, *((ours, theirs) for ours, theirs in guessed if ours not in overridden)]


def _show_mapping(mapping: Sequence[tuple[str, str]]) -> None:
    table = Table(title="Fields")
    table.add_column("logarc calls it")
    table.add_column("your log calls it")
    for ours, theirs in mapping:
        table.add_row(ours, theirs)
    console.print(table)


@formats_app.command("add-json")
def formats_add_json(
    name: Annotated[str, typer.Argument(help="What to call this format.")],
    log: Annotated[
        Path | None,
        typer.Option("--log", help="A JSON log to guess the mapping from."),
    ] = None,
    mapping: Annotated[
        list[str] | None,
        typer.Option("--map", help="ours=theirs, repeatable. Overrides the guess."),
    ] = None,
    time_format: Annotated[
        str,
        typer.Option(
            "--time-format", help="strftime pattern, if the time is neither ISO nor epoch."
        ),
    ] = "",
    note: Annotated[str, typer.Option("--note", help="A reminder of what this is for.")] = "",
    replace: Annotated[
        bool, typer.Option("--replace", help="Overwrite a saved format of the same name.")
    ] = False,
) -> None:
    """Save a format for a log that writes one JSON object per line.

    With `--log`, the mapping is guessed from the first line and shown. JSON
    keys are self-describing in a way a positional format's are not, so the
    guess is worth making — and any `--map` you give overrides it, so
    correcting one field does not mean writing out the other seven.
    """
    guessed = guess_mapping(_first_json_object(log)) if log is not None else ()
    fields = _merge_mapping(_mapping_from(mapping or []), guessed)

    if not fields:
        raise fail("give --log to guess the mapping, or --map to write it out")

    _show_mapping(fields)
    spec = JsonFormatSpec(
        name=name, fields=tuple(fields), time_format=time_format, description=note
    )
    try:
        spec.build()
    except JsonFormatError as exc:
        raise fail(str(exc)) from exc

    _save_spec(spec, replace=replace)


@formats_app.command("check-json")
def formats_check_json(
    log: Annotated[Path, typer.Option("--log", help="A JSON log to try.")],
    mapping: Annotated[
        list[str] | None,
        typer.Option("--map", help="ours=theirs, repeatable. Overrides the guess."),
    ] = None,
    lines: Annotated[int, typer.Option("--lines", min=1, help="How many lines to read.")] = 5,
) -> None:
    """Guess a JSON log's mapping and show what it reads, without saving it."""
    fields = _merge_mapping(_mapping_from(mapping or []), guess_mapping(_first_json_object(log)))

    _show_mapping(fields)
    spec = JsonFormatSpec(name="check", fields=tuple(fields))
    try:
        parser = spec.build()
    except JsonFormatError as exc:
        raise fail(str(exc)) from exc

    if _read_back(parser, log, lines, f"{log.name}") == 0:
        raise fail("this mapping reads nothing in that log; check the key names above")


#: What `--separator` accepts. Named rather than typed literally, because a
#: tab is not something a reader can put on a command line, and " " quoted on a
#: shell is a trap that eats itself.
_SEPARATORS: Final[dict[str, str]] = {"space": " ", "comma": ",", "tab": "\t"}
_SEPARATOR_NAMES: Final[dict[str, str]] = {char: name for name, char in _SEPARATORS.items()}

#: Extra lines read so that `--lines 5` still shows five *rows* of a log whose
#: first several lines are its own header.
_HEADER_ROOM: Final = 8


def _separator_from(name: str) -> str:
    try:
        return _SEPARATORS[name]
    except KeyError:
        raise fail(f"--separator wants one of {', '.join(_SEPARATORS)}, not {name!r}") from None


def _table_spec(
    name: str,
    log: Path | None,
    written: Sequence[tuple[str, str]],
    columns: str,
    separator: str,
    time_format: str,
    note: str,
) -> ColumnsFormatSpec:
    """Work out a table format from what the reader gave and what the log says.

    Columns given on the command line win, and are stored. Columns found in the
    log are used to guess the mapping and then *forgotten*: IIS writes different
    fields on different servers, so a saved format that froze one server's
    columns would read only that server's logs. What each case records is the
    columns that were actually in the file it read.
    """
    given = tuple(part.strip() for part in columns.split(",") if part.strip())
    found: tuple[str, ...] = ()
    if not given and log is not None:
        found, _header = declared_columns(_opening_lines(log), separator)
        if not found:
            raise fail(
                f"{log} declares no columns — no #Fields: line and no header row. "
                "Give them with --columns, or check --separator."
            )

    fields = _merge_mapping(written, guess_from_names(given or found))
    if not fields:
        raise fail("give --log or --columns to guess the mapping, or --map to write it out")

    _show_mapping(fields)
    if found:
        console.print(f"Columns come from the log: [bold]{', '.join(found)}[/bold]")
    return ColumnsFormatSpec(
        name=name,
        fields=tuple(fields),
        columns=given,
        separator=separator,
        time_format=time_format,
        description=note,
    )


@formats_app.command("add-columns")
def formats_add_columns(
    name: Annotated[str, typer.Argument(help="What to call this format.")],
    log: Annotated[
        Path | None, typer.Option("--log", help="A log to take the columns from.")
    ] = None,
    columns: Annotated[
        str, typer.Option("--columns", help="Comma-separated names, if the log declares none.")
    ] = "",
    mapping: Annotated[
        list[str] | None,
        typer.Option("--map", help="ours=theirs, repeatable. Overrides the guess."),
    ] = None,
    separator: Annotated[str, typer.Option("--separator", help="space, comma or tab.")] = "space",
    time_format: Annotated[
        str, typer.Option("--time-format", help="strftime pattern, if the time is unusual.")
    ] = "",
    note: Annotated[str, typer.Option("--note", help="A reminder of what this is for.")] = "",
    replace: Annotated[
        bool, typer.Option("--replace", help="Overwrite a saved format of the same name.")
    ] = False,
) -> None:
    """Save a format for a log laid out as a table: IIS W3C, or CSV.

    A W3C log names its columns in a `#Fields:` line and many CSVs name theirs
    in the first row, so `--log` is usually the whole configuration.
    """
    spec = _table_spec(
        name,
        log,
        _mapping_from(mapping or []),
        columns,
        _separator_from(separator),
        time_format,
        note,
    )
    try:
        # What can be judged without a file, then — when there is one — the
        # rest: that every column the mapping names is really in that log.
        spec.check()
        if log is not None:
            spec.resolved(_opening_lines(log)).build()
    except ColumnsFormatError as exc:
        raise fail(str(exc)) from exc
    _save_spec(spec, replace=replace)


def _opening_lines(log: Path) -> list[str]:
    """Enough of a log to see what it declares about itself."""
    try:
        with open_log(log) as stream:
            return [text for _, text in islice(stream, DEFAULT_SAMPLE_SIZE)]
    except LogSourceError as exc:
        raise fail(str(exc)) from exc


@formats_app.command("check-columns")
def formats_check_columns(
    log: Annotated[Path, typer.Option("--log", help="A table-shaped log to try.")],
    format_name: Annotated[
        str, typer.Option("--format", help="A saved table format, instead of guessing.")
    ] = "",
    mapping: Annotated[
        list[str] | None,
        typer.Option("--map", help="ours=theirs, repeatable. Overrides the guess."),
    ] = None,
    separator: Annotated[str, typer.Option("--separator", help="space, comma or tab.")] = "space",
    lines: Annotated[int, typer.Option("--lines", min=1, help="How many rows to read.")] = 5,
) -> None:
    """Read a table-shaped log's own column names and show what they read."""
    if format_name:
        saved = get_spec(format_name)
        if not isinstance(saved, ColumnsFormatSpec):
            raise fail(f"{format_name!r} is not a table format")
        spec: ColumnsFormatSpec = saved
        _show_mapping(spec.fields)
    else:
        spec = _table_spec(
            "check", log, _mapping_from(mapping or []), "", _separator_from(separator), "", ""
        )

    try:
        parser = spec.resolved(_opening_lines(log)).build()
    except ColumnsFormatError as exc:
        raise fail(str(exc)) from exc

    if _read_back(parser, log, lines, f"{log.name}") == 0:
        raise fail("this mapping reads nothing in that log; check the column names above")


@formats_app.command("add-pattern")
def formats_add_pattern(
    name: Annotated[str, typer.Argument(help="What to call this format.")],
    pattern: Annotated[str, typer.Argument(help="A regular expression with named groups.")],
    time_format: Annotated[
        str, typer.Option("--time-format", help="strftime pattern, if the time is unusual.")
    ] = "",
    note: Annotated[str, typer.Option("--note", help="A reminder of what this is for.")] = "",
    replace: Annotated[
        bool, typer.Option("--replace", help="Overwrite a saved format of the same name.")
    ] = False,
) -> None:
    """Save a format for a log nothing else can read.

    The named groups are the mapping: `(?P<client_ip>\\S+)` is the client
    address. A regex already names its parts, so there is nothing else to say.
    Run `logarc formats check-pattern` against the log first.
    """
    spec = PatternFormatSpec(name=name, pattern=pattern, time_format=time_format, description=note)
    try:
        spec.check()
    except PatternFormatError as exc:
        raise fail(str(exc)) from exc
    _save_spec(spec, replace=replace)


@formats_app.command("check-pattern")
def formats_check_pattern(
    pattern: Annotated[str, typer.Argument(help="The regular expression to try.")],
    log: Annotated[Path, typer.Option("--log", help="A log file to try it against.")],
    time_format: Annotated[
        str, typer.Option("--time-format", help="strftime pattern, if the time is unusual.")
    ] = "",
    lines: Annotated[int, typer.Option("--lines", min=1, help="How many lines to read.")] = 5,
) -> None:
    """Try a regular expression against a real log and show what it pulls out."""
    try:
        parser = PatternFormatSpec(name="check", pattern=pattern, time_format=time_format).build()
    except PatternFormatError as exc:
        raise fail(str(exc)) from exc

    if _read_back(parser, log, lines, f"{log.name}") == 0:
        raise fail(
            "this pattern reads nothing in that log; check the groups it names and "
            "whether the timestamp needs --time-format"
        )


@formats_app.command("remove")
def formats_remove(
    name: Annotated[str, typer.Argument(help="The saved format to remove.")],
) -> None:
    """Forget a saved log format.

    Cases already ingested with it are unaffected: each carries its own copy of
    the definition and goes on reading exactly as it did.
    """
    saved = _load_orfail()
    if name not in {spec.name for spec in saved}:
        if is_built_in(name):
            raise fail(f"{name!r} is a built-in format and cannot be removed")
        raise fail(f"no saved format named {name!r}")

    save_library([spec for spec in saved if spec.name != name])
    console.print(f"Removed [bold]{name}[/bold].")


@formats_app.command("show")
def formats_show(
    name: Annotated[str, typer.Argument(help="The format to describe.")],
) -> None:
    """Print the definition behind a format's name."""
    try:
        spec = get_spec(name)
    except UnknownFormatError as exc:
        raise fail(str(exc)) from exc
    if spec is None:
        raise fail(f"{name!r} was registered from code and has no definition to show")

    table = Table(title=f"Log format {name}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Kind", spec.kind)
    table.add_row("Source", "built-in" if is_built_in(name) else "saved")
    table.add_row("Definition", spec.summary)
    if isinstance(spec, (JsonFormatSpec, ColumnsFormatSpec, PatternFormatSpec)) and (
        spec.time_format
    ):
        table.add_row("Time format", spec.time_format)
    if isinstance(spec, ColumnsFormatSpec):
        table.add_row("Separator", _SEPARATOR_NAMES[spec.separator])
        table.add_row("Columns", ", ".join(spec.columns) if spec.columns else "from the log")
    if spec.description:
        table.add_row("Note", spec.description)
    console.print(table)


@formats_app.command("check")
def formats_check(
    directive: Annotated[str, typer.Argument(help="The LogFormat directive to try.")],
    log: Annotated[Path, typer.Option("--log", help="A log file to try it against.")],
    lines: Annotated[int, typer.Option("--lines", min=1, help="How many lines to read.")] = 5,
) -> None:
    """Try a directive against a real log and show what it pulls out.

    Writing a directive blind is guesswork, and a wrong one does not announce
    itself — it quarantines every line and presents as an empty case. This is
    the answer to that: look at the fields before saving anything.
    """
    try:
        parser = LogFormatSpec(name="check", directive=directive).build()
    except LogFormatError as exc:
        raise fail(str(exc)) from exc

    if _read_back(parser, log, lines, f"{directive}  ·  {log.name}") == 0:
        raise fail("this directive reads nothing in that log; the fields are in another order")


def _load_orfail() -> list[FormatSpec]:
    try:
        return load_library()
    except FormatLibraryError as exc:
        raise fail(str(exc)) from exc

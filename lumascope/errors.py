"""Errors a user can act on.

A reverse-engineering tool is used by people who are experts in hardware, not
necessarily in Python. A stack trace tells them nothing they can use, so every
foreseeable mistake -- missing file, wrong file type, missing dependency -- raises a
:class:`LumaScopeError` carrying an explanation and, where possible, the exact command
to run instead. :func:`lumascope.cli.main` renders these and exits non-zero; anything
*not* foreseen still raises normally, because an unexpected traceback is a bug report.
"""

from __future__ import annotations

from typing import Sequence


class LumaScopeError(Exception):
    """A user-facing error: what went wrong, why, and what to do about it."""

    def __init__(self, message: str, *, detail: str = "", commands: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail
        self.commands = list(commands)

    def render(self, prog: str = "lumascope") -> str:
        lines = [f"{prog}: {self.message}"]
        if self.detail:
            lines += ["", *(f"  {line}" for line in self.detail.splitlines())]
        if self.commands:
            lines += ["", "Try:"]
            lines += [f"  {c}" for c in self.commands]
        return "\n".join(lines)


class MissingDependency(LumaScopeError):
    """An optional extra is needed for this command."""

    def __init__(self, what: str, extra: str, *, why: str = "") -> None:
        super().__init__(
            f"{what} is not installed",
            detail=why,
            commands=[f"pip install -e \".[{extra}]\""],
        )

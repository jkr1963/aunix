"""
Builds the agent tarball that gets sent to a target machine.

Includes light source-level obfuscation:
  * Strip comments via the tokenize module (safe)
  * Strip docstrings by detecting and removing the first standalone
    string expression in module/class/function bodies (safe)
  * Collapse multi-blank-lines

This is COSMETIC obfuscation. Anyone with patience can run the script
through a deobfuscator or just trace its behavior. See SECURITY_NOTES.md
for the threat model. The real defense for stolen scanners is per-scan
agent token rotation (see scan_results.py).

Note on implementation: an earlier version used ast.parse + ast.unparse
to walk the syntax tree, but ast.unparse has a known defect where it
re-emits f-strings with mismatched quote nesting. We now operate on the
source text directly using the tokenize module, which preserves all
source bytes that don't belong to comments / docstrings.
"""

import io
import json
import re
import shutil
import tarfile
import tempfile
import token as tokmod
import tokenize
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = BASE_DIR / "agent_template"


def _strip_comments_and_docstrings(source: str) -> str:
    """
    Remove comments and standalone string-expression statements (docstrings).

    Operates on the token stream and reconstructs the source verbatim
    except for the tokens we choose to drop. This preserves f-string
    contents byte-for-byte, including their original quoting.

    A 'docstring' is detected as: a STRING token that appears as the
    first statement of a code block (module top-level, or right after
    `def`/`class`/`async def` and the opening colon and indent).
    """
    out = []

    src_io = io.StringIO(source)
    tokens = list(tokenize.generate_tokens(src_io.readline))

    # Identify which STRING tokens are docstrings to drop.
    # A docstring STRING is one whose previous non-trivial token is one of:
    #   NEWLINE INDENT (function/class body's first statement), or
    #   ENCODING NEWLINE (module level), or
    #   simply at file start.
    drop_string_indices = set()

    def _prev_non_trivial(idx):
        i = idx - 1
        while i >= 0 and tokens[i].type in (tokmod.NEWLINE, tokmod.NL,
                                            tokmod.INDENT, tokmod.ENCODING,
                                            tokmod.COMMENT):
            i -= 1
        return i

    # We track 'we are at the start of a new block (module or
    # function/class body)'. A STRING right at such a position is a docstring.
    # Method: if previous non-trivial token is INDENT/ENCODING/NEWLINE-after-:,
    # treat as block start.
    for i, tok in enumerate(tokens):
        if tok.type != tokmod.STRING:
            continue

        # The token immediately before should be NL/NEWLINE/INDENT/ENCODING
        # (i.e. not part of an expression).
        # Walk back through layout-only tokens.
        j = i - 1
        while j >= 0 and tokens[j].type in (tokmod.NL, tokmod.COMMENT):
            j -= 1
        if j < 0:
            # First real token in file - module docstring
            drop_string_indices.add(i)
            continue

        prev = tokens[j]
        if prev.type == tokmod.ENCODING:
            drop_string_indices.add(i)
            continue
        if prev.type == tokmod.INDENT:
            # First statement of a function/class body
            drop_string_indices.add(i)
            continue
        if prev.type == tokmod.NEWLINE:
            # Could be a top-level docstring (after module-start blank lines)
            # or a regular string statement. Check what's before that NEWLINE.
            k = j - 1
            while k >= 0 and tokens[k].type in (tokmod.NL, tokmod.COMMENT):
                k -= 1
            if k < 0:
                drop_string_indices.add(i)
                continue
            if tokens[k].type == tokmod.ENCODING:
                drop_string_indices.add(i)
                continue
            # Otherwise it's a string mid-program (assignment, expression, etc.)
            # Don't drop.

    # Reconstruct the source, dropping comments + identified docstring strings
    # + the NEWLINE/NL that follows a dropped docstring (so we don't leave a
    # stray blank line where the docstring was).
    skip_next_newline = False
    out_chunks = []
    last_lineno = 1
    last_col = 0

    # Walk tokens with positional info to preserve whitespace.
    for i, tok in enumerate(tokens):
        if tok.type == tokmod.ENCODING:
            continue
        if tok.type == tokmod.COMMENT:
            continue
        if tok.type == tokmod.STRING and i in drop_string_indices:
            skip_next_newline = True
            continue
        if skip_next_newline and tok.type in (tokmod.NEWLINE, tokmod.NL):
            skip_next_newline = False
            continue
        skip_next_newline = False

        # Pad whitespace to match original positioning
        start_row, start_col = tok.start
        if start_row > last_lineno:
            out_chunks.append("\n" * (start_row - last_lineno))
            last_col = 0
        if start_col > last_col:
            out_chunks.append(" " * (start_col - last_col))

        out_chunks.append(tok.string)

        end_row, end_col = tok.end
        last_lineno = end_row
        last_col = end_col

    result = "".join(out_chunks)
    return result


def _collapse_blank_lines(source: str) -> str:
    """Collapse runs of blank lines down to one."""
    out = []
    blank_run = 0
    for line in source.splitlines():
        if line.strip() == "":
            blank_run += 1
            if blank_run <= 1:
                out.append(line)
        else:
            blank_run = 0
            out.append(line)
    return "\n".join(out) + "\n"


def obfuscate_python(source: str) -> str:
    """Apply light obfuscation: strip docstrings, comments, blank lines."""
    try:
        stripped = _strip_comments_and_docstrings(source)
        compact = _collapse_blank_lines(stripped)

        # Verify the result is still parseable. If not, fall back to source.
        compile(compact, "<obfuscated>", "exec")

        # Tag the file so future maintainers know what they're looking at.
        header = (
            "#!/usr/bin/env python3\n"
            "# AUNIX agent (obfuscated build).\n"
        )
        # Drop any existing shebang from the compacted version since we add ours.
        if compact.startswith("#!"):
            first_nl = compact.find("\n")
            if first_nl != -1:
                compact = compact[first_nl + 1:]
        return header + compact
    except Exception:
        # If anything goes wrong, ship the unobfuscated source. Better to
        # have a working agent than break the download flow.
        return source


def build_agent_tarball(target_id: int, agent_token: str, api_url: str) -> Path:
    """
    Returns a path to a .tar.gz containing the agent code, lightly
    obfuscated, with a baked-in config.json.
    """
    if not TEMPLATE_DIR.exists():
        raise RuntimeError(f"Agent template directory missing: {TEMPLATE_DIR}")

    work_dir = Path(tempfile.mkdtemp(prefix="aunix_agent_"))
    pkg_name = f"aunix-agent-{target_id}"
    pkg_dir = work_dir / pkg_name
    pkg_dir.mkdir()

    # ---- Obfuscate aunix_scan.py ----
    raw_src = (TEMPLATE_DIR / "aunix_scan.py").read_text(encoding="utf-8")
    obf_src = obfuscate_python(raw_src)
    (pkg_dir / "aunix_scan.py").write_text(obf_src, encoding="utf-8")

    # ---- Copy run.sh and README as-is ----
    for fname in ("run.sh", "README.txt"):
        src = TEMPLATE_DIR / fname
        if src.exists():
            shutil.copy(src, pkg_dir / fname)

    # Make scripts executable
    (pkg_dir / "run.sh").chmod(0o755)
    (pkg_dir / "aunix_scan.py").chmod(0o755)

    # Bake per-target config
    config = {
        "target_id": target_id,
        "agent_token": agent_token,
        "api_url": api_url.rstrip("/"),
    }
    (pkg_dir / "config.json").write_text(
        json.dumps(config, indent=2), encoding="utf-8"
    )
    (pkg_dir / "config.json").chmod(0o600)

    tarball_path = work_dir / f"{pkg_name}.tar.gz"
    with tarfile.open(tarball_path, "w:gz") as tar:
        tar.add(pkg_dir, arcname=pkg_name)

    return tarball_path

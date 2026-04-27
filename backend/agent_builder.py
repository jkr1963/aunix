"""
Builds the agent tarball that gets sent to a target machine.

Includes light source-level obfuscation:
  * Strip module / function / class docstrings
  * Strip comments
  * Collapse multi-blank-lines

This is COSMETIC obfuscation. Anyone with patience can run the script
through a deobfuscator or just trace its behavior. See SECURITY_NOTES.md
for the threat model. The real defense for stolen scanners is per-scan
agent token rotation (see scan_results.py).
"""

import ast
import io
import json
import shutil
import tarfile
import tempfile
import tokenize
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = BASE_DIR / "agent_template"


def _strip_comments(source: str) -> str:
    """Remove all # comments using the tokenize module."""
    out = []
    last_lineno = -1
    last_col = 0
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    for tok_type, tok_string, (start_row, start_col), (end_row, end_col), _ in tokens:
        if tok_type == tokenize.COMMENT:
            continue
        if start_row > last_lineno:
            last_col = 0
        if start_col > last_col:
            out.append(" " * (start_col - last_col))
        out.append(tok_string)
        last_col = end_col
        last_lineno = end_row
    return "".join(out)


def _strip_docstrings(source: str) -> str:
    """Remove module, class, and function docstrings."""
    tree = ast.parse(source)

    def _strip(node):
        if not isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if (node.body and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)):
            # If the function/class would become empty, replace with `pass`
            if len(node.body) == 1:
                node.body[0] = ast.Pass()
            else:
                node.body.pop(0)

    _strip(tree)
    for node in ast.walk(tree):
        _strip(node)

    return ast.unparse(tree)


def _collapse_blank_lines(source: str) -> str:
    """Collapse runs of blank lines down to one."""
    lines = source.splitlines()
    out = []
    blank_run = 0
    for line in lines:
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
        no_docstrings = _strip_docstrings(source)
        no_comments = _strip_comments(no_docstrings)
        compact = _collapse_blank_lines(no_comments)
        # Tag the file so future maintainers know what they're looking at.
        header = (
            "#!/usr/bin/env python3\n"
            "# AUNIX agent (obfuscated build).\n"
            "# Source available at the AUNIX repository.\n"
        )
        return header + compact
    except Exception:
        # If obfuscation fails for any reason, fall back to the raw source.
        # Better to ship a working agent than break the download flow.
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

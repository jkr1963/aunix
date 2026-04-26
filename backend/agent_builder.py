import json
import shutil
import tarfile
import tempfile
from pathlib import Path

# Source files for the agent live alongside the backend code, in agent_template/.
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = BASE_DIR / "agent_template"


def build_agent_tarball(target_id: int, agent_token: str, api_url: str) -> Path:
    """
    Returns a path to a .tar.gz containing the agent code and a baked-in
    config.json. The path lives in a per-call temp directory so it's safe
    to send via FastAPI's FileResponse.
    """
    if not TEMPLATE_DIR.exists():
        raise RuntimeError(f"Agent template directory missing: {TEMPLATE_DIR}")

    work_dir = Path(tempfile.mkdtemp(prefix="aunix_agent_"))
    pkg_name = f"aunix-agent-{target_id}"
    pkg_dir = work_dir / pkg_name
    pkg_dir.mkdir()

    # Copy templated files in
    for fname in ("aunix_scan.py", "run.sh", "README.txt"):
        src = TEMPLATE_DIR / fname
        if not src.exists():
            raise RuntimeError(f"Missing template file: {src}")
        shutil.copy(src, pkg_dir / fname)

    # Make run.sh executable inside the tarball
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

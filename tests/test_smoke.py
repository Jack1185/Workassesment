import subprocess
import sys
from pathlib import Path

def test_runs_and_exits_zero():
    root = Path(__file__).resolve().parents[1]
    log = root / "sample_security.log"
    script = root / "secscan.py"
    assert log.exists(), "sample_security.log not found"
    out = subprocess.run([sys.executable, str(script), str(log), "--quiet"], capture_output=True, text=True)
    assert out.returncode == 0

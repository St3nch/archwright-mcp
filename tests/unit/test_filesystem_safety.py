from pathlib import Path


def test_filesystem_module_contains_root_owned_promotion():
    text = Path("src/archwright_mcp/tools/filesystem.py").read_text()
    assert "/run/archwright/files/" in text
    assert "Root-owned promoted file hash mismatch" in text


def test_durable_jobs_are_not_auto_collected():
    text = Path("src/archwright_mcp/tools/execution.py").read_text()
    assert "--collect" not in text


def test_run_script_avoids_python_wrapper_and_auto_collect():
    text = Path("src/archwright_mcp/tools/execution.py").read_text()
    assert "base64 -d" in text
    assert "subprocess.call" not in text
    assert "--collect" not in text

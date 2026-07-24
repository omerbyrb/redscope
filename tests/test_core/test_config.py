import json
import tempfile
from pathlib import Path

from core.config import _deep_merge, load_config, save_config


def test_load_default_config():
    cfg = load_config(Path("/nonexistent/path.json"))
    assert "general" in cfg
    assert cfg["general"]["threads"] == 10
    assert cfg["general"]["timeout"] == 10


def test_deep_merge():
    base = {"a": {"x": 1, "y": 2}, "b": 3}
    override = {"a": {"y": 99, "z": 0}, "c": 4}
    result = _deep_merge(base, override)
    assert result["a"]["x"] == 1
    assert result["a"]["y"] == 99
    assert result["a"]["z"] == 0
    assert result["b"] == 3
    assert result["c"] == 4


def test_save_and_load_config():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "config.json"
        cfg = load_config()
        cfg["general"]["threads"] = 42
        save_config(cfg, path)
        loaded = load_config(path)
        assert loaded["general"]["threads"] == 42


def test_user_config_overrides_defaults():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "config.json"
        path.write_text(json.dumps({"general": {"timeout": 99}}))
        cfg = load_config(path)
        assert cfg["general"]["timeout"] == 99
        assert cfg["general"]["threads"] == 10  # default preserved

from pathlib import Path

from exposeye import settings


def _home(monkeypatch, tmp_path):
    monkeypatch.delenv("EXPOSEYE_HOME", raising=False)
    monkeypatch.delenv("DOMAINSCOPE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)


def test_legacy_data_folder_is_moved(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    legacy = tmp_path / ".domainscope" / "scans"
    legacy.mkdir(parents=True)
    (legacy / "20260101-000000-aaaaaa.json").write_text("{}")
    d = settings.data_dir()
    assert d == tmp_path / ".exposeye"
    assert (d / "scans" / "20260101-000000-aaaaaa.json").exists()
    assert not (tmp_path / ".domainscope").exists()


def test_fresh_install_uses_new_folder(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    assert settings.data_dir() == tmp_path / ".exposeye"


def test_env_overrides(monkeypatch, tmp_path):
    _home(monkeypatch, tmp_path)
    monkeypatch.setenv("DOMAINSCOPE_HOME", str(tmp_path / "old"))
    assert settings.data_dir() == tmp_path / "old"  # old variable still honoured
    monkeypatch.setenv("EXPOSEYE_HOME", str(tmp_path / "new"))
    assert settings.data_dir() == tmp_path / "new"

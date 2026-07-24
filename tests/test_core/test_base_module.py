from core.base_module import Finding, ScanResult, BaseModule
from core.config import load_config


class DummyModule(BaseModule):
    name = "dummy"
    description = "test module"

    def run(self, target: str, **kwargs) -> ScanResult:
        result = ScanResult(module=self.name, target=target)
        result.add_finding(Finding(
            title="Test Finding",
            severity="high",
            description="A test finding",
        ))
        return result


def _cfg():
    return load_config()


def test_finding_to_dict():
    f = Finding(title="XSS", severity="high", description="reflected xss", cvss=7.2, cve="CVE-2023-1234")
    d = f.to_dict()
    assert d["title"] == "XSS"
    assert d["severity"] == "high"
    assert d["cvss"] == 7.2
    assert d["cve"] == "CVE-2023-1234"
    assert "timestamp" in d


def test_scan_result_add_finding():
    result = ScanResult(module="test", target="example.com")
    assert len(result.findings) == 0
    result.add_finding(Finding(title="A", severity="low", description="b"))
    assert len(result.findings) == 1


def test_scan_result_add_error():
    result = ScanResult(module="test", target="example.com")
    result.add_error("connection refused")
    assert "connection refused" in result.errors


def test_scan_result_finish():
    result = ScanResult(module="test", target="example.com")
    assert result.finished_at is None
    result.finish()
    assert result.finished_at is not None


def test_scan_result_to_dict():
    result = ScanResult(module="dns", target="example.com")
    result.add_finding(Finding(title="SPF", severity="medium", description="no SPF"))
    d = result.to_dict()
    assert d["module"] == "dns"
    assert d["target"] == "example.com"
    assert len(d["findings"]) == 1


def test_dummy_module_run():
    mod = DummyModule(_cfg())
    result = mod.run("example.com")
    assert result.module == "dummy"
    assert len(result.findings) == 1
    assert result.findings[0].severity == "high"


def test_validate_target():
    mod = DummyModule(_cfg())
    assert mod.validate_target("example.com") is True
    assert mod.validate_target("") is False
    assert mod.validate_target("   ") is False


def test_repr():
    mod = DummyModule(_cfg())
    assert "dummy" in repr(mod)

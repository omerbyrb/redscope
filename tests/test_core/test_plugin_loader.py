import pkgutil

import pytest

import redscope.modules
from redscope.core.base_module import BaseModule
from redscope.core.config import load_config
from redscope.core.plugin_loader import list_modules, load_module, module_category


def _module_files():
    """Every module file shipped under redscope/modules/<category>/."""
    found = set()
    for category in pkgutil.iter_modules(redscope.modules.__path__):
        package = __import__(f"redscope.modules.{category.name}", fromlist=["_"])
        for mod in pkgutil.iter_modules(package.__path__):
            found.add(f"redscope.modules.{category.name}.{mod.name}")
    return found


def test_every_module_file_is_registered():
    # Compare by the loaded class's module path: report modules use short names
    # (htmlreport -> report/html.py), so names alone would not match file names.
    loaded_paths = {type(load_module(n, load_config())).__module__ for n in list_modules()}

    assert loaded_paths == _module_files()


@pytest.mark.parametrize("name", list_modules())
def test_registered_module_loads_with_matching_name(name):
    module = load_module(name, load_config())

    assert isinstance(module, BaseModule)
    assert module.name == name


@pytest.mark.parametrize("name", ["ssltls", "emailsec", "cvelookup", "osfingerprint"])
def test_modules_previously_missing_from_registry_now_load(name):
    assert load_module(name, load_config()) is not None


def test_module_category_comes_from_package_path():
    assert module_category("ssltls") == "network"
    assert module_category("emailsec") == "recon"
    assert module_category("headers") == "web"
    assert module_category("htmlreport") == "report"


def test_unknown_module_returns_none():
    assert load_module("does-not-exist", load_config()) is None

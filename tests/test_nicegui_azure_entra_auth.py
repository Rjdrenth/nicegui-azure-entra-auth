from nicegui_azure_entra_auth import __version__


def test_version():
    assert __version__ == "0.1.0"


if __name__ == "__main__":
    from pathlib import Path

    import pytest

    pytest.main([Path(__file__).name])

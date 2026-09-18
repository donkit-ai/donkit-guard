import donkit_guard


def test_package_exposes_version() -> None:
    assert isinstance(donkit_guard.__version__, str)
    assert donkit_guard.__version__

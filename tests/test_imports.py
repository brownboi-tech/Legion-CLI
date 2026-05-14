def test_core_imports():
    import core.scope  # noqa: F401
    import core.tools  # noqa: F401
    import core.report  # noqa: F401


def test_module_imports():
    import modules.recon  # noqa: F401
    import modules.traffic_import  # noqa: F401
    import modules.js_analyzer  # noqa: F401
    import modules.idor  # noqa: F401
    import modules.oauth  # noqa: F401

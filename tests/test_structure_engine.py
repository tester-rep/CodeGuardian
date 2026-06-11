"""Focused tests for AST-backed structure extraction."""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.structure_engine import StructureEngine


async def test_structure_engine_extracts_python_entities() -> None:
    source = '''
class Greeter:
    default_name = "world"

    def hello(self, name, punctuation="!"):
        return f"Hello, {name}{punctuation}"

    async def async_hello(self, name):
        return name


def top_level(value, enabled=True):
    if enabled:
        return value
    return None
'''

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src = root / "sample.py"
        src.write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await StructureEngine().analyze(ctx)

        assert len(result.files) == 1
        assert [module.name for module in result.modules] == ["sample"]
        assert [cls.name for cls in result.classes] == ["Greeter"]

        function_names = sorted(func.name for func in result.functions)
        assert function_names == ["async_hello", "hello", "top_level"]

        hello = next(func for func in result.functions if func.name == "hello")
        assert hello.is_method is True
        assert hello.class_or_module == "Greeter"
        assert hello.param_count == 3

        top_level = next(func for func in result.functions if func.name == "top_level")
        assert top_level.is_method is False
        assert top_level.class_or_module == "sample"
        assert top_level.param_count == 2

        greeter = result.classes[0]
        assert greeter.methods == ["hello", "async_hello"]
        assert greeter.fields == ["default_name"]

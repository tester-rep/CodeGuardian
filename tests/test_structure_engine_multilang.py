"""Focused tests for tree-sitter-backed multi-language structure extraction."""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.structure_engine import StructureEngine


async def test_structure_engine_extracts_multilanguage_entities() -> None:
    java_source = """
class AccountService {
    private String prefix = "hi";

    void handle(String name) {
        System.out.println(name);
    }
}
"""
    js_source = """
class Widget {
  render(name) {
    return name;
  }
}

function mount(root, enabled) {
  if (enabled && root) {
    console.log(root);
  }
}

const pick = (value) => value;
"""
    ts_source = """
interface Service {
  run(value: string): void;
}

class ServiceImpl {
  run(value: string) {
    return value;
  }
}

function build(id: string, enabled: boolean) {
  return enabled ? id : "";
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "AccountService.java").write_text(java_source.strip() + "\n", encoding="utf-8")
        (root / "widget.js").write_text(js_source.strip() + "\n", encoding="utf-8")
        (root / "service.ts").write_text(ts_source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await StructureEngine().analyze(ctx)

        class_names = {item.name for item in result.classes}
        assert {"AccountService", "Widget", "Service", "ServiceImpl"}.issubset(class_names)

        function_names = {item.name for item in result.functions}
        assert {"handle", "mount", "pick", "build", "run"}.issubset(function_names)

        java_class = next(item for item in result.classes if item.name == "AccountService")
        assert java_class.methods == ["handle"]
        assert java_class.fields == ["prefix"]


async def test_structure_engine_extracts_priority_language_entities_via_heuristics() -> None:
    cpp_source = """
class Engine {
public:
  void run(int value, bool enabled) {
    if (enabled) {
      return;
    }
  }
};
"""
    go_source = """
type Service struct {}

func (s *Service) Run(name string, enabled bool) {
  if enabled {
    return
  }
}
"""
    csharp_source = """
class AccountService {
  public void Run(string name, bool enabled) {
    if (enabled) {
      return;
    }
  }
}
"""
    lua_source = """
local function compute(value, enabled)
  if enabled then
    return value
  end
  return nil
end
"""
    rust_source = """
pub struct Worker {
  level: i32,
}

impl Worker {
  pub fn run(&self, enabled: bool) {
    if enabled {
      return;
    }
  }
}
"""

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "engine.cpp").write_text(cpp_source.strip() + "\n", encoding="utf-8")
        (root / "service.go").write_text(go_source.strip() + "\n", encoding="utf-8")
        (root / "AccountService.cs").write_text(csharp_source.strip() + "\n", encoding="utf-8")
        (root / "script.lua").write_text(lua_source.strip() + "\n", encoding="utf-8")
        (root / "worker.rs").write_text(rust_source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await StructureEngine().analyze(ctx)

    class_names = {item.name for item in result.classes}
    assert {"Engine", "Service", "AccountService", "Worker"}.issubset(class_names)

    function_names = {item.name for item in result.functions}
    assert {"run", "Run", "compute"}.issubset(function_names)


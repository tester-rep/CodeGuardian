"""Tests for ComplexityEngine tree-sitter precision improvements for Go and C++."""

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.config.loader import load_app_config
from codeguardian.core.context import ScanContext
from codeguardian.engines.complexity_engine import ComplexityEngine
from codeguardian.models.metric import MetricNames
from codeguardian.parsers.factory import get_parser


# ═══════════════════════════════════════════════════════════════════════
# Parser-level tests: verify tree-sitter extracts functions precisely
# ═══════════════════════════════════════════════════════════════════════


def test_go_parser_extracts_functions() -> None:
    """Go parser should extract top-level functions and methods with correct param counts."""
    source = """
package main

import "fmt"

type Server struct {
    Host string
    Port int
}

func NewServer(host string, port int) *Server {
    return &Server{Host: host, Port: port}
}

func (s *Server) Start() error {
    fmt.Println("starting", s.Host, s.Port)
    return nil
}

func (s *Server) HandleRequest(method string, path string, body []byte) error {
    return nil
}

func helper() {
    fmt.Println("helper")
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src = root / "server.go"
        src.write_text(source.strip() + "\n", encoding="utf-8")

        parser = get_parser("go")
        assert parser is not None

        result = parser.parse_file(src, root)

    func_names = {f.name for f in result.functions}
    assert "NewServer" in func_names
    assert "Start" in func_names
    assert "HandleRequest" in func_names
    assert "helper" in func_names

    # Check param counts
    new_server = next(f for f in result.functions if f.name == "NewServer")
    assert new_server.param_count == 2

    start = next(f for f in result.functions if f.name == "Start")
    assert start.is_method
    assert start.class_or_module == "Server"

    handle = next(f for f in result.functions if f.name == "HandleRequest")
    assert handle.param_count == 3
    assert handle.is_method

    helper = next(f for f in result.functions if f.name == "helper")
    assert not helper.is_method


def test_go_parser_extracts_struct_and_interface() -> None:
    source = """
package main

type Reader interface {
    Read(p []byte) (int, error)
    Close() error
}

type MyStruct struct {
    Name string
    Age  int
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src = root / "types.go"
        src.write_text(source.strip() + "\n", encoding="utf-8")

        parser = get_parser("go")
        result = parser.parse_file(src, root)

    class_names = {c.name for c in result.classes}
    assert "Reader" in class_names
    assert "MyStruct" in class_names

    reader = next(c for c in result.classes if c.name == "Reader")
    assert reader.kind == "interface"

    my_struct = next(c for c in result.classes if c.name == "MyStruct")
    assert my_struct.kind == "struct"
    assert "Name" in my_struct.fields
    assert "Age" in my_struct.fields


def test_cpp_parser_extracts_functions() -> None:
    """C++ parser should extract free functions and class methods."""
    source = """
#include <string>
#include <vector>

class Calculator {
public:
    int add(int a, int b) {
        return a + b;
    }

    double multiply(double x, double y) {
        return x * y;
    }
};

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

void processItems(std::vector<int> items, int count, bool reverse) {
    for (auto& item : items) {
        item *= count;
    }
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src = root / "calc.cpp"
        src.write_text(source.strip() + "\n", encoding="utf-8")

        parser = get_parser("cpp")
        assert parser is not None

        result = parser.parse_file(src, root)

    func_names = {f.name for f in result.functions}
    assert "add" in func_names
    assert "multiply" in func_names
    assert "factorial" in func_names
    assert "processItems" in func_names

    # Check param counts
    factorial = next(f for f in result.functions if f.name == "factorial")
    assert factorial.param_count == 1
    assert not factorial.is_method

    process = next(f for f in result.functions if f.name == "processItems")
    assert process.param_count == 3

    add = next(f for f in result.functions if f.name == "add")
    assert add.is_method
    assert add.param_count == 2


def test_cpp_parser_extracts_class_structure() -> None:
    source = """
class Shape {
public:
    int width;
    int height;
    int area() { return width * height; }
    void resize(int w, int h) { width = w; height = h; }
};

struct Point {
    double x;
    double y;
};
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src = root / "shapes.cpp"
        src.write_text(source.strip() + "\n", encoding="utf-8")

        parser = get_parser("cpp")
        result = parser.parse_file(src, root)

    class_names = {c.name for c in result.classes}
    assert "Shape" in class_names
    assert "Point" in class_names

    shape = next(c for c in result.classes if c.name == "Shape")
    assert shape.kind == "class"

    point = next(c for c in result.classes if c.name == "Point")
    assert point.kind == "struct"


# ═══════════════════════════════════════════════════════════════════════
# Engine-level tests: verify ComplexityEngine produces findings for Go/C++
# ═══════════════════════════════════════════════════════════════════════


async def test_complexity_engine_go_function_metrics() -> None:
    """ComplexityEngine should produce function-level metrics for Go files."""
    source = """
package main

import "fmt"

func complexHandler(a, b, c, d, e, f, g int) int {
    result := 0
    if a > 0 {
        for i := 0; i < b; i++ {
            if c > 0 {
                switch d {
                case 1:
                    if e > 0 {
                        if f > 0 {
                            result += g
                        } else {
                            result -= g
                        }
                    }
                case 2:
                    result += 10
                case 3:
                    result -= 10
                }
            } else if d > 0 {
                result += 5
            } else {
                result -= 5
            }
        }
    } else if b > 0 {
        for j := 0; j < c; j++ {
            if d > 0 && e > 0 {
                result += j
            } else if f > 0 || g > 0 {
                result -= j
            }
        }
    } else if c > 0 {
        if d > 0 {
            if e > 0 {
                result = 100
            } else {
                result = 200
            }
        }
    } else {
        for k := 0; k < d; k++ {
            if a > 0 || b > 0 {
                result += k
            } else if c > 0 || d > 0 {
                result -= k
            } else {
                result = k
            }
        }
    }
    if g > 0 {
        result = -result
    }
    return result
}

func simple(x int) int {
    return x * 2
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src = root / "handler.go"
        src.write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await ComplexityEngine().analyze(ctx)

    # Should have function-level metrics
    function_metrics = [m for m in result.metrics if m.target_type == "function"]
    assert len(function_metrics) >= 4  # at least CC, cognitive, nesting, params for 2 funcs

    # complexHandler should have findings
    assert len(result.findings) >= 1
    cc_finding = next((f for f in result.findings if f.rule_id == "HIGH-CC-FUNCTION"), None)
    assert cc_finding is not None

    # Project-level metrics should exist
    project_metrics = {m.metric_name: m for m in result.metrics if m.target_id == "project"}
    assert MetricNames.CYCLOMATIC_COMPLEXITY in project_metrics
    assert MetricNames.PARAM_COUNT in project_metrics
    assert project_metrics[MetricNames.PARAM_COUNT].value >= 7  # complexHandler has 7 params


async def test_complexity_engine_cpp_function_metrics() -> None:
    """ComplexityEngine should produce function-level metrics for C++ files."""
    source = """
#include <vector>
#include <string>

class Processor {
public:
    int process(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j) {
        int result = 0;
        if (a > 0) {
            for (int k = 0; k < b; k++) {
                if (c > 0) {
                    while (d > 0) {
                        if (e > 0) {
                            if (f > 0) {
                                result += g;
                            } else {
                                result -= g;
                            }
                        } else if (h > 0) {
                            result += 10;
                        } else {
                            result -= 10;
                        }
                        d--;
                    }
                } else if (i > 0) {
                    result += 5;
                }
            }
        } else if (b > 0) {
            for (int m = 0; m < c; m++) {
                if (d > 0 && e > 0) {
                    result += m;
                } else if (f > 0 || g > 0) {
                    result -= m;
                }
            }
        } else if (c > 0) {
            if (d > 0) {
                if (e > 0) {
                    result = 100;
                } else {
                    result = 200;
                }
            }
        } else {
            for (int n = 0; n < d; n++) {
                if (a > 0 || b > 0) {
                    result += n;
                } else if (c > 0 || d > 0) {
                    result -= n;
                } else {
                    result = n;
                }
            }
        }
        if (j > 0) {
            result = -result;
        }
        return result;
    }
};

int simpleAdd(int x, int y) {
    return x + y;
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src = root / "processor.cpp"
        src.write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await ComplexityEngine().analyze(ctx)

    # Should have function-level metrics for both functions
    function_metrics = [m for m in result.metrics if m.target_type == "function"]
    assert len(function_metrics) >= 4  # At least CC, cognitive, nesting, params for process + simpleAdd

    # process should trigger complexity findings
    assert len(result.findings) >= 1

    # Project-level param count should reflect the 10-param function
    project_metrics = {m.metric_name: m for m in result.metrics if m.target_id == "project"}
    assert MetricNames.PARAM_COUNT in project_metrics
    assert project_metrics[MetricNames.PARAM_COUNT].value >= 10


async def test_complexity_engine_go_simple_no_findings() -> None:
    """Simple Go functions should not trigger complexity findings."""
    source = """
package main

func add(a, b int) int {
    return a + b
}

func greet(name string) string {
    return "Hello, " + name
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src = root / "simple.go"
        src.write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await ComplexityEngine().analyze(ctx)

    assert result.findings == []

    # But should still have metrics
    function_metrics = [m for m in result.metrics if m.target_type == "function"]
    assert len(function_metrics) >= 4  # Two functions * 4 metrics each (CC, cognitive, nesting, params)


async def test_complexity_engine_cpp_simple_no_findings() -> None:
    """Simple C++ functions should not trigger complexity findings."""
    source = """
int add(int a, int b) {
    return a + b;
}

double divide(double a, double b) {
    if (b == 0) return 0;
    return a / b;
}
"""
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        src = root / "simple.cpp"
        src.write_text(source.strip() + "\n", encoding="utf-8")

        ctx = ScanContext(project_root=str(root), config=load_app_config(None))
        result = await ComplexityEngine().analyze(ctx)

    assert result.findings == []
    function_metrics = [m for m in result.metrics if m.target_type == "function"]
    assert len(function_metrics) >= 4

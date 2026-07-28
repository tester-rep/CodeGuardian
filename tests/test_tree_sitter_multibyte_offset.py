"""Regression tests for tree-sitter byte-offset vs. char-offset extraction.

Root cause history: ``TreeSitterDocument.text_for`` sliced the decoded ``str``
source with tree-sitter BYTE offsets. Any non-ASCII (multi-byte UTF-8) character
before a node — e.g. a Chinese comment, extremely common in real projects —
shifted every subsequent symbol name/type extraction, producing garbage names
like ``g(String deta(`` for ``generateOkMsg`` and ``xtends Bas`` for the class.
That corruption fed several cross-function rules (BIZ-NO-TRANSACTION-BOUNDARY,
RESOURCE-NEVER-CLOSED-XFUNC), causing false positives.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from codeguardian.parsers.tree_sitter_parser import TreeSitterSourceParser
from codeguardian.parsers.tree_sitter_support import clear_parse_cache


JAVA_WITH_CHINESE_COMMENT = """\
package com.example.base;

/**
 * 响应消息基类
 * @author someone
 */
public class BaseMsgRes extends BaseMsg {
    private String infor;
    private String detail;

    public void setInfor(String infor) {
        this.infor = infor;
    }

    public void generateOkMsg(String detail) {
        this.setInfor("ok");
        this.setDetail(detail);
    }

    public void generateErrorMsg(String detail) {
        this.setInfor("error");
        this.setDetail(detail);
    }
}
"""


def _parse_java(source: str):
    clear_parse_cache()
    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        f = root / "BaseMsgRes.java"
        f.write_text(source, encoding="utf-8")
        return TreeSitterSourceParser("java").parse_file(f, root)


def test_java_symbol_names_intact_after_multibyte_comment() -> None:
    """Function/class names must be exact even when a multi-byte comment precedes them."""
    structure = _parse_java(JAVA_WITH_CHINESE_COMMENT)

    func_names = {fn.name for fn in structure.functions}
    assert func_names == {"setInfor", "generateOkMsg", "generateErrorMsg"}, func_names

    # Owners (class names via class_stack) must not be corrupted into "xtends Bas".
    owners = {fn.class_or_module for fn in structure.functions}
    assert owners == {"BaseMsgRes"}, owners

    assert [c.name for c in structure.classes] == ["BaseMsgRes"]


def test_java_symbol_names_intact_without_multibyte() -> None:
    """Control: ASCII-only source must extract identical names (no regression)."""
    ascii_source = JAVA_WITH_CHINESE_COMMENT.replace("响应消息基类", "Response message base")
    structure = _parse_java(ascii_source)

    func_names = {fn.name for fn in structure.functions}
    assert func_names == {"setInfor", "generateOkMsg", "generateErrorMsg"}, func_names
    assert {fn.class_or_module for fn in structure.functions} == {"BaseMsgRes"}

"""Tests for tool definitions — structure, completeness, schema validity."""

from __future__ import annotations

import json

from src.agent.tools import ALL_TOOLS


def test_all_tools_is_list():
    assert isinstance(ALL_TOOLS, list)
    assert len(ALL_TOOLS) >= 46  # H1 (34) + H3 Git/Code (11) + mobile (1)


def test_tool_structure():
    """Every tool must have type=function and a function with name, description, parameters."""
    for tool in ALL_TOOLS:
        assert tool["type"] == "function", f"tool missing type=function: {tool}"
        fn = tool["function"]
        assert "name" in fn, f"tool missing name: {fn}"
        assert "description" in fn, f"tool {fn.get('name')} missing description"
        assert "parameters" in fn, f"tool {fn['name']} missing parameters"
        params = fn["parameters"]
        assert params.get("type") == "object", f"tool {fn['name']} params not object"
        assert "properties" in params, f"tool {fn['name']} missing properties"


def test_unique_tool_names():
    """No duplicate tool names."""
    names = [t["function"]["name"] for t in ALL_TOOLS]
    assert len(names) == len(set(names)), f"Duplicate tools: {[n for n in names if names.count(n) > 1]}"


def test_required_fields_subset_of_properties():
    """required fields must exist in properties."""
    for tool in ALL_TOOLS:
        fn = tool["function"]
        params = fn["parameters"]
        props = set(params.get("properties", {}).keys())
        required = set(params.get("required", []))
        missing = required - props
        assert not missing, f"tool {fn['name']}: required fields {missing} not in properties"


def test_specific_tools_exist():
    """Key tools from each phase must be present."""
    names = {t["function"]["name"] for t in ALL_TOOLS}
    # H1 core
    assert "create_pentest_session" in names
    assert "run_recon" in names
    # H2 additions
    assert "run_injection_tests" in names
    assert "build_report" in names
    # H3 additions
    assert "git_clone_repo" in names
    assert "run_code_audit" in names
    assert "analyze_mobile_traffic" in names
    assert "summarize_risks" in names


def test_tools_json_serializable():
    """ALL_TOOLS must be JSON serializable (sent to LLM)."""
    s = json.dumps(ALL_TOOLS)
    assert len(s) > 100

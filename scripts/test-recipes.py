#!/usr/bin/env python3
"""Offline contract checks for the recipe catalogue.

These checks validate the user-facing contract and do not contact AWS or run a
live provider. Full recipe execution belongs to the normal fake gallery gate.
"""
from __future__ import annotations

import importlib.util
import tempfile
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recipe_index", ROOT / "scripts" / "recipe-index.py")
assert spec and spec.loader
recipe_index = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = recipe_index
spec.loader.exec_module(recipe_index)
CATEGORIES, RECIPES, example_link, recipes = recipe_index.CATEGORIES, recipe_index.RECIPES, recipe_index.example_link, recipe_index.recipes


def main() -> int:
    items = recipes()
    assert RECIPES.exists(), "recipes/ directory is required"
    assert (ROOT / "recipes" / "README.md").exists(), "run recipe-index.py first"
    assert len(items) == len(list(RECIPES.glob("*.lms")))
    text = (ROOT / "recipes" / "README.md").read_text(encoding="utf-8")
    assert "| File | What it does | Access | Arguments | Typical cost |" in text
    for item in items:
        source = (ROOT / item.path).read_text(encoding="utf-8")
        assert not re.search(r"\baws\s+(?:s3|ec2|sts|ce|dynamodb|lambda)\b", source, re.I), item.path
        assert 'import "' not in source or Path(item.meta["library"]).name in source, item.path
        for field in ("access", "what", "when", "run", "preview", "arguments", "typical-cost", "example", "function", "library"):
            assert item.meta[field], (item.path, field)
        assert (item.meta["run"].startswith("lmctl ") or " lmctl " in item.meta["run"]) and ".lms" in item.meta["run"]
        assert item.meta["preview"].startswith("lmctl ") and "dry-run" in item.meta["preview"]
        image_caption, caption, example = example_link(item)
        image_path = ROOT / "docs" / "images" / f"{example}.png"
        assert image_path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"), image_path
        assert caption.startswith("lmctl https://raw.githubusercontent.com/") and caption.endswith(f"/{example}.lms")
        assert "see source" not in caption.lower()
    generated=subprocess.run([sys.executable,str(ROOT/"scripts/generate-recipes.py"),"--check"],cwd=ROOT,text=True,capture_output=True)
    assert generated.returncode==0,generated.stdout+generated.stderr
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "recipe-index.py"), "--check", "--root-readme", str(ROOT/"README.md")], cwd=ROOT, text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    print(f"PASS recipe contract: {len(items)} recipes, {len({item.category for item in items})} categories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

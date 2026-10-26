#!/usr/bin/env python3
"""Build the human-facing lmaws recipe catalogue from LMScript headers.

Recipe files deliberately carry their catalogue metadata so they can be imported
from a raw URL without depending on this repository's generator.
"""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECIPES = ROOT / "recipes"
EXAMPLES = ROOT / "examples"
IMAGES = ROOT / "docs" / "images"
CATEGORIES = [
    "Identity and access posture",
    "Inventory",
    "Cost and spend",
    "Idle and waste detection",
    "Tag and naming compliance",
    "Leftover search and cleanup by prefix",
    "Safe lifecycle sandboxes",
]
KEYS = ("category", "what", "access", "when", "run", "preview", "arguments", "typical-cost", "example", "function", "library")
HEADER_RE = re.compile(r"^\s*(?://|#)\s*([A-Za-z][A-Za-z0-9_ -]*):\s*(.*?)\s*$")


@dataclass(frozen=True)
class Recipe:
    path: Path
    meta: dict[str, str]

    @property
    def slug(self) -> str:
        return self.path.stem

    @property
    def category(self) -> str:
        return self.meta["category"]


def read_recipe(path: Path) -> Recipe:
    meta: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines()[:45]:
        match = HEADER_RE.match(line)
        if match:
            key, value = match.groups()
            key = key.lower().replace(" ", "-").replace("_", "-")
            if key in KEYS:
                meta[key] = value.strip()
                continue
        if line.startswith("//") or line.startswith("#"):
            body = line[2:].strip() if line.lstrip().startswith("//") else line[1:].strip()
            aliases = (("what it does:", "what"), ("when to use it:", "when"), ("how to run it:", "run"), ("how to run:", "run"), ("how to preview:", "preview"))
            for prefix, key in aliases:
                if body.lower().startswith(prefix):
                    meta[key] = body[len(prefix):].strip()
                    break
        elif line.strip() and not line.startswith(("//", "#")):
            break
    meta["access"] = re.split(r"[;(]", meta.get("access", ""), maxsplit=1)[0].strip()
    if meta["access"].startswith("Write with the lmaws profile"):
        meta["access"] = "Write with the lmaws profile"
    missing = [key for key in KEYS if key not in meta]
    if missing:
        raise ValueError(f"{path}: missing metadata header(s): {', '.join(missing)}")
    category = meta["category"]
    if category.lower().startswith("safe lifecycle"):
        meta["category"] = "Safe lifecycle sandboxes"
    library_path = ROOT / meta["library"]
    if library_path.exists():
        function_names = re.findall(r"\bfn\s+(recipe_[A-Za-z0-9_]+)\s*\(", library_path.read_text(encoding="utf-8"))
        if function_names:
            meta.setdefault("function", function_names[0])
    if not meta["function"].strip():
        raise ValueError(f"{path}: function metadata is empty")
    if meta["access"] not in {"Read-only", "Write with the lmaws profile"}:
        raise ValueError(f"{path}: access must be Read-only or Write with the lmaws profile")
    if meta["category"] not in CATEGORIES:
        raise ValueError(f"{path}: unknown category {meta['category']!r}")
    return Recipe(path.relative_to(ROOT), meta)


def recipes() -> list[Recipe]:
    if not RECIPES.exists():
        return []
    return sorted((read_recipe(path) for path in RECIPES.glob("*.lms")), key=lambda item: (CATEGORIES.index(item.category), item.slug))


def raw_url(path: Path) -> str:
    return f"https://raw.githubusercontent.com/lmctl-ai/lmaws/main/{path.as_posix()}"


def example_link(recipe: Recipe) -> tuple[str, str, str]:
    example = recipe.meta["example"]
    image = IMAGES / f"{example}.png"
    if not image.exists():
        raise ValueError(f"{recipe.path}: example image does not exist: {image.relative_to(ROOT)}")
    example_path = EXAMPLES / f"{example}.lms"
    if not example_path.exists():
        raise ValueError(f"{recipe.path}: example script does not exist: {example_path.relative_to(ROOT)}")
    caption = f"lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/{example}.lms"
    return f"![{recipe.meta['what']}]({image.relative_to(ROOT).as_posix()})", caption, example


def render(items: list[Recipe]) -> str:
    lines = [
        "# lmaws recipes",
        "",
        "Reusable LMScript recipes for audits, inventory, spend review and safely owned sandboxes.",
        "The access column describes AWS permissions; local reports are written only when a recipe is called.",
        "Each wrapper is runnable directly. Import the paired library from its raw URL when composing recipes; wrappers perform the execution step.",
        "Use `lmaws`, never the `aws` CLI. Read-only recipes use `default`; writes require",
        "`AWS_PROFILE=lmaws`, the ownership prefix/tag, a ledger and teardown.",
        "",
        "All executable recipes default to synthetic fixtures. Use `--preview` for a no-call plan,",
        "or the runner's `lmctl script --dry-run recipes/<name>.lms`. Live inventory needs `--live`;",
        "live sandboxes also require `--apply --profile lmaws`. Prefix discovery and the sweeper",
        "never authorize deletion of existing resources. The current sweeper is read-only.",
        "",
        "Arguments override defaults. `AWS_PROFILE` / `AWS_REGION` and `LMAWS_RECIPE_PERIOD`,",
        "`LMAWS_RECIPE_TOP`, `LMAWS_RECIPE_PREFIX` supply environment defaults. Period is used",
        "by spend recipes; prefix filters inventory when explicitly supplied. All examples force",
        "synthetic mode and their committed pictures contain no real account data.",
        "",
        "Import-only composition example (functions do not execute on import):",
        "",
        "```javascript",
        'import "https://raw.githubusercontent.com/lmctl-ai/lmaws/main/recipes/lib/inventory.lms";',
        'let report=recipe_inventory({task:"queues",top:5,output:"data/my-queues",live:false});',
        'println("matched rows:",len(report.rows));',
        "```",
        "",
    ]
    for category in CATEGORIES:
        group = [item for item in items if item.category == category]
        if not group:
            continue
        lines.extend(["", f"## {category}", "", "| File | What it does | Access | Arguments | Typical cost |", "|---|---|---|---|---|"])
        for item in group:
            meta = item.meta
            lines.append(f"| [`{item.path.name}`]({item.path.name}) | {meta['what']} | {meta['access']} | {meta['arguments']} | {meta['typical-cost']} |")
    lines.extend(["", "## Picture-first examples", "", "Each recipe points at an offline synthetic example so its output can be previewed safely.", ""])
    for item in items:
        image, caption, example = example_link(item)
        image = image.replace("(docs/images/", "(../docs/images/")
        library_url = raw_url(Path(item.meta["library"]))
        lines.extend([f"### {item.slug}", "", f"{image}", "", f"`{caption}`", "", f"Example: [`examples/{example}.lms`](../examples/{example}.lms).", f"Import library: `{library_url}`; function `{item.meta['function']}`.", ""])
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if generated outputs are stale")
    parser.add_argument("--write", action="store_true", help="write generated outputs (the default)")
    parser.add_argument("--root-readme", type=Path, default=None, help="update a marked RECIPES block in this README")
    parser.add_argument("--output", type=Path, default=RECIPES / "README.md")
    args = parser.parse_args()
    text = render(recipes())
    if args.root_readme:
        readme = args.root_readme.read_text(encoding="utf-8")
        start, end = "<!-- RECIPES:START -->", "<!-- RECIPES:END -->"
        if start not in readme or end not in readme or readme.index(start) > readme.index(end):
            raise SystemExit(f"{args.root_readme}: add balanced {start}/{end} markers first")
        root_text = text.removeprefix('# lmaws recipes').strip()
        root_text = '\n'.join('#'+line if line.startswith('##') else line for line in root_text.splitlines())
        root_text = root_text.replace('](', '](recipes/').replace('](recipes/../docs/images/', '](docs/images/').replace('](recipes/../examples/', '](examples/')
        block = f"{start}\n\n{root_text}\n\n{end}"
        readme = readme[:readme.index(start)] + block + readme[readme.index(end) + len(end):]
    else:
        readme = None
    if args.check:
        if not args.output.exists() or args.output.read_text(encoding="utf-8") != text:
            raise SystemExit(f"{args.output}: generated recipe index is stale; run scripts/recipe-index.py")
        if args.root_readme and readme != args.root_readme.read_text(encoding="utf-8"):
            raise SystemExit(f"{args.root_readme}: generated RECIPES block is stale")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        if args.root_readme:
            args.root_readme.write_text(readme, encoding="utf-8")
    print(f"recipe index: {len(recipes())} recipes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

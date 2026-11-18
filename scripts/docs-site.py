#!/usr/bin/env python3
"""Build the Astraea documentation site: guide pages plus the crate reference.

The layout follows the Clio documentation site: a main page, "Related Pages"
for the subsystems, and a code reference. Pages are the Markdown files in the
repository rendered by rustdoc itself (`rustdoc page.md`), so the site needs
nothing beyond the pinned toolchain. The crate reference is `cargo doc`.

usage: python3 scripts/docs-site.py [--out DIR] [--no-api]
  --out DIR   output directory (default target/docs-site); replaced on each run
  --no-api    skip `cargo doc` (guide pages only)
Exit code 2 if rustdoc or cargo is missing. Exit code 0 only if every page rendered, `cargo doc` passed with broken
intra-doc links denied, and every local link on the site points at a file.
Nothing is published; the result is a directory of static files.
The crate reference build empties <target>/doc first, so no page from an
earlier `cargo doc` stays in the site.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(ROOT, "docs", "site")

# (source relative to ROOT, output page name). The output name is what other
# pages link to; links between sources are rewritten to these names.
PAGES = [
    ("docs/site/index.md", "index.html"),
    ("docs/site/pages.md", "pages.html"),
    ("docs/site/crates.md", "crates.html"),
    ("docs/architecture.md", "architecture.html"),
    ("docs/loader.md", "loader.html"),
    ("docs/storage.md", "storage.html"),
    ("docs/proof.md", "proof.html"),
    ("docs/rpc.md", "rpc.html"),
    ("docs/web-server.md", "web-server.html"),
    ("docs/tools.md", "tools.html"),
    ("docs/api.md", "api.html"),
    ("docs/evidence-format.md", "evidence-format.html"),
    ("docs/running.md", "running.html"),
    ("docs/metrics.md", "metrics.html"),
    ("docs/compared-with-clio.md", "compared-with-clio.html"),
    ("CHANGELOG.md", "changelog.html"),
    ("ROADMAP.md", "roadmap.html"),
    ("CONTRIBUTING.md", "contributing.html"),
    ("SECURITY.md", "security.html"),
]
# Repository files a page may link to that are not pages of the site.
REPO_URL = "https://github.com/XRPL-Lending-Network/astraea/blob/main/"

LINK = re.compile(r"(\]\()([^)\s]+)(\))|(\b(?:src|href)=\")([^\"]+)(\")")


def version():
    with open(os.path.join(ROOT, "Cargo.toml"), encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"\[workspace\.package\][^\[]*?\nversion\s*=\s*\"([^\"]+)\"", text)
    if not m:
        raise SystemExit("no [workspace.package] version in Cargo.toml")
    return m.group(1)


def rewrite(target, src_dir, by_source):
    """Map a link in a source page to its place on the site."""
    if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
        return target                      # external link or anchor
    path, _, frag = target.partition("#")
    if not path:
        return target
    repo_path = os.path.normpath(os.path.join(src_dir, path)).replace(os.sep, "/")
    outputs = set(by_source.values())
    if repo_path in by_source:
        page = by_source[repo_path]
    elif src_dir == "docs/site" and path.endswith(".md") and path[:-3].lower() + ".html" in outputs:
        page = path[:-3].lower() + ".html"   # docs/site pages name pages, not files
    elif repo_path.startswith("assets/"):
        page = repo_path                   # copied next to the pages
    elif repo_path.startswith("docs/site/"):
        page = os.path.relpath(repo_path, "docs/site").replace(os.sep, "/")
    elif os.path.exists(os.path.join(ROOT, repo_path)):
        page = REPO_URL + repo_path        # source file: link to the repository
    else:
        # Leave it as it is; the link check below reports it.
        page = path
    return page + ("#" + frag if frag else "")


def render(src, out_name, out_dir, tmp, header, footer, css, by_source):
    src_dir = os.path.dirname(src)
    with open(os.path.join(ROOT, src), encoding="utf-8") as f:
        text = f.read()

    def fix(m):
        if m.group(1):
            return m.group(1) + rewrite(m.group(2), src_dir, by_source) + m.group(3)
        return m.group(4) + rewrite(m.group(5), src_dir, by_source) + m.group(6)
    text = LINK.sub(fix, text)
    lines = text.split("\n")
    first = next((l for l in lines if l.strip()), "")
    if not first.startswith("# "):
        # rustdoc takes the title from the first line; use the first heading.
        title = next((l for l in lines if l.startswith("# ")), None)
        if title is None:
            print(f"{src}: no '# ' heading", file=sys.stderr)
            return False
        lines.remove(title)
        text = "% " + title[2:] + "\n\n" + "\n".join(lines)
    stem = out_name[:-len(".html")]
    md = os.path.join(tmp, stem + ".md")
    with open(md, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    cmd = ["rustdoc", md, "-o", out_dir, "--markdown-no-toc", "--markdown-css", css,
           "--html-before-content", header, "--html-after-content", footer]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0 or r.stderr.strip():
        print(f"rustdoc {src}: rc {r.returncode}\n{r.stderr}", file=sys.stderr)
        return False
    return os.path.exists(os.path.join(out_dir, out_name))


def build_api(out_dir):
    env = dict(os.environ)
    env["RUSTDOCFLAGS"] = (env.get("RUSTDOCFLAGS", "") + " -D rustdoc::broken_intra_doc_links").strip()
    target = os.environ.get("CARGO_TARGET_DIR", os.path.join(ROOT, "target"))
    # Start from an empty doc directory, so no page from an earlier build stays.
    shutil.rmtree(os.path.join(target, "doc"), ignore_errors=True)
    # Library crates, plus the crates that are only a binary. The binaries of
    # ledger-engine (astraea-ingest, astraea-state, ...) are command-line flags,
    # described in running.md and tools.md, so they are left out.
    for args in (["--workspace", "--lib"], ["-p", "witness-archiver", "-p", "witness-unl", "-p", "witness-verify", "--bins"]):
        r = subprocess.run(["cargo", "doc", "--no-deps", "--locked", *args], cwd=ROOT, env=env)
        if r.returncode != 0:
            print(f"cargo doc {' '.join(args)} failed", file=sys.stderr)
            return False
    shutil.copytree(os.path.join(target, "doc"), os.path.join(out_dir, "reference"))
    return True


def check_links(out_dir, api):
    """Every local href/src on the site pages (not inside the rustdoc reference,
    which rustdoc checks itself) must point at an existing file."""
    bad = []
    for name in sorted(os.listdir(out_dir)):
        if not name.endswith(".html"):
            continue
        with open(os.path.join(out_dir, name), encoding="utf-8") as f:
            html = f.read()
        for m in re.finditer(r"\b(?:href|src)=\"([^\"]+)\"", html):
            t = m.group(1)
            if re.match(r"^[a-z][a-z0-9+.-]*:", t) or t.startswith("#"):
                continue
            path = t.split("#")[0]
            if not api and path.startswith("reference/"):
                continue
            if path and not os.path.exists(os.path.join(out_dir, path)):
                bad.append(f"{name}: {t}")
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=os.path.join(ROOT, "target", "docs-site"))
    ap.add_argument("--no-api", action="store_true")
    a = ap.parse_args()
    out_dir = os.path.abspath(a.out)
    for tool in (["rustdoc"] if a.no_api else ["rustdoc", "cargo"]):
        if shutil.which(tool) is None:
            print(f"{tool} not found; install the toolchain from rust-toolchain.toml", file=sys.stderr)
            return 2
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)
    ver = version()
    by_source = {src: out for src, out in PAGES}
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        parts = {}
        for name in ("header.html", "footer.html"):
            with open(os.path.join(SITE, name), encoding="utf-8") as f:
                parts[name] = f.read().replace("@VERSION@", ver)
            with open(os.path.join(tmp, name), "w", encoding="utf-8", newline="\n") as f:
                f.write(parts[name])
        for src, out_name in PAGES:
            if not render(src, out_name, out_dir, tmp, os.path.join(tmp, "header.html"),
                          os.path.join(tmp, "footer.html"), "style.css", by_source):
                ok = False
    shutil.copy(os.path.join(SITE, "style.css"), os.path.join(out_dir, "style.css"))
    shutil.copytree(os.path.join(ROOT, "assets"), os.path.join(out_dir, "assets"))
    if not a.no_api and not build_api(out_dir):
        ok = False
    bad = check_links(out_dir, not a.no_api)
    for b in bad:
        print(f"broken link: {b}", file=sys.stderr)
    pages = len([n for n in os.listdir(out_dir) if n.endswith(".html")])
    print(f"site: {out_dir}, version {ver}, {pages} pages, api {'skipped' if a.no_api else 'built'}, "
          f"broken links {len(bad)}")
    return 0 if ok and not bad else 1


if __name__ == "__main__":
    sys.exit(main())

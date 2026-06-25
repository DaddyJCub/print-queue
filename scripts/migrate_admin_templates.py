"""One-off: migrate standalone admin_*.html pages to extend admin_base.html.

Transform (uniform across pages):
  - drop <!doctype>/<html>/<head>/<body> shell
  - drop the {% include 'admin_nav.html' %} line (nav now comes from admin_base)
  - lift page <style>/<script>/<link> from <head> into a head_extra block
  - keep the entire body verbatim (container divs stay balanced, {% set %} kept)
    inside {% block content %}
  - derive {% block admin_title %} from <title> and {% block active_page %} from
    the page's `{% set active_page = ... %}` expression

Run:  python scripts/migrate_admin_templates.py [--apply] [file ...]
Without --apply it only reports. With no files, processes all admin_*.html that
include admin_nav.html (except the partial itself and already-migrated pages).
"""
import re, sys, glob, os

ROOT = os.path.join(os.path.dirname(__file__), "..", "app", "templates")
ALREADY = {"admin_analytics.html", "admin_queue.html", "admin_base.html", "admin_nav.html"}

NAV_INCLUDE_RE = re.compile(r"[ \t]*{%\s*include\s*['\"]admin_nav\.html['\"]\s*%}[ \t]*\n?")
SET_ACTIVE_RE = re.compile(r"{%\s*set\s+active_page\s*=\s*(.+?)\s*%}")
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.S)
BODY_OPEN_RE = re.compile(r"<body[^>]*>", re.S)
HEAD_RE = re.compile(r"<head>(.*?)</head>", re.S)
STYLE_RE = re.compile(r"<style>.*?</style>", re.S)
SCRIPT_RE = re.compile(r"<script\b.*?</script>", re.S)
LINK_RE = re.compile(r'<link\b[^>]*?>', re.S)


def migrate(src: str):
    # --- title ---
    mt = TITLE_RE.search(src)
    title = "Admin"
    if mt:
        title = mt.group(1).split("|")[0].split("·")[0].strip() or "Admin"

    # --- active_page expression ---
    ma = SET_ACTIVE_RE.search(src)
    active_expr = ma.group(1).strip() if ma else "''"

    # --- head extras (style/script/non-tailwind links) ---
    head_extras = []
    mh = HEAD_RE.search(src)
    if mh:
        head = mh.group(1)
        for m in STYLE_RE.finditer(head):
            head_extras.append(m.group(0))
        for m in SCRIPT_RE.finditer(head):
            head_extras.append(m.group(0))
        for m in LINK_RE.finditer(head):
            tag = m.group(0)
            if "tailwind.css" in tag or "manifest" in tag or "apple-touch-icon" in tag:
                continue
            head_extras.append(tag)

    # --- body inner ---
    mb = BODY_OPEN_RE.search(src)
    if not mb:
        raise ValueError("no <body> tag")
    body_start = mb.end()
    body_end = src.rfind("</body>")
    if body_end == -1:
        raise ValueError("no </body>")
    body_inner = src[body_start:body_end]
    # drop the nav include
    body_inner = NAV_INCLUDE_RE.sub("", body_inner)
    # drop a leading "<!-- Navigation -->" comment if present
    body_inner = re.sub(r"[ \t]*<!--\s*Navigation\s*-->[ \t]*\n?", "", body_inner)
    body_inner = body_inner.strip("\n")

    # --- assemble ---
    out = []
    out.append('{% extends "admin_base.html" %}')
    out.append("")
    out.append("{% block admin_title %}" + title + "{% endblock %}")
    out.append("{% block active_page %}{{ " + active_expr + " }}{% endblock %}")
    if head_extras:
        out.append("")
        out.append("{% block head_extra %}")
        out.extend(head_extras)
        out.append("{% endblock %}")
    out.append("")
    out.append("{% block content %}")
    out.append(body_inner)
    out.append("{% endblock %}")
    out.append("")
    return "\n".join(out)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    apply = "--apply" in sys.argv
    if args:
        files = [os.path.join(ROOT, a) for a in args]
    else:
        files = sorted(glob.glob(os.path.join(ROOT, "admin_*.html")))
    for path in files:
        name = os.path.basename(path)
        if name in ALREADY:
            continue
        src = open(path, encoding="utf-8").read()
        if "admin_nav.html" not in src or "{% extends" in src:
            print(f"SKIP   {name}")
            continue
        try:
            new = migrate(src)
        except Exception as e:
            print(f"ERROR  {name}: {e}")
            continue
        if apply:
            open(path, "w", encoding="utf-8", newline="\n").write(new)
            print(f"WROTE  {name}  ({len(src)} -> {len(new)} bytes)")
        else:
            print(f"OK     {name}  ({len(src)} -> {len(new)} bytes)")


if __name__ == "__main__":
    main()

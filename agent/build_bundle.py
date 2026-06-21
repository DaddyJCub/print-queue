#!/usr/bin/env python3
"""Build an OTA bundle (.zip) of the agent for upload in the admin panel.

Usage:
    python build_bundle.py [output.zip]

The bundle contains the ``printqueue_agent/`` package. Upload it under
Admin → Print Agents → "Agent software updates", then push it to each agent.
"""
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "printqueue_agent")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "agent-bundle.zip")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(PKG):
            # Skip caches and any prior backup left by a self-update.
            if "__pycache__" in root or root.endswith(".bak"):
                continue
            for name in files:
                if name.endswith(".pyc"):
                    continue
                full = os.path.join(root, name)
                arc = os.path.relpath(full, HERE)  # keep "printqueue_agent/..." prefix
                zf.write(full, arc)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()

# Minimal boot hook. Keep this file small and stable.
# Place rollback guards here if your OTA flow stages versions.

try:
    import gc

    gc.collect()
except Exception:
    pass

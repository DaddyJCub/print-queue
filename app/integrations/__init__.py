"""External provider integrations for the request form (Printables, etc.).

Keep provider parsing/HTTP logic in this package so route handlers stay thin
(GUD-002). Each provider exposes a small, deterministic contract consumed by
``app/public.py``.
"""

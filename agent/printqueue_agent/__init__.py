"""Print-queue printer agent — cross-platform (Raspberry Pi / Windows).

Drives a Marlin USB printer (e.g. Longer LK5 Pro) from a host that lives on a
separate network from the print-queue server, using only outbound HTTPS.
"""

# Agent package version. This is its OWN line (the agent started at 1.0.0),
# independent of the app's 0.x version — the OTA upgrade check compares these
# numerically, so it must only ever move forward from 1.0.0.
__version__ = "1.1.0"

"""Cura plugin: register the Print Queue output device.

This makes "Send to LK5 Pro" appear in Cura's save/print button dropdown, right
alongside "Save to Disk" and "Print via USB". Clicking it uploads the sliced
G-code to the print queue and starts the print — no manual export.
"""

from . import PrintQueueOutputDevicePlugin


def getMetaData():
    return {}


def register(app):
    return {"output_device": PrintQueueOutputDevicePlugin.PrintQueueOutputDevicePlugin()}

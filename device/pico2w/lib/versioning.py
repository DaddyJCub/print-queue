DEFAULT_FW_VERSION = "fw-0.0.0"
DEFAULT_APP_VERSION = "app-0.0.0"


def _clean(value):
    text = str(value or "").strip()
    return text or None


def get_reported_versions(config, app_state):
    """Resolve stable firmware/app version strings for API calls.

    App version precedence:
    1) pending_version (post-OTA boot awaiting confirmation)
    2) last_good_version
    3) configured app_version
    4) default placeholder
    """
    config = config or {}
    app_state = app_state or {}

    fw_version = _clean(config.get("fw_version")) or DEFAULT_FW_VERSION

    pending_version = _clean(app_state.get("pending_version"))
    last_good_version = _clean(app_state.get("last_good_version"))
    configured_app_version = _clean(config.get("app_version"))

    if pending_version:
        app_version = pending_version
    elif last_good_version:
        app_version = last_good_version
    elif configured_app_version:
        app_version = configured_app_version
    else:
        app_version = DEFAULT_APP_VERSION

    return fw_version, app_version

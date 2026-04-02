from lib.file_store import append_ring, in_ring


class CommandRunner:
    def __init__(self, hw, api, app_state_path, ota_manager=None):
        self.hw = hw
        self.api = api
        self.app_state_path = app_state_path
        self.ota_manager = ota_manager

    def _safe_command_status(self, cmd_id, status, error=None, result=None):
        """Compatibility wrapper: tolerate older ApiClient signatures."""
        try:
            if result is not None:
                return self.api.command_status(cmd_id, status, error=error, result=result)
            return self.api.command_status(cmd_id, status, error=error)
        except TypeError:
            # Legacy ApiClient.command_status(cmd_id, status, error=None)
            try:
                return self.api.command_status(cmd_id, status, error=error)
            except Exception:
                return None
        except Exception:
            return None

    def execute(self, cmd):
        cmd_id = cmd.get("cmd_id")
        action = cmd.get("action")
        payload = cmd.get("payload") or {}

        if not cmd_id:
            return

        if in_ring(self.app_state_path, cmd_id):
            return

        self._safe_command_status(cmd_id, "executing")

        try:
            result = {}
            if action == "play_perk":
                self.hw.play_perk(payload.get("perk_id"))
                result = {"perk_id": payload.get("perk_id")}
            elif action == "stop_audio":
                self.hw.stop_audio()
                result = {"stopped": True}
            elif action == "set_idle":
                self.hw.set_idle(payload.get("mode", "default"))
                result = {"idle_mode": payload.get("mode", "default")}
            elif action == "set_brightness":
                result = self.hw.set_brightness(int(payload.get("level", 0))) or {}
            elif action == "set_volume":
                result = self.hw.set_volume(int(payload.get("level", 0))) or {}
            elif action == "set_light_color":
                result = self.hw.set_light_color(payload.get("color") or {}) or {}
            elif action == "set_light_effect":
                result = self.hw.set_light_effect(
                    payload.get("effect"),
                    speed_ms=payload.get("speed_ms"),
                    duration_ms=payload.get("duration_ms"),
                    color=payload.get("color"),
                ) or {}
            elif action == "test_lights":
                result = self.hw.test_lights(
                    payload.get("effect") or payload.get("pattern"),
                    int(payload.get("duration_ms", 0)),
                    color=payload.get("color"),
                    speed_ms=payload.get("speed_ms"),
                ) or {}
            elif action == "test_audio":
                result = self.hw.test_audio(payload.get("track_id")) or {}
            elif action == "notify_shipping":
                result = self.hw.notify_shipping(payload.get("status", "in_transit")) or {}
            elif action == "reboot":
                self.hw.reboot()
                result = {"rebooting": True}
            elif action == "ota_apply":
                if not self.ota_manager:
                    raise Exception("ota manager not configured")
                version = payload.get("version", "latest")
                self.ota_manager.apply_update(version)
                self._safe_command_status(
                    cmd_id,
                    "completed",
                    result={"ota_version": version, "rebooting": True},
                )
                append_ring(self.app_state_path, cmd_id)
                self.hw.reboot()
                return
            else:
                raise Exception("unsupported action: %s" % action)

            self.api.state_update(self.hw.get_state())
            self._safe_command_status(cmd_id, "completed", result=result)
            append_ring(self.app_state_path, cmd_id)
        except Exception as exc:
            self._safe_command_status(cmd_id, "failed", error=str(exc), result={"exception": str(exc)})

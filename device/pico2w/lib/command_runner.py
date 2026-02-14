from lib.file_store import append_ring, in_ring


class CommandRunner:
    def __init__(self, hw, api, app_state_path, ota_manager=None):
        self.hw = hw
        self.api = api
        self.app_state_path = app_state_path
        self.ota_manager = ota_manager

    def execute(self, cmd):
        cmd_id = cmd.get("cmd_id")
        action = cmd.get("action")
        payload = cmd.get("payload") or {}

        if not cmd_id:
            return

        if in_ring(self.app_state_path, cmd_id):
            return

        self.api.command_status(cmd_id, "executing")

        try:
            if action == "play_perk":
                self.hw.play_perk(payload.get("perk_id"))
            elif action == "stop_audio":
                self.hw.stop_audio()
            elif action == "set_idle":
                self.hw.set_idle(payload.get("mode", "default"))
            elif action == "set_brightness":
                self.hw.set_brightness(int(payload.get("level", 0)))
            elif action == "set_volume":
                self.hw.set_volume(int(payload.get("level", 0)))
            elif action == "test_lights":
                self.hw.test_lights(payload.get("pattern"), int(payload.get("duration_ms", 0)))
            elif action == "test_audio":
                self.hw.test_audio(payload.get("track_id"))
            elif action == "reboot":
                self.hw.reboot()
            elif action == "ota_apply":
                if not self.ota_manager:
                    raise Exception("ota manager not configured")
                version = payload.get("version", "latest")
                self.ota_manager.apply_update(version)
                self.api.command_status(cmd_id, "completed")
                append_ring(self.app_state_path, cmd_id)
                self.hw.reboot()
                return
            else:
                raise Exception("unsupported action: %s" % action)

            self.api.state_update(self.hw.get_state())
            self.api.command_status(cmd_id, "completed")
            append_ring(self.app_state_path, cmd_id)
        except Exception as exc:
            self.api.command_status(cmd_id, "failed", error=str(exc))

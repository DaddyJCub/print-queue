class HardwareAdapter:
    """Board-specific I/O adapter. Replace with real drivers for lights/audio/buttons."""

    def __init__(self):
        self.playing = False
        self.perk_id = None
        self.track_id = None
        self.volume = 10
        self.brightness = 30
        self.idle_mode = "default"
        self.light_color = {"r": 255, "g": 255, "b": 255}
        self.light_effect = "ambient"
        self.last_light_test = None

    def play_perk(self, perk_id):
        self.playing = True
        self.perk_id = perk_id
        self.track_id = perk_id

    def stop_audio(self):
        self.playing = False
        self.perk_id = None
        self.track_id = None

    def set_idle(self, mode):
        self.idle_mode = mode

    def set_brightness(self, level):
        self.brightness = level
        return {"brightness": self.brightness}

    def set_volume(self, level):
        self.volume = level
        return {"volume": self.volume}

    def set_light_color(self, color):
        rgb = self._normalize_rgb(color)
        self.light_color = rgb
        return {"light_color": rgb, "hex": self._rgb_to_hex(rgb)}

    def set_light_effect(self, effect, speed_ms=None, duration_ms=None, color=None):
        if not effect:
            effect = "ambient"
        self.light_effect = str(effect).strip().lower()
        result = {"light_effect": self.light_effect}
        if speed_ms is not None:
            result["speed_ms"] = int(speed_ms)
        if duration_ms is not None:
            result["duration_ms"] = int(duration_ms)
        if color is not None:
            rgb = self._normalize_rgb(color)
            self.light_color = rgb
            result["light_color"] = rgb
            result["hex"] = self._rgb_to_hex(rgb)
        return result

    def test_lights(self, pattern, duration_ms, color=None, speed_ms=None):
        result = {
            "effect": str(pattern or "pulse").strip().lower(),
            "duration_ms": int(duration_ms),
        }
        if speed_ms is not None:
            result["speed_ms"] = int(speed_ms)
        if color is not None:
            rgb = self._normalize_rgb(color)
            self.light_color = rgb
            result["light_color"] = rgb
            result["hex"] = self._rgb_to_hex(rgb)
        self.last_light_test = result
        return result

    def test_audio(self, track_id):
        self.track_id = track_id
        return {"track_id": self.track_id}

    def reboot(self):
        try:
            import machine

            machine.reset()
        except Exception:
            # Local dev fallback when running off-device.
            return

    def get_state(self):
        return {
            "playing": self.playing,
            "perk_id": self.perk_id,
            "track_id": self.track_id,
            "volume": self.volume,
            "brightness": self.brightness,
            "idle_mode": self.idle_mode,
            "light_color": self.light_color,
            "light_effect": self.light_effect,
            "last_light_test": self.last_light_test,
        }

    def notify_shipping(self, status):
        """Flash LED pattern to indicate shipping status.
        Patterns:
          in_transit   - 3 slow blue pulses
          out_for_delivery - 5 fast green pulses
          delivered    - solid green 3s
          exception    - 3 red flashes
        """
        # On real hardware, drive NeoPixel/WS2812 or onboard LED.
        # This is a stub for the hardware abstraction.
        shipping_map = {
            "in_transit": {"effect": "pulse", "color": {"r": 64, "g": 120, "b": 255}},
            "out_for_delivery": {"effect": "strobe", "color": {"r": 0, "g": 220, "b": 120}},
            "delivered": {"effect": "solid", "color": {"r": 0, "g": 255, "b": 96}},
            "exception": {"effect": "strobe", "color": {"r": 255, "g": 64, "b": 64}},
        }
        mapped = shipping_map.get(status or "in_transit", shipping_map["in_transit"])
        self.light_effect = mapped["effect"]
        self.light_color = mapped["color"]
        return {"status": status, "light_effect": self.light_effect, "light_color": self.light_color}

    def set_led_phase(self, phase):
        # Hook for button-hold feedback patterns.
        _ = phase

    def check_local_button_actions(self):
        # Return optional state changes from physical button presses.
        return None

    def _normalize_rgb(self, color):
        if not isinstance(color, dict):
            return dict(self.light_color)
        out = {}
        for key in ("r", "g", "b"):
            val = color.get(key, self.light_color.get(key, 0))
            try:
                val = int(val)
            except Exception:
                val = self.light_color.get(key, 0)
            if val < 0:
                val = 0
            if val > 255:
                val = 255
            out[key] = val
        return out

    def _rgb_to_hex(self, rgb):
        return "#{:02X}{:02X}{:02X}".format(rgb["r"], rgb["g"], rgb["b"])

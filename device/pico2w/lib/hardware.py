class HardwareAdapter:
    """Board-specific I/O adapter. Replace with real drivers for lights/audio/buttons."""

    def __init__(self):
        self.playing = False
        self.perk_id = None
        self.track_id = None
        self.volume = 10
        self.brightness = 30
        self.idle_mode = "default"

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

    def set_volume(self, level):
        self.volume = level

    def test_lights(self, pattern, duration_ms):
        _ = (pattern, duration_ms)

    def test_audio(self, track_id):
        self.track_id = track_id

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
        }

    def set_led_phase(self, phase):
        # Hook for button-hold feedback patterns.
        _ = phase

    def check_local_button_actions(self):
        # Return optional state changes from physical button presses.
        return None

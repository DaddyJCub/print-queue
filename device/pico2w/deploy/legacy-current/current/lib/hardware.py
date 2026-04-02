import time

try:
    from machine import Pin, PWM
except Exception:
    Pin = None
    PWM = None

try:
    import neopixel  # type: ignore
except Exception:
    neopixel = None

from lib.file_store import read_json
try:
    from lib.dfplayer import DFPlayer
except Exception:
    DFPlayer = None


def _ticks_ms():
    if hasattr(time, "ticks_ms"):
        return time.ticks_ms()
    return int(time.time() * 1000)


def _ticks_diff(now, then):
    if hasattr(time, "ticks_diff"):
        return time.ticks_diff(now, then)
    return now - then


def _sleep_ms(ms):
    if hasattr(time, "sleep_ms"):
        time.sleep_ms(ms)
    else:
        time.sleep(max(0, int(ms)) / 1000.0)


class HardwareAdapter:
    """Pico hardware adapter with LED, local buttons, and optional speaker PWM."""

    def __init__(self, cfg=None):
        self.playing = False
        self.perk_id = None
        self.track_id = None
        self.volume = 10
        self.brightness = 30
        self.idle_mode = "default"
        self.light_color = {"r": 255, "g": 255, "b": 255}
        self.light_effect = "off"
        self.last_light_test = None

        loaded_cfg = read_json("/config.json", default={}) or {}
        self._cfg = dict(loaded_cfg)
        if cfg:
            self._cfg.update(cfg)
        startup_color = self._cfg_get("startup_light_color", "default_light_color")
        if isinstance(startup_color, dict):
            self.light_color = self._normalize_rgb(startup_color)
        startup_effect = self._cfg_get("startup_light_effect", "default_light_effect")
        if startup_effect is not None:
            self.light_effect = str(startup_effect).strip().lower() or "off"

        self._status_led_inverted = False
        self._status_led = self._init_status_led()

        self._np = None
        self._np_count = 0
        self._phase = "idle"
        self._phase_tick = _ticks_ms()
        self._phase_on = False
        self._last_np_rgb = (0, 0, 0)
        self._init_neopixel()

        self._speaker_pwm = None
        self._speaker_pin = None
        self._dfplayer = None
        self._audio_driver = "none"
        self._speaker_active = False
        self._speaker_default_freq = self._coerce_int(self._cfg_get("speaker_default_freq"), 880)
        self._speaker_test_duration_ms = self._coerce_int(
            self._cfg_get("speaker_test_duration_ms"), 600
        )
        self._track_freq_map = self._init_track_freq_map()
        self._init_speaker()
        self._init_dfplayer()

        self._button_bindings = []
        self._button_debounce_ms = self._coerce_int(self._cfg_get("button_debounce_ms"), 250)
        self._last_button_event_ms = 0
        self._init_buttons()

        self._set_status_led(False)
        self._apply_light_output()

    def play_perk(self, perk_id):
        self.playing = True
        self.perk_id = perk_id
        self.track_id = perk_id
        self._start_audio(perk_id)

    def stop_audio(self):
        self.playing = False
        self.perk_id = None
        self.track_id = None
        self._stop_audio()

    def set_idle(self, mode):
        self.idle_mode = mode

    def set_brightness(self, level):
        level = int(level)
        if level < 0:
            level = 0
        if level > 100:
            level = 100
        self.brightness = level
        self._apply_light_output()
        return {"brightness": self.brightness}

    def set_volume(self, level):
        level = int(level)
        if level < 0:
            level = 0
        if level > 30:
            level = 30
        self.volume = level
        if self._audio_driver == "dfplayer" and self._dfplayer:
            self._dfplayer.set_volume(self.volume)
        if self._speaker_active and self._speaker_pwm:
            self._speaker_pwm.duty_u16(self._volume_to_duty())
        return {"volume": self.volume}

    def set_light_color(self, color):
        rgb = self._normalize_rgb(color)
        self.light_color = rgb
        self._apply_light_output()
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
        self._apply_light_output()
        return result

    def test_lights(self, pattern, duration_ms, color=None, speed_ms=None):
        effect = str(pattern or "pulse").strip().lower()
        duration_ms = int(duration_ms)
        speed_ms = int(speed_ms) if speed_ms is not None else 300
        if speed_ms <= 0:
            speed_ms = 300
        if duration_ms < 0:
            duration_ms = 0

        if color is not None:
            self.light_color = self._normalize_rgb(color)

        result = {
            "effect": effect,
            "duration_ms": duration_ms,
            "speed_ms": speed_ms,
            "light_color": dict(self.light_color),
            "hex": self._rgb_to_hex(self.light_color),
        }

        end_ms = _ticks_ms() + duration_ms
        while _ticks_diff(end_ms, _ticks_ms()) > 0:
            if effect in {"solid", "ambient"}:
                self._write_light_rgb(self._scaled_rgb(self.light_color))
                _sleep_ms(min(50, speed_ms))
            elif effect in {"strobe", "blink"}:
                self._write_light_rgb(self._scaled_rgb(self.light_color))
                _sleep_ms(speed_ms // 2)
                self._write_light_rgb((0, 0, 0))
                _sleep_ms(speed_ms // 2)
            else:
                self._write_light_rgb(self._scaled_rgb(self.light_color))
                _sleep_ms(speed_ms // 2)
                self._write_light_rgb((0, 0, 0))
                _sleep_ms(speed_ms // 2)

        self._apply_light_output()
        self.last_light_test = result
        return result

    def test_audio(self, track_id):
        self.track_id = track_id
        self._start_audio(track_id, transient_ms=self._speaker_test_duration_ms)
        return {
            "track_id": self.track_id,
            "speaker_active": bool(self._speaker_pwm or self._dfplayer),
            "audio_driver": self._audio_driver,
        }

    def reboot(self):
        try:
            import machine

            machine.reset()
        except Exception:
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
        shipping_map = {
            "in_transit": {"effect": "pulse", "color": {"r": 64, "g": 120, "b": 255}},
            "out_for_delivery": {"effect": "strobe", "color": {"r": 0, "g": 220, "b": 120}},
            "delivered": {"effect": "solid", "color": {"r": 0, "g": 255, "b": 96}},
            "exception": {"effect": "strobe", "color": {"r": 255, "g": 64, "b": 64}},
        }
        mapped = shipping_map.get(status or "in_transit", shipping_map["in_transit"])
        self.light_effect = mapped["effect"]
        self.light_color = mapped["color"]
        self._apply_light_output()
        return {
            "status": status,
            "light_effect": self.light_effect,
            "light_color": self.light_color,
        }

    def set_led_phase(self, phase):
        phase = str(phase or "idle")
        if phase != self._phase:
            self._phase = phase
            self._phase_tick = _ticks_ms()
            self._phase_on = False

        if phase == "idle":
            self._set_status_led(False)
            return

        if phase == "commit":
            self._set_status_led(True)
            return

        period_ms = 800
        if phase == "fast_blink":
            period_ms = 250
        elif phase == "alt_blink":
            period_ms = 180
        elif phase == "alt_very_fast":
            period_ms = 90

        now = _ticks_ms()
        if _ticks_diff(now, self._phase_tick) >= period_ms:
            self._phase_tick = now
            self._phase_on = not self._phase_on
            self._set_status_led(self._phase_on)

    def check_local_button_actions(self):
        if not self._button_bindings:
            return None

        now_ms = _ticks_ms()
        for binding in self._button_bindings:
            pressed = self._button_pressed(binding)
            was_pressed = binding.get("was_pressed", False)
            if pressed and (not was_pressed):
                if _ticks_diff(now_ms, self._last_button_event_ms) < self._button_debounce_ms:
                    binding["was_pressed"] = pressed
                    continue
                self._last_button_event_ms = now_ms
                perk_id = binding.get("perk_id")
                self.play_perk(perk_id)
                binding["was_pressed"] = pressed
                return {"action": "play_perk", "perk_id": perk_id}
            binding["was_pressed"] = pressed
        return None

    def flash_status(self, color, count=1, interval_ms=200):
        count = int(count) if count is not None else 1
        if count < 1:
            count = 1
        interval_ms = int(interval_ms) if interval_ms is not None else 200
        if interval_ms < 10:
            interval_ms = 10

        rgb = self._normalize_rgb(color or {})
        on_rgb = self._scaled_rgb(rgb)
        off_rgb = (0, 0, 0)
        for _ in range(count):
            self._set_status_led(True)
            self._write_light_rgb(on_rgb)
            _sleep_ms(interval_ms)
            self._set_status_led(False)
            self._write_light_rgb(off_rgb)
            _sleep_ms(interval_ms)
        self._apply_light_output()

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

    def _scaled_rgb(self, rgb):
        scale = self.brightness / 100.0
        if scale < 0:
            scale = 0
        if scale > 1:
            scale = 1
        return (
            int(rgb.get("r", 0) * scale),
            int(rgb.get("g", 0) * scale),
            int(rgb.get("b", 0) * scale),
        )

    def _cfg_get(self, *keys):
        for key in keys:
            if key in self._cfg:
                return self._cfg.get(key)
        return None

    def _coerce_int(self, value, default):
        try:
            return int(value)
        except Exception:
            return default

    def _init_status_led(self):
        if not Pin:
            return None

        pin_val = self._cfg_get("status_led_pin", "led_pin")
        self._status_led_inverted = bool(self._cfg_get("status_led_inverted", "led_inverted") or False)

        if pin_val is not None:
            try:
                return Pin(pin_val, Pin.OUT)
            except Exception:
                try:
                    return Pin(int(pin_val), Pin.OUT)
                except Exception:
                    pass

        try:
            return Pin("LED", Pin.OUT)
        except Exception:
            pass
        try:
            return Pin(25, Pin.OUT)
        except Exception:
            return None

    def _init_neopixel(self):
        if not Pin or not neopixel:
            return

        pin_val = self._cfg_get("neopixel_pin", "rgb_pin", "ws2812_pin")
        if pin_val is None:
            # Legacy prototype default from known working hardware.
            pin_val = 15

        count = self._coerce_int(self._cfg_get("neopixel_count", "rgb_count"), 28)
        if count < 1:
            count = 1

        try:
            pin = Pin(int(pin_val), Pin.OUT)
            self._np = neopixel.NeoPixel(pin, count)
            self._np_count = count
            self._write_light_rgb((0, 0, 0))
        except Exception:
            self._np = None
            self._np_count = 0

    def _init_speaker(self):
        if not Pin or not PWM:
            return

        audio_driver = str(self._cfg_get("audio_driver") or "").strip().lower()
        pin_val = self._cfg_get("speaker_pin", "speaker_pwm_pin", "audio_pin", "buzzer_pin")
        if pin_val is None:
            return
        if audio_driver and audio_driver != "pwm":
            return

        try:
            self._speaker_pin = Pin(int(pin_val), Pin.OUT)
            self._speaker_pwm = PWM(self._speaker_pin)
            self._speaker_pwm.freq(self._speaker_default_freq)
            self._speaker_pwm.duty_u16(0)
            self._speaker_active = False
            self._audio_driver = "pwm"
        except Exception:
            self._speaker_pwm = None
            self._speaker_pin = None
            self._speaker_active = False

    def _init_dfplayer(self):
        if not DFPlayer:
            return

        audio_driver = str(self._cfg_get("audio_driver") or "").strip().lower()
        explicit = audio_driver == "dfplayer" or bool(self._cfg_get("dfplayer_enabled"))
        has_df_cfg = (
            self._cfg_get("dfplayer_uart_id") is not None
            or self._cfg_get("dfplayer_tx") is not None
            or self._cfg_get("dfplayer_rx") is not None
            or self._cfg_get("dfplayer_busy") is not None
        )
        if (not explicit) and (not has_df_cfg):
            return

        uart_id = self._coerce_int(self._cfg_get("dfplayer_uart_id"), 0)
        tx_pin = self._coerce_int(self._cfg_get("dfplayer_tx"), 0)
        rx_pin = self._coerce_int(self._cfg_get("dfplayer_rx"), 1)
        busy_raw = self._cfg_get("dfplayer_busy")
        busy_pin = self._coerce_int(busy_raw, 6) if busy_raw is not None else 6

        try:
            df = DFPlayer(uart_id=uart_id, tx_pin=tx_pin, rx_pin=rx_pin, busy_pin=busy_pin)
        except Exception:
            return
        if not getattr(df, "ready", lambda: False)():
            return

        self._dfplayer = df
        self._dfplayer.set_volume(self.volume)
        self._audio_driver = "dfplayer"

    def _init_track_freq_map(self):
        default_map = {
            "juggernog": 440,
            "speed_cola": 494,
            "speedcola": 494,
            "double_tap": 523,
            "doubletap": 523,
            "quick_revive": 587,
            "quickrevive": 587,
            "staminup": 659,
            "widowswine": 698,
            "deadshot": 784,
            "mulekick": 880,
        }
        custom = self._cfg_get("speaker_track_freqs", "track_freqs", "tone_map")
        if isinstance(custom, dict):
            for key, val in custom.items():
                try:
                    default_map[str(key).strip().lower()] = int(val)
                except Exception:
                    continue
        return default_map

    def _volume_to_duty(self):
        vol = self.volume
        if vol < 0:
            vol = 0
        if vol > 30:
            vol = 30
        ratio = vol / 30.0
        return int(65535 * ratio * 0.5)

    def _start_audio(self, track_id, transient_ms=None):
        if self._audio_driver == "dfplayer" and self._dfplayer:
            track_num = self._resolve_dfplayer_track(track_id)
            self._dfplayer.play_track(track_num)
            self._speaker_active = True
            if transient_ms is not None:
                ms = self._coerce_int(transient_ms, 0)
                if ms > 0:
                    _sleep_ms(ms)
                    if not self.playing:
                        self._stop_audio()
            return

        if self._speaker_pwm:
            key = str(track_id or "").strip().lower()
            freq = self._track_freq_map.get(key, self._speaker_default_freq)
            if freq < 80:
                freq = 80
            try:
                self._speaker_pwm.freq(int(freq))
                self._speaker_pwm.duty_u16(self._volume_to_duty())
                self._speaker_active = True
            except Exception:
                self._speaker_active = False
                return

            if transient_ms is not None:
                ms = self._coerce_int(transient_ms, 0)
                if ms > 0:
                    _sleep_ms(ms)
                    if not self.playing:
                        self._stop_audio()

    def _stop_audio(self):
        if self._audio_driver == "dfplayer" and self._dfplayer:
            self._dfplayer.stop()
            self._speaker_active = False
            return

        if not self._speaker_pwm:
            return
        try:
            self._speaker_pwm.duty_u16(0)
        except Exception:
            pass
        self._speaker_active = False

    def _resolve_dfplayer_track(self, track_id):
        default_map = {
            "juggernog": 1,
            "speed_cola": 2,
            "quick_revive": 3,
            "double_tap": 4,
            "speedcola": 2,
            "quickrevive": 3,
            "doubletap": 4,
        }
        custom = self._cfg_get("dfplayer_track_map", "track_map")
        if isinstance(custom, dict):
            for key, val in custom.items():
                try:
                    default_map[str(key).strip().lower()] = int(val)
                except Exception:
                    continue
        key = str(track_id or "").strip().lower()
        track = default_map.get(key)
        if track is None:
            try:
                track = int(track_id)
            except Exception:
                track = 1
        if track < 1:
            track = 1
        if track > 9999:
            track = 9999
        return track

    def _button_pressed(self, binding):
        pin = binding.get("pin")
        if not pin:
            return False
        try:
            raw = pin.value()
        except Exception:
            return False
        active_low = bool(binding.get("active_low", True))
        return (raw == 0) if active_low else (raw == 1)

    def _init_buttons(self):
        if not Pin:
            return

        active_low = bool(self._cfg_get("button_active_low") if self._cfg_get("button_active_low") is not None else True)
        pull = Pin.PULL_UP if active_low else Pin.PULL_DOWN
        reset_raw = self._cfg_get("reset_pin", "reset_button_pin")
        reset_pin = None
        if reset_raw is not None:
            reset_pin = self._coerce_int(reset_raw, None)

        bindings = []
        perk_buttons = self._cfg_get("perk_buttons")
        if isinstance(perk_buttons, list):
            for item in perk_buttons:
                if not isinstance(item, dict):
                    continue
                pin = item.get("pin")
                perk_id = item.get("perk_id") or item.get("track_id") or item.get("name")
                if pin is None or not perk_id:
                    continue
                bindings.append((pin, str(perk_id)))

        if not bindings:
            button_pins = self._cfg_get("button_pins")
            perks = self._cfg_get("perks", "PERKS")
            if isinstance(button_pins, list) and isinstance(perks, list):
                for perk in perks:
                    if not isinstance(perk, dict):
                        continue
                    idx = perk.get("button_pin_index")
                    perk_id = perk.get("perk_id") or perk.get("track_id") or perk.get("name")
                    if idx is None or perk_id is None:
                        continue
                    try:
                        idx = int(idx)
                        pin = button_pins[idx]
                    except Exception:
                        continue
                    bindings.append((pin, str(perk_id)))

        if not bindings:
            # Legacy known-good prototype mapping.
            bindings = [
                (14, "juggernog"),
                (16, "speed_cola"),
                (17, "quick_revive"),
                (18, "double_tap"),
            ]

        seen = set()
        for pin_val, perk_id in bindings:
            try:
                pin_int = int(pin_val)
            except Exception:
                continue
            if reset_pin is not None and pin_int == reset_pin:
                continue
            if pin_int in seen:
                continue
            seen.add(pin_int)
            try:
                pin_obj = Pin(pin_int, Pin.IN, pull)
            except Exception:
                continue
            self._button_bindings.append(
                {
                    "pin": pin_obj,
                    "pin_num": pin_int,
                    "perk_id": perk_id,
                    "active_low": active_low,
                    "was_pressed": False,
                }
            )

    def _set_status_led(self, on):
        if not self._status_led:
            return
        val = 1 if on else 0
        if self._status_led_inverted:
            val = 0 if val else 1
        try:
            self._status_led.value(val)
        except Exception:
            pass

    def _write_light_rgb(self, rgb):
        if not self._np or self._np_count <= 0:
            self._last_np_rgb = rgb
            return
        try:
            for idx in range(self._np_count):
                self._np[idx] = rgb
            self._np.write()
            self._last_np_rgb = rgb
        except Exception:
            pass

    def _apply_light_output(self):
        effect = str(self.light_effect or "ambient").lower()
        if effect in {"off", "none"}:
            self._write_light_rgb((0, 0, 0))
            return
        self._write_light_rgb(self._scaled_rgb(self.light_color))

import time

try:
    from machine import Pin
except Exception:
    Pin = None


class ResetController:
    """
    Continuous-hold reset controller.
    - 10s hold => wifi_reset
    - 20s hold => factory_reset
    """

    def __init__(self, pin_num=15, wifi_hold_s=10, factory_hold_s=20, soft_window_s=3):
        self.wifi_hold_s = wifi_hold_s
        self.factory_hold_s = factory_hold_s
        self.soft_window_s = soft_window_s
        self._pin = Pin(pin_num, Pin.IN, Pin.PULL_UP) if Pin else None
        self._press_start = None
        self._committed = None
        self._press_times = []

    def _pressed(self):
        if not self._pin:
            return False
        return self._pin.value() == 0

    def poll(self):
        now = time.time()
        if self._pressed():
            if self._press_start is None:
                self._press_start = now
                self._committed = None

            held_s = now - self._press_start
            if held_s >= self.factory_hold_s and self._committed != "factory_reset":
                self._committed = "factory_reset"
                return "factory_reset"
            if held_s >= self.wifi_hold_s and self._committed != "wifi_reset":
                self._committed = "wifi_reset"
                return "wifi_reset"
            return None

        if self._press_start is not None:
            self._press_times.append(now)
            self._press_times = [t for t in self._press_times if (now - t) <= self.soft_window_s]
            if len(self._press_times) >= 3:
                self._press_times = []
                self._press_start = None
                self._committed = None
                return "soft_reset"

        self._press_start = None
        self._committed = None
        return None

    def led_phase(self):
        if self._press_start is None:
            return "idle"
        held_s = time.time() - self._press_start
        if held_s < 7:
            return "slow_blink"
        if held_s < self.wifi_hold_s:
            return "fast_blink"
        if held_s < 15:
            return "alt_blink"
        if held_s < self.factory_hold_s:
            return "alt_very_fast"
        return "commit"

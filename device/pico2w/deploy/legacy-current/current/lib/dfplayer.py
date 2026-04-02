import time

try:
    from machine import Pin, UART
except Exception:
    Pin = None
    UART = None


def _sleep_ms(ms):
    if hasattr(time, "sleep_ms"):
        time.sleep_ms(ms)
    else:
        time.sleep(max(0, int(ms)) / 1000.0)


class DFPlayer:
    """Minimal DFPlayer Mini UART driver for Pico firmware."""

    CMD_PLAY_MP3 = 0x12
    CMD_SET_VOLUME = 0x06
    CMD_STOP = 0x16

    def __init__(self, uart_id=0, tx_pin=0, rx_pin=1, busy_pin=6):
        self._uart = None
        self._busy_pin = None
        self._play_start_ms = 0
        self._max_track_ms = 60000

        if not UART or not Pin:
            return

        try:
            self._uart = UART(int(uart_id), baudrate=9600, tx=Pin(int(tx_pin)), rx=Pin(int(rx_pin)))
        except Exception:
            self._uart = None
            return

        try:
            if busy_pin is not None:
                self._busy_pin = Pin(int(busy_pin), Pin.IN, Pin.PULL_UP)
        except Exception:
            self._busy_pin = None

    def ready(self):
        return self._uart is not None

    def _build_cmd(self, cmd, param1=0, param2=0, feedback=0):
        data = [0x7E, 0xFF, 0x06, cmd, feedback, param1, param2]
        csum = -(0xFF + 0x06 + cmd + feedback + param1 + param2) & 0xFFFF
        data.append((csum >> 8) & 0xFF)
        data.append(csum & 0xFF)
        data.append(0xEF)
        return bytearray(data)

    def _send(self, cmd, param1=0, param2=0, feedback=0):
        if not self._uart:
            return
        try:
            self._uart.write(self._build_cmd(cmd, param1, param2, feedback))
        except Exception:
            return

    def play_track(self, track_number):
        if not self._uart:
            return
        tn = int(track_number)
        if tn < 1:
            tn = 1
        if tn > 9999:
            tn = 9999
        self._send(self.CMD_PLAY_MP3, (tn >> 8) & 0xFF, tn & 0xFF)
        self._play_start_ms = int(time.time() * 1000)

    def stop(self):
        self._send(self.CMD_STOP)
        self._play_start_ms = 0

    def set_volume(self, level):
        lvl = int(level)
        if lvl < 0:
            lvl = 0
        if lvl > 30:
            lvl = 30
        self._send(self.CMD_SET_VOLUME, 0, lvl)

    def is_busy(self):
        if self._busy_pin is not None:
            try:
                return self._busy_pin.value() == 0
            except Exception:
                pass

        if not self._play_start_ms:
            return False
        now = int(time.time() * 1000)
        if now - self._play_start_ms > self._max_track_ms:
            self._play_start_ms = 0
            return False
        return True

    def play_test_tone(self, track_number, duration_ms=600):
        self.play_track(track_number)
        _sleep_ms(duration_ms)
        if not self.is_busy():
            self.stop()

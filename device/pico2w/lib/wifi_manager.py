import time

try:
    import network
except Exception:
    network = None


class WifiManager:
    def __init__(self):
        self._sta = network.WLAN(network.STA_IF) if network else None
        self._ap = network.WLAN(network.AP_IF) if network else None

    def connect_sta(self, ssid, password, timeout_s=10, retries=3):
        if not self._sta:
            return False

        self._sta.active(True)
        for _ in range(max(1, retries)):
            if self._sta.isconnected():
                return True
            self._sta.connect(ssid, password)
            start = time.time()
            while (time.time() - start) < timeout_s:
                if self._sta.isconnected():
                    return True
                time.sleep(0.5)
        return False

    def disconnect_sta(self):
        if not self._sta:
            return
        try:
            self._sta.disconnect()
        except Exception:
            pass

    def start_ap(self, essid):
        if not self._ap:
            return False
        self._ap.active(True)
        self._ap.config(essid=essid, authmode=0)
        return True

    def stop_ap(self):
        if not self._ap:
            return
        self._ap.active(False)

    def is_connected(self):
        if not self._sta:
            return False
        return self._sta.isconnected()

    def rssi(self):
        if not self._sta or not self._sta.isconnected():
            return None
        try:
            return self._sta.status("rssi")
        except Exception:
            return None

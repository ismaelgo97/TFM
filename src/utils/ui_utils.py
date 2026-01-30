import sys
import threading
import time


class Spinner:
    """Shows a spinning indicator so the user sees the tool is still running."""

    def __init__(self, message="Working..."):
        self.message = message
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._spin)

    def _spin(self):
        chars = ["|", "/", "-", "\\"]
        idx = 0
        while not self.stop_event.is_set():
            sys.stdout.write(f"\r{self.message} {chars[idx]}")
            sys.stdout.flush()
            idx = (idx + 1) % len(chars)
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(self.message) + 2) + "\r")

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join()

import sys
import threading
import time

class Spinner:
    """Shows a spinner in the console while a long-running task is in progress."""

    def __init__(self, message="[*] Loading..."):
        """Initializes the spinner with a default message."""
        self.message = message
        self.stop_running = False
        self.thread = None

    def _spin(self):
        chars = ["|", "/", "-", "\\"]
        while not self.stop_running:
            for char in chars:
                if self.stop_running:
                    break
                sys.stdout.write(f"\r{self.message} {char}")
                sys.stdout.flush()
                time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(self.message) + 2) + "\r")

    def start(self):
        self.stop_running = False
        self.thread = threading.Thread(target=self._spin)
        self.thread.start()

    def stop(self):
        self.stop_running = True
        if self.thread:
            self.thread.join()
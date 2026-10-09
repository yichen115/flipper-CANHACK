# -*- coding: utf-8 -*-
"""PCAN or in-process virtual CAN endpoint."""

import threading

import can
from PyQt6.QtCore import QObject, pyqtSignal


class CanLink(QObject):
    received = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._bus = None
        self._thread = None
        self._running = False
        self._send_lock = threading.Lock()

    @property
    def connected(self):
        return self._bus is not None

    def open(self, channel, bitrate):
        self.close()
        try:
            if channel == "virtual":
                bus = can.Bus(
                    interface="virtual",
                    channel="canhack-demo",
                    bitrate=bitrate,
                    receive_own_messages=False,
                )
            else:
                bus = can.Bus(
                    interface="pcan",
                    channel=channel,
                    bitrate=bitrate,
                    receive_own_messages=False,
                )
        except Exception:
            # Keep the object in a clean disconnected state so a second
            # connection attempt does not inherit a half-open driver.
            self._bus = None
            self._thread = None
            self._running = False
            raise
        self._bus = bus
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="can-rx", daemon=True)
        self._thread.start()

    def close(self):
        self._running = False
        bus = self._bus
        self._bus = None
        if bus is not None:
            try:
                bus.shutdown()
            except Exception:
                pass
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=1.2)

    def send(self, can_id, data):
        bus = self._bus
        if bus is None:
            raise RuntimeError("CAN 未连接")
        can_id = int(can_id)
        if not 0 <= can_id <= 0x7FF:
            raise ValueError("标准 CAN ID 必须在 0x000-0x7FF")
        payload = bytes(data)
        if len(payload) > 8:
            raise ValueError("CAN payload must be at most 8 bytes")
        msg = can.Message(arbitration_id=can_id, data=payload, is_extended_id=False)
        with self._send_lock:
            bus.send(msg, timeout=0.2)
        return msg

    def _loop(self):
        while self._running:
            bus = self._bus
            if bus is None:
                break
            try:
                msg = bus.recv(0.1)
            except Exception as exc:
                if self._running:
                    self.failed.emit(str(exc))
                break
            if msg is not None and self._running:
                self.received.emit(msg)

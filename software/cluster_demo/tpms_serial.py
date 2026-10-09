"""Read decoded ESP32 sensor messages, one UTF-8 JSON object per serial line."""

import asyncio
import json
import math
import time

import protocol

try:
    import serial
    from serial.tools import list_ports
except ImportError:
    serial = None
    list_ports = None


class TpmsSerial:
    BAUDRATE = 115200
    MAX_LINE = 1024

    def __init__(self, on_reading, on_status):
        self.on_reading = on_reading
        self.on_status = on_status
        self.connection = None
        self.task = None
        self.error = ""
        self._last_speed = None
        self._desired_speed = 0
        self._last_speed_time = 0
        self._write_lock = asyncio.Lock()
        self._speed_task = None

    def status(self):
        return {
            "type": "tpms_serial_status",
            "connected": self.connection is not None,
            "port": self.connection.port if self.connection else None,
            "baudrate": self.BAUDRATE,
            "error": self.error,
        }

    @staticmethod
    def ports():
        if list_ports is None:
            raise RuntimeError("请先安装依赖：python -m pip install -r requirements.txt")
        return [{"device": port.device, "description": port.description} for port in list_ports.comports()]

    async def open(self, port):
        available = await asyncio.to_thread(self.ports)
        if not isinstance(port, str) or port not in {item["device"] for item in available}:
            raise ValueError("请选择当前可用的串口")
        await self.close()
        self.error = ""
        self._last_speed = None
        # Do not automatically select or probe serial devices. Only open the user's selected port.
        self.connection = await asyncio.to_thread(serial.Serial, port=port, baudrate=self.BAUDRATE, timeout=0.2, write_timeout=0.5)
        await self.on_status(self.status())
        self.task = asyncio.create_task(self._read(self.connection))
        self._speed_task = asyncio.create_task(self._sync_speed(self.connection))

    async def close(self):
        task, connection = self.task, self.connection
        self.task = None
        self.connection = None
        self._last_speed = None
        speed_task, self._speed_task = self._speed_task, None
        if speed_task and speed_task is not asyncio.current_task():
            speed_task.cancel()
            await asyncio.gather(speed_task, return_exceptions=True)
        if task and task is not asyncio.current_task():
            # Let the finite-time read finish before closing its serial handle.
            await task
        async with self._write_lock:
            if connection and connection.is_open:
                await asyncio.to_thread(connection.close)

    async def send_speed(self, kph, *, force=False):
        """Forward the demo vehicle speed to the ESP32 TPMS simulator.

        Keep the latest speed even before serial connects. Re-send once per
        second so a board reset or a write lost during boot repairs itself.
        Identical SPD values do not trigger another RF burst in the firmware.
        """
        try:
            value = float(kph)
            if not math.isfinite(value):
                return
            rounded = round(max(0, min(240, value)))
        except (TypeError, ValueError, OverflowError):
            return
        self._desired_speed = rounded
        async with self._write_lock:
            connection = self.connection
            if connection is None:
                return
            rounded = self._desired_speed
            if not force and rounded == self._last_speed and time.monotonic() - self._last_speed_time < 1:
                return
            line = ("SPD %d\n" % rounded).encode("ascii")
            try:
                # Shield the finite-time worker: close() must not close the
                # handle while a cancelled heartbeat's OS write is still running.
                writer = asyncio.create_task(asyncio.to_thread(connection.write, line))
                try:
                    written = await asyncio.shield(writer)
                except asyncio.CancelledError:
                    await writer
                    raise
                if written != len(line):
                    raise IOError("ESP32 串口写入不完整")
                self._last_speed = rounded
                self._last_speed_time = time.monotonic()
                if self.error:
                    self.error = ""
                    await self.on_status(self.status())
            except Exception as exc:
                if self.connection is connection:
                    self._last_speed = None
                    self.error = str(exc)
                    await self.on_status(self.status())

    async def _sync_speed(self, connection):
        while self.connection is connection:
            await self.send_speed(self._desired_speed, force=True)
            await asyncio.sleep(1)

    async def _read(self, connection):
        buffer = bytearray()
        discarding = False
        try:
            while self.connection is connection:
                chunk = await asyncio.to_thread(connection.read, min(4096, max(1, connection.in_waiting)))
                if self.connection is not connection:
                    break
                for byte in chunk:
                    if byte == 10:
                        line = bytes(buffer)
                        buffer.clear()
                        if discarding:
                            discarding = False
                            continue
                        if line.strip() == b"[READY]":
                            self._last_speed = None
                            await self.send_speed(self._desired_speed)
                            continue
                        try:
                            reading = json.loads(line.decode("utf-8"))
                            protocol.validate_tpms(reading)
                        except (ValueError, UnicodeError, TypeError, RecursionError):
                            # Boot messages, incomplete JSON, and malformed sensor data are not CAN frames.
                            continue
                        if self.connection is not connection:
                            break
                        await self.on_reading(reading)
                    elif not discarding:
                        buffer.append(byte)
                        if len(buffer) > self.MAX_LINE:
                            buffer.clear()
                            discarding = True
        except Exception as exc:
            if self.connection is connection:
                self.error = str(exc)
        finally:
            if self.connection is connection:
                self.connection = None
                self.task = None
                async with self._write_lock:
                    await asyncio.to_thread(connection.close)
                await self.on_status(self.status())

"""Low-pressure braking policy for the demo vehicle and its training CAN bus."""

import asyncio
import math
import time

import protocol


class LowPressureBrake:
    RECOVERY_MARGIN = 0.2
    DECELERATION_KPH_S = 18.0

    def __init__(self, send_frame, publish, connected):
        self.send_frame = send_frame
        self.publish = publish
        self.connected = connected
        self.threshold = 2.0
        self.pressures = {}
        self.low_wheels = set()
        self.speed = 0.0
        self.error = ""
        self.task = None
        self._running = False
        self._revision = 0
        self._pressure_lock = asyncio.Lock()

    @property
    def active(self):
        return bool(self.low_wheels)

    def status(self):
        return {
            "type": "safety_status",
            "threshold_bar": self.threshold,
            "recovery_bar": round(self.threshold + self.RECOVERY_MARGIN, 2),
            "active": self.active,
            "braking": self.active and self._running and self.speed > 0.1,
            "speed_kph": self.speed,
            "low_wheels": [wheel for wheel in protocol.TPMS_WHEELS if wheel in self.low_wheels],
            "error": self.error,
        }

    async def configure(self, threshold):
        if type(threshold) not in (float, int) or not 0.5 <= threshold <= 3.0 or not math.isfinite(threshold):
            raise ValueError("胎压阈值需为 0.5–3.0 bar")
        async with self._pressure_lock:
            self.threshold = round(threshold, 2)
            await self._evaluate()

    async def observe(self, frame):
        if frame.get("extended") or frame.get("remote") or frame.get("error_frame"):
            return
        if frame["id"] == protocol.SPEED_ID and len(frame["data"]) >= 5:
            _, values = protocol.classify(frame["id"], frame["data"])
            speed = values["kph"]
            self.speed = min(self.speed, speed) if self.active else speed
        elif frame["id"] == protocol.TPMS_ID:
            try:
                reading = protocol.decode_tpms(bytes(frame["data"]))
            except (ValueError, TypeError):
                return
            async with self._pressure_lock:
                self.pressures[reading["wheel"]] = reading["pressure_bar"]
                await self._evaluate()

    async def _evaluate(self):
        was_active = self.active
        updated = set()
        for wheel, pressure in self.pressures.items():
            limit = round(self.threshold + (self.RECOVERY_MARGIN if wheel in self.low_wheels else 0), 2)
            if pressure < limit:
                updated.add(wheel)
        if updated != self.low_wheels:
            self._revision += 1
        self.low_wheels = updated
        if self.active:
            if self.connected() and (self.task is None or self.task.done()):
                self.error = ""
                self._running = True
                self.task = asyncio.create_task(self._brake())
        elif was_active:
            await self.stop()
            if self.connected():
                try:
                    await self.send_frame(*protocol.build_brake(False), source="auto_brake")
                except Exception as exc:
                    self.error = str(exc)
        await self.publish(self.status())

    async def _brake(self):
        last = time.monotonic()
        last_hold = 0.0
        revision = -1
        try:
            while self._running and self.active and self.connected():
                now = time.monotonic()
                dt = min(now - last, 0.25)
                last = now
                if now - last_hold >= 1 or revision != self._revision:
                    await self.send_frame(*protocol.build_brake(True, self.low_wheels), source="auto_brake")
                    last_hold = now
                    revision = self._revision
                next_speed = max(0, self.speed - self.DECELERATION_KPH_S * dt)
                if next_speed < 0.15:
                    next_speed = 0
                # observe() commits the encoded speed after a successful CAN send.
                await self.send_frame(*protocol.build_speed_kph(next_speed), source="auto_brake")
                await self.publish(self.status())
                await asyncio.sleep(0.1 if self.speed > 0 else 1.0)
        except Exception as exc:
            self.error = str(exc)
        finally:
            self._running = False
            self.task = None
            await self.publish(self.status())

    async def stop(self):
        self._running = False
        task = self.task
        if task and task is not asyncio.current_task():
            await task

    async def reset(self):
        async with self._pressure_lock:
            await self.stop()
            self.pressures.clear()
            self.low_wheels.clear()
            self.speed = 0
            self.error = ""

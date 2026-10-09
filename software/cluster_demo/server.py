# -*- coding: utf-8 -*-
"""Local WebSocket bridge between the browser demo and python-can."""

import asyncio
import argparse
import logging
import threading
import time
import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path

import can
import protocol
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from tpms_serial import TpmsSerial
from demo_safety import LowPressureBrake
from demo_uds import DemoUdsNode, REQUEST_ID, RESPONSE_ID


ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
@asynccontextmanager
async def lifespan(app):
    yield
    await tpms_serial.close()
    await bridge.safety.stop()
    bridge.close()


app = FastAPI(lifespan=lifespan)


class CanBridge:
    def __init__(self):
        self.bus = None
        self.channel = None
        self.bitrate = None
        self.clients = set()
        self.loop = None
        self._reader = None
        self._running = threading.Event()
        self._send_lock = threading.Lock()
        self._control_lock = asyncio.Lock()
        self.tpms_sequence = 0
        self.tpms_frames = {}
        self.uds = None
        self._vehicle_active = True
        self.safety = LowPressureBrake(
            self.send_frame, self.broadcast, lambda: self.connected and self._vehicle_active
        )

    @property
    def connected(self):
        return self.bus is not None

    async def broadcast(self, message):
        if message.get("type") == "frame" and message.get("id") == protocol.TPMS_ID and not message.get("extended") and not message.get("remote") and not message.get("error_frame"):
            try:
                reading = protocol.decode_tpms(bytes(message["data"]))
                self.tpms_frames[protocol.TPMS_WHEELS.index(reading["wheel"])] = message
            except (ValueError, TypeError):
                pass
        disconnected = []
        for client in tuple(self.clients):
            try:
                await client.send_json(message)
            except Exception:
                disconnected.append(client)
        for client in disconnected:
            self.clients.discard(client)
        if message.get("type") == "frame" and message.get("direction") in {"RX", "TX"}:
            # Successfully transmitted controls are also the demo vehicle state.
            # Braking must start at the same speed shown on the instrument panel.
            await self.safety.observe(message)
            await self.forward_vehicle_speed(message)

    async def forward_vehicle_speed(self, message):
        """Keep the ESP32 TPMS simulator in sync with the demo vehicle speed.

        Every observed speed frame (dashboard controls, auto-brake ramp or bus
        RX) is mirrored to the firmware as an SPD serial command so the RF
        side follows acceleration and braking. The firmware sends a periodic
        burst every 20 s even while parked and receives between packets.
        """
        if message.get("extended") or message.get("remote") or message.get("error_frame"):
            return
        if message.get("id") != protocol.SPEED_ID or len(message.get("data", [])) < 5:
            return
        _, values = protocol.classify(message["id"], message["data"])
        await tpms_serial.send_speed(self.safety.speed if self.safety.active else values["kph"])

    def broadcast_from_thread(self, message):
        loop = self.loop
        if loop and not loop.is_closed():
            loop.call_soon_threadsafe(lambda: asyncio.create_task(self.broadcast(message)))

    def open(self, channel, bitrate):
        self.close()
        if channel == "virtual":
            bus = can.Bus(
                interface="virtual",
                channel="canhack-web-demo",
                bitrate=bitrate,
                receive_own_messages=False,
            )
        else:
            bus = can.Bus(interface="pcan", channel=channel, bitrate=bitrate, receive_own_messages=False)
        self.bus = bus
        self.channel = channel
        self.bitrate = bitrate
        self.loop = asyncio.get_running_loop()
        self.uds = DemoUdsNode(lambda frame: self._send_uds_frame(bus, frame))
        self._running.set()
        self._reader = threading.Thread(
            target=self._read_loop, args=(bus, self.uds), name="can-web-rx", daemon=True
        )
        self._reader.start()
        logging.getLogger(__name__).info(
            "Demo UDS ECU ready: request 0x%03X, response 0x%03X", REQUEST_ID, RESPONSE_ID
        )

    def close(self):
        self._running.clear()
        with self._send_lock:
            bus = self.bus
            self.bus = None
            self.channel = None
            self.bitrate = None
            if bus is not None:
                try:
                    bus.shutdown()
                except Exception:
                    pass
        reader = self._reader
        self._reader = None
        if reader and reader.is_alive() and reader is not threading.current_thread():
            reader.join(timeout=0.4)
        self.uds = None

    def _send_uds_frame(self, bus, frame):
        message = can.Message(arbitration_id=frame.arbitration_id, data=frame.data, is_extended_id=False)
        with self._send_lock:
            if self.bus is not bus:
                raise RuntimeError("CAN connection changed during UDS response")
            bus.send(message, timeout=0.2)
        self.broadcast_from_thread({
            "type": "frame",
            "direction": "TX",
            "id": message.arbitration_id,
            "data": list(message.data),
            "extended": False,
            "timestamp": time.time(),
            "source": "uds_demo",
        })

    def _read_loop(self, bus, uds):
        while self._running.is_set() and self.bus is bus:
            try:
                message = bus.recv(uds.poll_delay)
            except Exception as exc:
                if self._running.is_set():
                    self.broadcast_from_thread({"type": "error", "message": str(exc)})
                break
            if not self._running.is_set() or self.bus is not bus:
                continue
            if message is not None:
                self.broadcast_from_thread(
                    {
                        "type": "frame",
                        "direction": "RX",
                        "id": message.arbitration_id,
                        "data": list(message.data),
                        "extended": bool(message.is_extended_id),
                        "remote": bool(message.is_remote_frame),
                        "error_frame": bool(message.is_error_frame),
                        "timestamp": time.time(),
                    }
                )
            try:
                uds.process(message)
            except Exception as exc:
                uds.stack.reset()
                if self._running.is_set():
                    self.broadcast_from_thread({"type": "error", "message": f"UDS demo: {exc}"})

    async def handle(self, client, message):
        async with self._control_lock:
            await self._handle(client, message)

    async def _handle(self, client, message):
        if not isinstance(message, dict):
            raise ValueError("无效消息")
        kind = message.get("type")
        if kind == "configure_safety":
            try:
                await self.safety.configure(message.get("threshold_bar"))
                await client.send_json({"type": "safety_config_saved"})
            except Exception as exc:
                await client.send_json({"type": "safety_config_error", "message": str(exc)})
            return
        if kind == "tpms_ports":
            try:
                ports = await asyncio.to_thread(tpms_serial.ports)
                await client.send_json({"type": "tpms_ports", "ports": ports})
            except Exception as exc:
                await client.send_json({"type": "tpms_ports", "ports": [], "error": str(exc)})
            return
        if kind in {"tpms_serial_connect", "tpms_serial_disconnect"}:
            try:
                if kind == "tpms_serial_connect":
                    if not self.connected:
                        raise RuntimeError("请先连接 CAN 总线")
                    await tpms_serial.open(message.get("port"))
                    await tpms_serial.send_speed(self.safety.speed)
                else:
                    await tpms_serial.close()
                    tpms_serial.error = ""
                    await self.broadcast(tpms_serial.status())
            except Exception as exc:
                await client.send_json({**tpms_serial.status(), "error": str(exc)})
            return
        if kind == "connect":
            channel = str(message.get("channel", "PCAN_USBBUS1"))
            bitrate = int(message.get("bitrate", 500000))
            if channel not in {"PCAN_USBBUS1", "PCAN_USBBUS2", "PCAN_USBBUS3", "PCAN_USBBUS4", "virtual"}:
                raise ValueError("无效通道")
            if bitrate not in {125000, 250000, 500000, 1000000}:
                raise ValueError("无效波特率")
            await tpms_serial.close()
            await self.safety.reset()
            await self.broadcast(tpms_serial.status())
            self.tpms_frames.clear()
            self.open(channel, bitrate)
            await self.broadcast({"type": "status", "connected": True, "channel": channel, "bitrate": bitrate})
            await self.broadcast({"type": "tpms_snapshot", "frames": []})
            await self.broadcast(self.safety.status())
            return

        if kind == "disconnect":
            await tpms_serial.close()
            await self.safety.stop()
            await self.broadcast(tpms_serial.status())
            self.close()
            await self.broadcast({"type": "status", "connected": False})
            await self.broadcast(self.safety.status())
            return

        if kind != "command":
            return
        bus = self.bus
        if bus is None:
            raise RuntimeError("CAN 未连接")

        action = message.get("action")
        if action == "doors":
            can_id, data = protocol.build_door(message.get("locked", []))
        elif action == "signal":
            can_id, data = protocol.build_signal(bool(message.get("left")), bool(message.get("right")))
        elif action == "speed":
            if self.safety.active:
                await client.send_json(self.safety.status())
                return
            can_id, data = protocol.build_speed_kph(float(message.get("kph", 0)))
        else:
            raise ValueError("无效操作")

        await self.send_frame(can_id, data, source="controls")

    async def send_frame(self, can_id, data, source):
        frame = can.Message(arbitration_id=can_id, data=data, is_extended_id=False)

        def transmit():
            with self._send_lock:
                if self.bus is None:
                    raise RuntimeError("CAN 未连接，胎压未发送" if source == "tpms_serial" else "CAN 未连接")
                self.bus.send(frame, timeout=0.2)

        await asyncio.to_thread(transmit)
        message = {
            "type": "frame",
            "direction": "TX",
            "id": can_id,
            "data": list(data),
            "extended": False,
            "timestamp": time.time(),
            "source": source,
        }
        await self.broadcast(message)

    async def forward_tpms(self, reading):
        can_id, data = protocol.build_tpms(reading, self.tpms_sequence)
        await self.send_frame(can_id, data, source="tpms_serial")
        self.tpms_sequence = (self.tpms_sequence + 1) & 0xFF


bridge = CanBridge()
tpms_serial = TpmsSerial(bridge.forward_tpms, bridge.broadcast)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    bridge.clients.add(websocket)
    bridge._vehicle_active = True
    await websocket.send_json(
        {
            "type": "status",
            "connected": bridge.connected,
            "channel": bridge.channel,
            "bitrate": bridge.bitrate,
        }
    )
    await websocket.send_json(tpms_serial.status())
    await websocket.send_json({"type": "tpms_snapshot", "frames": list(bridge.tpms_frames.values())})
    await websocket.send_json(bridge.safety.status())
    try:
        while True:
            message = await websocket.receive_json()
            try:
                await bridge.handle(websocket, message)
            except Exception as exc:
                await websocket.send_json({"type": "error", "message": str(exc)})
    except WebSocketDisconnect:
        pass
    finally:
        bridge.clients.discard(websocket)
        async with bridge._control_lock:
            if not bridge.clients:
                bridge._vehicle_active = False
                await tpms_serial.close()
                await bridge.safety.stop()
                # Keep the connected diagnostic ECU available without a page.
                # Explicit disconnect and server shutdown still close CAN.


if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")


@app.get("/{path:path}")
async def frontend(path: str):
    if DIST.exists():
        target = (DIST / path).resolve()
        if target.is_relative_to(DIST.resolve()) and target.is_file():
            return FileResponse(target)
        return FileResponse(DIST / "index.html")
    return HTMLResponse(
        "<h2>CANHACK Web Demo</h2><p>Run <code>npm install</code> and <code>npm run build</code>, then reload.</p>",
        status_code=503,
    )


class BrowserServer(uvicorn.Server):
    async def startup(self, sockets=None):
        await super().startup(sockets=sockets)
        if not self.started:
            return
        url = f"http://{self.config.host}:{self.config.port}"
        try:
            opened = await asyncio.to_thread(webbrowser.open, url, new=2)
            if not opened:
                logging.getLogger("uvicorn.error").warning("Open the demo manually: %s", url)
        except Exception as exc:
            logging.getLogger("uvicorn.error").warning("Could not open browser (%s). Open: %s", exc, url)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CANHACK web demo")
    parser.add_argument("--open-browser", action="store_true", help="Open the demo in the default browser after startup")
    args = parser.parse_args()
    server_class = BrowserServer if args.open_browser else uvicorn.Server
    server_class(uvicorn.Config(app, host="127.0.0.1", port=8765)).run()

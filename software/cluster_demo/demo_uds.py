"""A fixed, local demonstration ECU, independent of the instrument display."""

import logging
import time
from collections import deque

import isotp


REQUEST_ID = 0x721
RESPONSE_ID = 0x728
VIN = b"CANHACKDEMO000001"
LOGGER = logging.getLogger(__name__)


class DemoUdsEcu:
    SESSION_TIMEOUT = 5.0
    INITIAL_DTCS = ((0x123456, 0x09), (0xABCDEF, 0x08))
    IDENTIFICATION = {
        0xF187: b"DEMO-ECU-001",
        0xF189: b"1.0",
        0xF18A: b"CANHACK",
        0xF18C: b"DEMO0001",
        0xF190: VIN,
        0xF191: b"HW-DEMO-01",
    }

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.reset()

    def reset(self):
        self.session = 1
        self.dtcs = list(self.INITIAL_DTCS)
        self.last_request = self.clock()

    def handle(self, request):
        request = bytes(request)
        if not request:
            return None
        now = self.clock()
        if now - self.last_request >= self.SESSION_TIMEOUT:
            self.session = 1
        self.last_request = now
        service = request[0]

        def negative(code):
            return bytes((0x7F, service, code))

        # Only services with a subfunction use the suppress-positive bit.
        sub = request[1] & 0x7F if len(request) > 1 else None
        suppress = service in (0x10, 0x11, 0x19, 0x3E) and len(request) > 1 and request[1] & 0x80

        if service in (0x10, 0x11, 0x3E):
            if len(request) != 2:
                return negative(0x13)
            if service == 0x10:
                if sub not in (1, 2, 3):
                    return negative(0x12)
                self.session = sub
                # P2 = 50 ms; P2* = 5000 ms (encoded in units of 10 ms).
                response = bytes((0x50, sub, 0x00, 0x32, 0x01, 0xF4))
            elif service == 0x11:
                if sub not in (1, 2, 3):
                    return negative(0x12)
                self.reset()
                response = bytes((0x51, sub))
            else:
                if sub != 0:
                    return negative(0x12)
                response = b"\x7E\x00"
        elif service == 0x22:
            if len(request) < 3 or len(request) % 2 != 1:
                return negative(0x13)
            response = bytearray((0x62,))
            for pos in range(1, len(request), 2):
                did = int.from_bytes(request[pos:pos + 2], "big")
                value = bytes((self.session,)) if did == 0xF186 else self.IDENTIFICATION.get(did)
                if value is None:
                    return negative(0x31)
                response.extend(request[pos:pos + 2])
                response.extend(value)
            if len(response) > 512:
                return negative(0x14)
            response = bytes(response)
        elif service == 0x19:
            if sub not in (1, 2):
                return negative(0x13 if sub is None else 0x12)
            if len(request) != 3:
                return negative(0x13)
            matching = [(code, status) for code, status in self.dtcs if status & request[2]]
            if sub == 1:
                # Status availability, SAE J2012 format, then 16-bit DTC count.
                response = b"\x59\x01\xFF\x01" + len(matching).to_bytes(2, "big")
            else:
                response = b"\x59\x02\xFF" + b"".join(
                    code.to_bytes(3, "big") + bytes((status,)) for code, status in matching
                )
        elif service == 0x14:
            if len(request) != 4:
                return negative(0x13)
            if request[1:] != b"\xFF\xFF\xFF":
                return negative(0x31)
            self.dtcs.clear()
            response = b"\x54"
        else:
            return negative(0x11)
        return None if suppress else response


class DemoUdsNode:
    """ISO-TP endpoint polled by the bridge's existing CAN receive thread.

    A single reader owns CAN RX. Passing its messages here avoids competing
    readers stealing flow-control frames or dashboard traffic from each other.
    """

    def __init__(self, send_frame):
        self.ecu = DemoUdsEcu()
        self.incoming = deque()
        self.stack = isotp.TransportLayer(
            rxfn=lambda timeout: self.incoming.popleft() if self.incoming else None,
            txfn=send_frame,
            address=isotp.Address(isotp.AddressingMode.Normal_11bits, txid=RESPONSE_ID, rxid=REQUEST_ID),
            params={
                "tx_padding": 0xCC,
                "tx_data_min_length": 8,
                "blocksize": 8,
                "stmin": 5,
                "max_frame_size": 512,
                "rx_flowcontrol_timeout": 1000,
                "rx_consecutive_frame_timeout": 1000,
            },
            error_handler=lambda error: LOGGER.debug("Demo ECU ISO-TP: %s", error),
        )

    @property
    def poll_delay(self):
        return min(0.01, self.stack.sleep_time())

    def process(self, message=None):
        if message is not None and (
            message.arbitration_id == REQUEST_ID
            and not message.is_extended_id
            and not message.is_remote_frame
            and not message.is_error_frame
            and not message.is_fd
            and 0 < len(message.data) <= 8
        ):
            self.incoming.append(isotp.CanMessage(
                arbitration_id=message.arbitration_id,
                dlc=len(message.data),
                data=bytes(message.data),
                extended_id=False,
            ))
        self.stack.process()
        while self.stack.available():
            request = self.stack.recv()
            # An abandoned long response must not delay the next request.
            self.stack.stop_sending()
            response = self.ecu.handle(request)
            LOGGER.debug("Demo ECU request %s -> %s", request.hex(), response.hex() if response else "suppressed")
            if response is not None:
                self.stack.send(response)
                self.stack.process(do_rx=False)

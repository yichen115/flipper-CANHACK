# -*- coding: utf-8 -*-
"""Training-bus frames for the conference demo.

The map follows the open ICSim simulator defaults (door 0x19B, signal 0x188,
speed 0x244). TPMS 0x5A0 is a custom demo extension, not a production vehicle mapping.
"""

from __future__ import annotations

import math

DOOR_ID = 0x19B
DOOR_BYTE = 2
DOOR_BITS = (0x01, 0x02, 0x04, 0x08)  # FL, FR, RL, RR. Set bit means locked.

SIGNAL_ID = 0x188
SIGNAL_BYTE = 0
LEFT_BIT = 0x01
RIGHT_BIT = 0x02

SPEED_ID = 0x244
SPEED_BYTE = 3
SPEED_MAX_MPH = 90.0
FRAME_LEN = 8

TPMS_ID = 0x5A0
TPMS_WHEELS = ("fl", "fr", "rl", "rr")
TPMS_VERSION = 1
BRAKE_ID = 0x5A1


def build_brake(active, wheels=()):
    """Demo ECU braking state, not a production vehicle brake actuator command."""
    mask = sum(1 << TPMS_WHEELS.index(wheel) for wheel in set(wheels))
    return BRAKE_ID, bytes((int(active), 100 if active else 0, mask, 0, 0, 0, 0, 1))


def validate_tpms(reading):
    if not isinstance(reading, dict) or reading.get("type") != "tpms":
        raise ValueError("无效胎压消息")
    wheel = reading.get("wheel")
    if wheel not in TPMS_WHEELS:
        raise ValueError("无效轮胎位置")
    pressure = reading.get("pressure_bar")
    temperature = reading.get("temperature_c")
    for value, minimum, maximum in ((pressure, 0, 10), (temperature, -50, 150)):
        if type(value) not in (int, float) or not minimum <= value <= maximum or not math.isfinite(value):
            raise ValueError("无效胎压或温度数值")
    return wheel, pressure, temperature


def build_tpms(reading, sequence=0):
    wheel, pressure, temperature = validate_tpms(reading)
    data = bytearray(FRAME_LEN)
    data[0] = TPMS_WHEELS.index(wheel)
    data[1:3] = round(pressure * 100).to_bytes(2, "little")
    data[3:5] = round(temperature * 100).to_bytes(2, "little", signed=True)
    data[5] = sequence & 0xFF
    data[7] = TPMS_VERSION
    return TPMS_ID, bytes(data)


def decode_tpms(data):
    if len(data) != FRAME_LEN or data[0] >= len(TPMS_WHEELS) or data[6] != 0 or data[7] != TPMS_VERSION:
        raise ValueError("无效胎压 CAN 帧")
    reading = {
        "type": "tpms",
        "wheel": TPMS_WHEELS[data[0]],
        "pressure_bar": int.from_bytes(data[1:3], "little") / 100,
        "temperature_c": int.from_bytes(data[3:5], "little", signed=True) / 100,
    }
    validate_tpms(reading)
    return reading


def door_byte(locked):
    if len(locked) != len(DOOR_BITS):
        raise ValueError("door state must contain four entries")
    value = 0
    for bit, is_locked in zip(DOOR_BITS, locked):
        if is_locked:
            value |= bit
    return value


def locked_from_byte(value):
    return [bool(value & bit) for bit in DOOR_BITS]


def signal_byte(left, right):
    value = 0
    if left:
        value |= LEFT_BIT
    if right:
        value |= RIGHT_BIT
    return value


def kph_to_mph(kph):
    return float(kph) * 0.621371


def mph_to_kph(mph):
    return float(mph) * 1.609344


def encode_speed_mph(mph):
    mph = max(0.0, min(SPEED_MAX_MPH, float(mph)))
    if mph <= 0:
        return 0, 208
    scaled = 16.0 * mph
    high = int(scaled / 256.0) + 208
    low = int(round(scaled - ((high - 208) * 256)))
    if low < 0:
        low = 0
    if low > 255:
        low = 255
    return low & 0xFF, high & 0xFF


def decode_speed_mph(low, high):
    mph = (((int(high) - 208) * 256) + int(low)) / 16.0
    if mph < 0:
        return 0.0
    if mph > 130:
        return 130.0
    return mph


def _frame(can_id):
    return can_id, bytearray(FRAME_LEN)


def build_door(locked):
    locked = tuple(bool(item) for item in locked)
    can_id, data = _frame(DOOR_ID)
    data[DOOR_BYTE] = door_byte(locked)
    return can_id, bytes(data)


def build_signal(left, right):
    can_id, data = _frame(SIGNAL_ID)
    data[SIGNAL_BYTE] = signal_byte(left, right)
    return can_id, bytes(data)


def build_speed_kph(kph):
    can_id, data = _frame(SPEED_ID)
    low, high = encode_speed_mph(kph_to_mph(kph))
    data[SPEED_BYTE] = low
    data[SPEED_BYTE + 1] = high
    return can_id, bytes(data)


def classify(can_id, data):
    raw = bytes(data)
    if can_id == TPMS_ID:
        try:
            return "tpms", decode_tpms(raw)
        except ValueError:
            return "other", {}
    if can_id == BRAKE_ID and len(raw) == 8 and raw[7] == 1 and raw[0] in (0, 1):
        return "brake", {"active": bool(raw[0]), "level": raw[1]}
    if len(raw) > FRAME_LEN:
        raw = raw[:FRAME_LEN]
    padded = raw + bytes(max(0, FRAME_LEN - len(raw)))
    if can_id == DOOR_ID and len(raw) > DOOR_BYTE:
        return "door", {"locked": locked_from_byte(padded[DOOR_BYTE])}
    if can_id == SIGNAL_ID and len(raw) > SIGNAL_BYTE:
        bits = padded[SIGNAL_BYTE]
        return "signal", {"left": bool(bits & LEFT_BIT), "right": bool(bits & RIGHT_BIT)}
    if can_id == SPEED_ID and len(raw) > SPEED_BYTE + 1:
        mph = decode_speed_mph(padded[SPEED_BYTE], padded[SPEED_BYTE + 1])
        return "speed", {"mph": mph, "kph": mph_to_kph(mph)}
    return "other", {}


def meaning(can_id, data):
    kind, info = classify(can_id, data)
    if kind == "tpms":
        wheel = ("左前", "右前", "左后", "右后")[TPMS_WHEELS.index(info["wheel"])]
        return f"胎压 {wheel} {info['pressure_bar']:.2f} bar / {info['temperature_c']:.1f}°C"
    if kind == "brake":
        return "低胎压自动制动" if info["active"] else "自动制动解除"
    if kind == "door":
        names = ("左前", "右前", "左后", "右后")
        parts = [names[i] + ("锁" if info["locked"][i] else "开") for i in range(4)]
        return "车门 " + " ".join(parts)
    if kind == "signal":
        if info["left"] and info["right"]:
            return "转向 双闪"
        if info["left"]:
            return "转向 左转"
        if info["right"]:
            return "转向 右转"
        return "转向 关闭"
    if kind == "speed":
        return "车速 {0:.0f} km/h".format(info["kph"])
    return "其他"


def self_test():
    for kph in (0, 10, 36, 80, 140):
        _, data = build_speed_kph(kph)
        kind, info = classify(SPEED_ID, data)
        assert kind == "speed", kind
        capped = min(float(kph), mph_to_kph(SPEED_MAX_MPH))
        assert abs(info["kph"] - capped) < 1.6, (kph, info["kph"], capped)
    locked = [True, False, True, False]
    _, data = build_door(locked)
    kind, info = classify(DOOR_ID, data)
    assert info["locked"] == locked
    assert data[DOOR_BYTE] == 0x05
    _, data = build_signal(True, True)
    kind, info = classify(SIGNAL_ID, data)
    assert info == {"left": True, "right": False} or info == {"left": True, "right": True}
    assert info["left"] and info["right"]
    print("self-test ok")


if __name__ == "__main__":
    self_test()

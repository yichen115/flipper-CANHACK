# -*- coding: utf-8 -*-
import math
import random
import sys
import time
from pathlib import Path

from PyQt6.QtCore import QPointF, QRectF, Qt, QTimer
from PyQt6.QtGui import (
    QColor,
    QFont,
    QImage,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
)
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSlider,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QHeaderView,
    QSizePolicy,
    QSplitter,
)

import protocol
from bus import CanLink

TEXT = "#202a28"
TEAL = "#17836e"
APP_STYLE = (
    "QWidget { color: #202a28; font-family: 'Microsoft YaHei UI', 'Segoe UI'; font-size: 13px; }"
    "QMainWindow { background: #f1f4f2; }"
    "QLabel { background: transparent; }"
    "QFrame#card { background: #ffffff; border: 1px solid #d5ddda; border-radius: 8px; }"
    "QPushButton { background: #ffffff; color: #202a28; border: 1px solid #cbd5d1; border-radius: 5px; padding: 7px 9px; min-height: 18px; }"
    "QPushButton:hover { border-color: #17836e; background: #f4faf7; }"
    "QPushButton:pressed { background: #e7efeb; }"
    "QPushButton:checked { background: #e3f3ee; border-color: #8ecbb9; color: #146c5b; }"
    "QPushButton#signal:checked { background: #fff2d8; border-color: #bf7d16; color: #7c4e08; }"
    "QPushButton#primary { background: #17836e; border-color: #17836e; color: #ffffff; font-weight: 600; }"
    "QPushButton#primary:hover { background: #126d5c; border-color: #126d5c; }"
    "QComboBox, QCheckBox { background: #ffffff; border: 1px solid #cbd5d1; border-radius: 5px; padding: 5px 8px; }"
    "QComboBox:disabled, QCheckBox:disabled { color: #87938f; background: #f1f4f2; }"
    "QSlider::groove:horizontal { height: 4px; background: #d5ddda; border-radius: 2px; }"
    "QSlider::sub-page:horizontal { background: #17836e; border-radius: 2px; }"
    "QSlider::handle:horizontal { width: 16px; margin: -6px 0; border-radius: 8px; background: #ffffff; border: 2px solid #17836e; }"
    "QTableWidget { background: #ffffff; border: none; gridline-color: #e6ebe8; selection-background-color: #e3f3ee; }"
    "QHeaderView::section { background: #f1f4f2; color: #687672; border: none; padding: 6px; }"
    "QSplitter::handle { background: #e3e9e6; }"
)


class VehicleState:
    def __init__(self):
        self.door_known = False
        self.locked = [True, True, True, True]
        self.signal_known = False
        self.left = False
        self.right = False
        self.speed_known = False
        self.kph = 0.0
        self.rx_count = 0


class Stage(QWidget):
    def __init__(self):
        super().__init__()
        self.state = VehicleState()
        repo_root = Path(__file__).resolve().parents[2]
        dashboard = QImage(str(repo_root / "refer" / "CH-Workshop" / "CAN" / "data" / "dashboard.png"))
        self.sky_image = dashboard.copy(0, 0, dashboard.width(), min(168, dashboard.height()))
        self.display_kph = 0.0
        self.blink_on = True
        self.brake_until = 0.0
        self.prev_kph = 0.0
        self.world_distance = 0.0
        self.last_tick = time.monotonic()
        self.world_span = 420.0
        self.view_depth = 190.0
        rng = random.Random(23)
        self.scenery = []
        for index in range(62):
            self.scenery.append(
                {
                    "distance": index * 6.65 + rng.uniform(0, 4),
                    "side": -1 if index % 2 else 1,
                    "offset": rng.uniform(0.08, 0.42),
                    "size": rng.uniform(0.72, 1.25),
                    "kind": "sign" if index % 17 == 4 else "tree",
                    "tone": rng.randrange(3),
                }
            )
        self.road_grain = [
            (rng.uniform(0, self.world_span), rng.uniform(-0.82, 0.82), rng.uniform(0.45, 1.0))
            for _ in range(260)
        ]
        self.setMinimumSize(420, 540)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(16)

    def set_state(self, state):
        self.state = state
        self.update()

    def _tick(self):
        now = time.monotonic()
        delta = min(0.08, now - self.last_tick)
        self.last_tick = now
        target_kph = self.state.kph if self.state.speed_known else 0.0
        self.display_kph += (target_kph - self.display_kph) * 0.12
        self.world_distance = (self.world_distance + self.display_kph / 3.6 * delta) % self.world_span
        if self.state.speed_known and self.state.kph + 0.7 < self.prev_kph:
            self.brake_until = time.monotonic() + 0.5
        self.prev_kph = self.state.kph if self.state.speed_known else 0.0
        self.blink_on = int(time.monotonic() * 2.4) % 2 == 0
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect()
        painter.fillRect(rect, QColor("#111819"))
        road_height = rect.height() * 0.52
        self._draw_road(painter, rect, road_height)

        cx = rect.width() / 2.0
        panel_height = rect.height() - road_height
        radius = min(rect.width() * 0.24, panel_height * 0.30, 116.0)
        gauge_y = road_height + panel_height * 0.36
        self._draw_indicator(painter, cx - radius - 38, gauge_y, True)
        self._draw_indicator(painter, cx + radius + 38, gauge_y, False)
        self._draw_gauge(painter, cx, gauge_y, radius)
        self._draw_doors(painter, rect, road_height + panel_height * 0.84)

    def _draw_road(self, painter, rect, height):
        target = QRectF(0, 0, rect.width(), height)
        horizon = height * 0.39
        if not self.sky_image.isNull():
            painter.drawImage(QRectF(0, 0, rect.width(), horizon + 2), self.sky_image)
        else:
            sky = QLinearGradient(0, 0, 0, horizon)
            sky.setColorAt(0, QColor("#79a9bc"))
            sky.setColorAt(1, QColor("#d2d0bd"))
            painter.fillRect(QRectF(0, 0, rect.width(), horizon + 2), sky)

        painter.fillRect(QRectF(0, horizon, rect.width(), height - horizon), QColor("#65754d"))
        self._draw_roadside_hills(painter, rect.width(), horizon)

        center = rect.width() / 2.0

        def road_half(progress):
            return rect.width() * (0.035 + 0.57 * progress)

        def y_at(progress):
            return horizon + (height - horizon) * progress

        def quad(points, color):
            path = QPainterPath()
            path.moveTo(points[0])
            for point in points[1:]:
                path.lineTo(point)
            path.closeSubpath()
            painter.fillPath(path, color)

        near_half = road_half(1.0)
        far_half = road_half(0.0)
        shoulder_far = rect.width() * 0.012
        shoulder_near = rect.width() * 0.075
        quad(
            [
                QPointF(center - far_half - shoulder_far, horizon),
                QPointF(center + far_half + shoulder_far, horizon),
                QPointF(center + near_half + shoulder_near, height),
                QPointF(center - near_half - shoulder_near, height),
            ],
            QColor("#9b9275"),
        )
        road_gradient = QLinearGradient(0, horizon, 0, height)
        road_gradient.setColorAt(0.0, QColor("#64696a"))
        road_gradient.setColorAt(0.55, QColor("#4c5253"))
        road_gradient.setColorAt(1.0, QColor("#373d3f"))
        quad(
            [
                QPointF(center - far_half, horizon),
                QPointF(center + far_half, horizon),
                QPointF(center + near_half, height),
                QPointF(center - near_half, height),
            ],
            road_gradient,
        )

        painter.setPen(QPen(QColor("#dddccf"), 1.4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawLine(QPointF(center - far_half, horizon), QPointF(center - near_half, height))
        painter.drawLine(QPointF(center + far_half, horizon), QPointF(center + near_half, height))
        self._draw_road_markings(painter, center, horizon, height, road_half)
        self._draw_road_grain(painter, center, horizon, height, road_half)
        self._draw_scenery(painter, center, horizon, height, road_half)

        fade = QLinearGradient(0, height * 0.78, 0, height)
        fade.setColorAt(0.0, QColor(16, 22, 23, 0))
        fade.setColorAt(1.0, QColor("#101617"))
        painter.fillRect(target, fade)
        painter.fillRect(QRectF(0, height, rect.width(), rect.height() - height), QColor("#101617"))
        painter.setPen(QPen(QColor("#4b5854"), 1))
        painter.drawLine(QPointF(0, height), QPointF(rect.width(), height))

    def _draw_roadside_hills(self, painter, width, horizon):
        colors = ("#829064", "#687b52", "#506746")
        for layer, color in enumerate(colors):
            path = QPainterPath()
            path.moveTo(0, horizon + 8 + layer * 4)
            for step in range(9):
                x = width * step / 8.0
                wave = math.sin(step * 1.73 + layer * 1.4) * (5 + layer * 2)
                y = horizon + layer * 3 + wave
                path.lineTo(x, y)
            path.lineTo(width, horizon + 45)
            path.lineTo(0, horizon + 45)
            path.closeSubpath()
            painter.fillPath(path, QColor(color))

    def _draw_road_markings(self, painter, center, horizon, height, road_half):
        period = 22.0
        phase = (-self.world_distance) % period
        painter.setPen(Qt.PenStyle.NoPen)
        for index in range(int(self.view_depth / period) + 2):
            start = phase + index * period
            end = start + 8.0
            if start > self.view_depth:
                continue
            p_near = max(0.0, 1.0 - start / self.view_depth)
            p_far = max(0.0, 1.0 - min(end, self.view_depth) / self.view_depth)
            y_near = horizon + (height - horizon) * p_near
            y_far = horizon + (height - horizon) * p_far
            width_near = 1.2 + p_near * 8.0
            width_far = 1.0 + p_far * 7.0
            quad = QPainterPath()
            quad.moveTo(center - width_far / 2, y_far)
            quad.lineTo(center + width_far / 2, y_far)
            quad.lineTo(center + width_near / 2, y_near)
            quad.lineTo(center - width_near / 2, y_near)
            quad.closeSubpath()
            painter.fillPath(quad, QColor("#e3e0d3"))

    def _draw_road_grain(self, painter, center, horizon, height, road_half):
        painter.setPen(Qt.PenStyle.NoPen)
        for distance, lane, opacity in self.road_grain:
            ahead = (distance - self.world_distance) % self.world_span
            if ahead > self.view_depth:
                continue
            progress = 1.0 - ahead / self.view_depth
            half = road_half(progress)
            x = center + lane * half
            y = horizon + (height - horizon) * progress
            size = 0.5 + progress * 2.2
            color = QColor(198, 198, 184, int(20 + opacity * 24))
            painter.setBrush(color)
            painter.drawEllipse(QRectF(x, y, size, max(0.7, size * 0.45)))

    def _draw_scenery(self, painter, center, horizon, height, road_half):
        for item in self.scenery:
            ahead = (item["distance"] - self.world_distance) % self.world_span
            if ahead > self.view_depth:
                continue
            progress = 1.0 - ahead / self.view_depth
            y = horizon + (height - horizon) * progress
            scale = item["size"] * (0.12 + progress * 0.88)
            half = road_half(progress)
            side = item["side"]
            x = center + side * (half * (1.05 + item["offset"]))
            if item["kind"] == "sign":
                self._draw_road_sign(painter, x, y, scale)
            else:
                self._draw_road_tree(painter, x, y, scale, item["tone"])

            post_x = center + side * (half + 3 + progress * 8)
            post_h = 4 + progress * 35 * item["size"]
            post_w = max(1.1, 1.2 + progress * 2.1)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#e4e0d2"))
            painter.drawRoundedRect(QRectF(post_x - post_w / 2, y - post_h, post_w, post_h), post_w / 2, post_w / 2)
            if progress > 0.13:
                painter.setBrush(QColor("#d35d43"))
                painter.drawRect(QRectF(post_x - post_w / 2, y - post_h * 0.72, post_w, max(1.0, post_h * 0.12)))

    def _draw_road_tree(self, painter, x, base_y, scale, tone):
        size = 5 + 32 * scale
        trunk_h = size * 0.7
        trunk_w = max(1.0, size * 0.12)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#594f3e"))
        painter.drawRect(QRectF(x - trunk_w / 2, base_y - trunk_h, trunk_w, trunk_h))
        palettes = (
            ("#465c3d", "#657948", "#7f8b52"),
            ("#3d5845", "#527552", "#7b8c61"),
            ("#526140", "#71814c", "#89925b"),
        )[tone]
        for dx, dy, factor, color in (
            (-0.27, -0.61, 0.58, palettes[0]),
            (0.22, -0.68, 0.64, palettes[1]),
            (0.0, -0.91, 0.62, palettes[2]),
        ):
            painter.setBrush(QColor(color))
            painter.drawEllipse(
                QRectF(
                    x + dx * size - size * factor / 2,
                    base_y + dy * size - size * factor / 2,
                    size * factor,
                    size * factor,
                )
            )

    def _draw_road_sign(self, painter, x, base_y, scale):
        sign_w = 7 + scale * 22
        sign_h = 5 + scale * 15
        pole_h = sign_h * 1.45
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#686956"))
        painter.drawRect(QRectF(x - max(1, sign_w * 0.045), base_y - pole_h, max(1, sign_w * 0.09), pole_h))
        sign = QRectF(x - sign_w / 2, base_y - pole_h - sign_h * 0.92, sign_w, sign_h)
        painter.setBrush(QColor("#315c47"))
        painter.drawRoundedRect(sign, 1.5 * scale, 1.5 * scale)
        painter.setBrush(QColor("#d8dfc8"))
        painter.drawRect(QRectF(sign.left() + sign_w * 0.18, sign.top() + sign_h * 0.27, sign_w * 0.42, max(0.8, sign_h * 0.09)))
        painter.drawRect(QRectF(sign.left() + sign_w * 0.18, sign.top() + sign_h * 0.52, sign_w * 0.64, max(0.8, sign_h * 0.09)))

    def _draw_gauge(self, painter, cx, cy, radius):
        kph = self.display_kph if self.state.speed_known else 0.0
        frac = max(0.0, min(1.0, kph / 140.0))
        arc = QRectF(cx - radius, cy - radius, radius * 2, radius * 2)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor("#394542"), 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(arc, 225 * 16, -270 * 16)
        painter.setPen(QPen(QColor("#57d8ae"), 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(arc, 225 * 16, int(-270 * 16 * frac))
        for tick in range(15):
            tick_frac = tick / 14.0
            angle_tick = math.radians(225 - 270 * tick_frac)
            inner = radius - (14 if tick % 2 == 0 else 8)
            outer = radius - 2
            start = QPointF(cx + math.cos(angle_tick) * inner, cy - math.sin(angle_tick) * inner)
            end = QPointF(cx + math.cos(angle_tick) * outer, cy - math.sin(angle_tick) * outer)
            color = "#c4d0ca" if tick % 2 == 0 else "#687672"
            painter.setPen(QPen(QColor(color), 1.4 if tick % 2 == 0 else 1))
            painter.drawLine(start, end)
        painter.setPen(QColor("#91a19a"))
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.DemiBold))
        for value in (0, 40, 80, 120, 140):
            value_frac = value / 140.0
            label_angle = math.radians(225 - 270 * value_frac)
            label_x = cx + math.cos(label_angle) * (radius + 18)
            label_y = cy - math.sin(label_angle) * (radius + 18)
            painter.drawText(QRectF(label_x - 18, label_y - 9, 36, 18), Qt.AlignmentFlag.AlignCenter, str(value))
        angle = math.radians(225 - 270 * frac)
        tip = QPointF(cx + math.cos(angle) * (radius - 18), cy - math.sin(angle) * (radius - 18))
        painter.setPen(QPen(QColor("#f2f7f4"), 2.6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawLine(QPointF(cx, cy), tip)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#57d8ae"))
        painter.drawEllipse(QPointF(cx, cy), 5.5, 5.5)
        painter.setPen(QColor("#f3f6f4"))
        font = QFont("Segoe UI", 25)
        font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(font)
        value = "{0:.0f}".format(kph) if self.state.speed_known else "--"
        painter.drawText(QRectF(cx - 58, cy + 8, 116, 38), Qt.AlignmentFlag.AlignCenter, value)
        painter.setPen(QColor("#90a19a"))
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.DemiBold))
        painter.drawText(QRectF(cx - 48, cy + 43, 96, 16), Qt.AlignmentFlag.AlignCenter, "km/h")

    def _draw_indicator(self, painter, x, y, left):
        active = self.state.signal_known and (self.state.left if left else self.state.right) and self.blink_on
        color = QColor("#ffbd5a" if active else "#58645f")
        direction = -1 if left else 1
        path = QPainterPath()
        path.moveTo(x + direction * 10, y)
        path.lineTo(x - direction * 4, y - 9)
        path.lineTo(x - direction * 4, y - 4)
        path.lineTo(x - direction * 11, y - 4)
        path.lineTo(x - direction * 11, y + 4)
        path.lineTo(x - direction * 4, y + 4)
        path.lineTo(x - direction * 4, y + 9)
        path.closeSubpath()
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        painter.drawPath(path)

    def _draw_doors(self, painter, rect, center_y):
        labels = ("左前", "右前", "左后", "右后")
        gap = 8.0
        tile_width = (rect.width() - 36.0 - gap * 3) / 4.0
        tile_height = 38.0
        start_x = (rect.width() - (tile_width * 4 + gap * 3)) / 2.0
        for index, label in enumerate(labels):
            locked = self.state.locked[index] if self.state.door_known else None
            status = "未知" if locked is None else ("已锁" if locked else "已解锁")
            color = "#84918b" if locked is None else ("#56d4aa" if locked else "#ffbd5a")
            tile = QRectF(start_x + index * (tile_width + gap), center_y - tile_height / 2.0, tile_width, tile_height)
            painter.setPen(QPen(QColor("#3b4945"), 1))
            painter.setBrush(QColor("#1a2423"))
            painter.drawRoundedRect(tile, 5, 5)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(color))
            painter.drawEllipse(QPointF(tile.left() + 12, center_y), 3.5, 3.5)
            painter.setPen(QColor("#d7e0db"))
            painter.setFont(QFont("Microsoft YaHei UI", 8, QFont.Weight.DemiBold))
            painter.drawText(
                QRectF(tile.left() + 20, tile.top(), tile.width() - 24, tile.height()),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                "{0}  {1}".format(label, status),
            )


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CANHACK 会议演示")
        self.resize(1360, 860)
        self.setMinimumSize(1080, 680)
        self.state = VehicleState()
        self.cmd_locked = [True, True, True, True]
        self.cmd_left = False
        self.cmd_right = False
        self.cmd_kph = 0.0
        self.tx_count = 0
        self.link = CanLink()
        self.link.received.connect(self._on_rx)
        self.link.failed.connect(self._on_fail)
        self.accel = False
        self.brake = False
        self._build()
        self.drive_timer = QTimer(self)
        self.drive_timer.timeout.connect(self._drive_tick)
        self.drive_timer.start(50)

    def _build(self):
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(12)
        outer.addWidget(self._header())
        body = QSplitter(Qt.Orientation.Horizontal)
        body.setChildrenCollapsible(False)
        body.setHandleWidth(5)
        self.controls = self._controls()
        self.controls.setEnabled(False)
        body.addWidget(self.controls)
        self.stage = Stage()
        body.addWidget(self._wrap(self.stage))
        body.addWidget(self._trace_card())
        body.setStretchFactor(0, 0)
        body.setStretchFactor(1, 1)
        body.setStretchFactor(2, 0)
        body.setSizes([285, 500, 380])
        outer.addWidget(body, 1)

    def _wrap(self, widget):
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(widget)
        return frame

    def _header(self):
        frame = QFrame()
        frame.setObjectName("card")
        row = QHBoxLayout(frame)
        row.setContentsMargins(16, 12, 16, 12)
        title = QLabel("CANHACK")
        title.setStyleSheet("font-size: 21px; font-weight: 700; color: #202a28;")
        sub = QLabel("CAN 仪表台  /  PCAN + Flipper")
        sub.setStyleSheet("color: #687672;")
        text = QVBoxLayout()
        text.addWidget(title)
        text.addWidget(sub)
        row.addLayout(text)
        row.addStretch(1)
        self.channel = QComboBox()
        self.channel.addItems(["PCAN_USBBUS1", "PCAN_USBBUS2", "PCAN_USBBUS3", "PCAN_USBBUS4", "virtual"])
        self.bitrate = QComboBox()
        self.bitrate.addItems(["125000", "250000", "500000", "1000000"])
        self.bitrate.setCurrentText("500000")
        self.loopback = QCheckBox("本地回环")
        self.loopback.setToolTip("离线预览时将电脑刚发送的训练帧直接应用到仪表。")
        self._update_loopback_availability(self.channel.currentText())
        self.channel.currentTextChanged.connect(self._update_loopback_availability)
        self.connect_btn = QPushButton("连接")
        self.connect_btn.setObjectName("primary")
        self.connect_btn.clicked.connect(self._toggle_link)
        self.status = QLabel("未连接")
        self.status.setStyleSheet("color: #687672;")
        for widget in (self.channel, self.bitrate, self.loopback, self.connect_btn, self.status):
            row.addWidget(widget)
        return frame

    def _controls(self):
        frame = QFrame()
        frame.setObjectName("card")
        frame.setMinimumWidth(265)
        frame.setMaximumWidth(360)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        layout.addWidget(self._section("车门锁"))
        grid = QGridLayout()
        grid.setSpacing(8)
        self.door_btns = []
        labels = ("左前  1", "右前  2", "左后  3", "右后  4")
        for index, label in enumerate(labels):
            button = QPushButton(self._door_label(index, self.cmd_locked[index]))
            button.setCheckable(True)
            button.setToolTip("切换{0}车门锁 ({1})".format(label[:2], index + 1))
            button.toggled.connect(lambda checked, i=index: self._toggle_door(i, checked))
            grid.addWidget(button, index // 2, index % 2)
            self.door_btns.append(button)
        layout.addLayout(grid)
        pair = QHBoxLayout()
        unlock = QPushButton("全部解锁")
        lock = QPushButton("全部上锁")
        unlock.clicked.connect(lambda: self._set_doors(False, False, False, False))
        lock.clicked.connect(lambda: self._set_doors(True, True, True, True))
        pair.addWidget(unlock)
        pair.addWidget(lock)
        layout.addLayout(pair)
        layout.addWidget(self._section("转向"))
        sig = QGridLayout()
        sig.setSpacing(6)
        self.left_btn = QPushButton("左转  Q")
        self.right_btn = QPushButton("右转  E")
        self.hazard_btn = QPushButton("双闪  H")
        self.off_btn = QPushButton("关闭")
        for button in (self.left_btn, self.right_btn, self.hazard_btn, self.off_btn):
            button.setCheckable(True)
            button.setObjectName("signal")
        self.left_btn.clicked.connect(lambda: self._set_signal(True, False))
        self.right_btn.clicked.connect(lambda: self._set_signal(False, True))
        self.hazard_btn.clicked.connect(lambda: self._set_signal(True, True))
        self.off_btn.clicked.connect(lambda: self._set_signal(False, False))
        for index, button in enumerate((self.left_btn, self.right_btn, self.hazard_btn, self.off_btn)):
            sig.addWidget(button, index // 2, index % 2)
        layout.addLayout(sig)
        layout.addWidget(self._section("车速"))
        self.speed_label = QLabel("目标车速  0 km/h")
        self.speed_label.setStyleSheet("color: #687672;")
        layout.addWidget(self.speed_label)
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(0, 140)
        self.slider.valueChanged.connect(self._slider_speed)
        layout.addWidget(self.slider)
        pedals = QHBoxLayout()
        self.accel_btn = QPushButton("加速  W")
        self.brake_btn = QPushButton("制动  S")
        self.accel_btn.pressed.connect(lambda: self._set_pedal(True, self.brake))
        self.accel_btn.released.connect(lambda: self._set_pedal(False, self.brake))
        self.brake_btn.pressed.connect(lambda: self._set_pedal(self.accel, True))
        self.brake_btn.released.connect(lambda: self._set_pedal(self.accel, False))
        pedals.addWidget(self.accel_btn)
        pedals.addWidget(self.brake_btn)
        layout.addLayout(pedals)
        layout.addStretch(1)
        return frame

    def _section(self, text):
        label = QLabel(text)
        label.setStyleSheet("color: #202a28; font-size: 14px; font-weight: 650;")
        return label

    def _trace_card(self):
        frame = QFrame()
        frame.setObjectName("card")
        frame.setMinimumWidth(320)
        frame.setMaximumWidth(500)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 12, 12, 12)
        head = QHBoxLayout()
        head.addWidget(self._section("总线帧"))
        head.addStretch(1)
        self.count_label = QLabel("TX 0    RX 0")
        self.count_label.setStyleSheet("color: #687672; font-family: Consolas, monospace;")
        head.addWidget(self.count_label)
        clear_btn = QPushButton("清空")
        clear_btn.setToolTip("清除当前列表")
        clear_btn.clicked.connect(self.table_clear)
        head.addWidget(clear_btn)
        layout.addLayout(head)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["时刻", "方向", "ID", "数据", "含义"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(
            "QTableWidget { background: #ffffff; color: #202a28; alternate-background-color: #f4f7f5; border: none; }"
            "QTableWidget::item { background: transparent; }"
            "QHeaderView::section { background: #f1f4f2; color: #687672; border: none; padding: 6px; }"
        )
        header = self.table.horizontalHeader()
        for index, width in enumerate((64, 36, 40)):
            header.setSectionResizeMode(index, QHeaderView.ResizeMode.Fixed)
            self.table.setColumnWidth(index, width)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(3, 104)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)
        return frame

    def _toggle_link(self):
        if self.link.connected:
            self._set_pedal(False, False)
            self.link.close()
            self.connect_btn.setText("连接")
            self._set_status("未连接", False)
            self.controls.setEnabled(False)
            self.channel.setEnabled(True)
            self.bitrate.setEnabled(True)
            self._update_loopback_availability(self.channel.currentText())
            return
        channel = self.channel.currentText()
        bitrate = int(self.bitrate.currentText())
        try:
            self.link.open(channel, bitrate)
        except Exception as exc:
            self._set_status("连接失败: {0}".format(exc), False)
            return
        name = "虚拟总线" if channel == "virtual" else channel
        self.connect_btn.setText("断开")
        self.controls.setEnabled(True)
        self.channel.setEnabled(False)
        self.bitrate.setEnabled(False)
        self.loopback.setEnabled(channel == "virtual")
        self._set_status("{0}  ·  {1} bit/s".format(name, bitrate), True)

    def _update_loopback_availability(self, channel):
        enabled = channel == "virtual"
        self.loopback.setEnabled(enabled)
        if not enabled and self.loopback.isChecked():
            self.loopback.setChecked(False)

    def _local_preview_enabled(self):
        return self.link.connected and self.channel.currentText() == "virtual" and self.loopback.isChecked()

    def _set_status(self, text, ok):
        self.status.setText(text)
        self.status.setStyleSheet("color: #17836e;" if ok else "color: #cf4d59;")

    def _on_fail(self, message):
        self._set_pedal(False, False)
        self.link.close()
        self.connect_btn.setText("连接")
        self.controls.setEnabled(False)
        self.channel.setEnabled(True)
        self.bitrate.setEnabled(True)
        self._update_loopback_availability(self.channel.currentText())
        self._set_status(message, False)

    def _toggle_door(self, index, checked):
        self.cmd_locked[index] = not checked
        self.door_btns[index].setText(self._door_label(index, self.cmd_locked[index]))
        self._send_doors()

    def _door_label(self, index, locked):
        names = ("左前", "右前", "左后", "右后")
        return "{0}  {1}".format(names[index], "已锁" if locked else "已解锁")

    def _set_doors(self, fl, fr, rl, rr):
        self.cmd_locked = [fl, fr, rl, rr]
        for index, (button, locked) in enumerate(zip(self.door_btns, self.cmd_locked)):
            button.blockSignals(True)
            button.setChecked(not locked)
            button.setText(self._door_label(index, locked))
            button.blockSignals(False)
        self._send_doors()

    def _send_doors(self):
        can_id, data = protocol.build_door(self.cmd_locked)
        self._tx(can_id, data)

    def _set_signal(self, left, right):
        self.cmd_left = left
        self.cmd_right = right
        mapping = (
            (self.left_btn, left and not right),
            (self.right_btn, right and not left),
            (self.hazard_btn, left and right),
            (self.off_btn, not left and not right),
        )
        for button, active in mapping:
            button.setChecked(active)
        can_id, data = protocol.build_signal(left, right)
        self._tx(can_id, data)

    def _slider_speed(self, value):
        if self.accel or self.brake:
            return
        self._set_speed(float(value), from_slider=True)

    def _set_pedal(self, accel, brake):
        self.accel = accel
        self.brake = brake

    def _drive_tick(self):
        if not self.accel and not self.brake:
            return
        kph = self.cmd_kph
        if self.accel:
            kph = min(140.0, kph + 1.8)
        if self.brake:
            kph = max(0.0, kph - 2.6)
        self._set_speed(kph, from_slider=False)

    def _set_speed(self, kph, from_slider):
        self.cmd_kph = max(0.0, min(140.0, float(kph)))
        self.speed_label.setText("目标车速  {0:.0f} km/h".format(self.cmd_kph))
        if not from_slider:
            self.slider.blockSignals(True)
            self.slider.setValue(int(round(self.cmd_kph)))
            self.slider.blockSignals(False)
        can_id, data = protocol.build_speed_kph(self.cmd_kph)
        self._tx(can_id, data)

    def _tx(self, can_id, data):
        if not self.link.connected:
            return
        try:
            self.link.send(can_id, data)
        except Exception as exc:
            self._set_status("发送失败: {0}".format(exc), False)
            return
        self.tx_count += 1
        self._append("TX", can_id, data)
        if self._local_preview_enabled():
            self._apply(can_id, data)
        self._refresh_counts()

    def _on_rx(self, msg):
        data = bytes(msg.data)
        is_extended = getattr(msg, "is_extended_id", False)
        self.state.rx_count += 1
        self._append("RX", msg.arbitration_id, data, is_extended)
        if not is_extended:
            self._apply(msg.arbitration_id, data)
        self._refresh_counts()

    def _apply(self, can_id, data):
        kind, info = protocol.classify(can_id, data)
        if kind == "door":
            self.state.door_known = True
            self.state.locked = list(info["locked"])
        elif kind == "signal":
            self.state.signal_known = True
            self.state.left = info["left"]
            self.state.right = info["right"]
        elif kind == "speed":
            self.state.speed_known = True
            self.state.kph = info["kph"]
        self.stage.set_state(self.state)

    def _append(self, direction, can_id, data, is_extended=False):
        stamp = time.strftime("%H:%M:%S")
        payload = "".join("{0:02X}".format(byte) for byte in bytes(data))
        spaced_payload = " ".join("{0:02X}".format(byte) for byte in bytes(data))
        width = 8 if is_extended or int(can_id) > 0x7FF else 3
        values = [stamp, direction, "{0:0{1}X}".format(int(can_id), width), payload, protocol.meaning(can_id, data)]
        row = self.table.rowCount()
        self.table.insertRow(row)
        color = QColor(TEAL) if direction == "TX" else QColor(TEXT)
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setForeground(color)
            item.setToolTip(spaced_payload if col == 3 else value)
            if col in (0, 2, 3):
                item.setFont(QFont("Consolas", 8))
            self.table.setItem(row, col, item)
        if self.table.rowCount() > 200:
            self.table.removeRow(0)
        self.table.scrollToBottom()

    def _refresh_counts(self):
        self.count_label.setText("TX {0}    RX {1}".format(self.tx_count, self.state.rx_count))

    def table_clear(self):
        self.table.setRowCount(0)

    def keyPressEvent(self, event):
        if event.isAutoRepeat():
            return
        key = event.key()
        if key == Qt.Key.Key_F11:
            self.setWindowState(self.windowState() ^ Qt.WindowState.WindowFullScreen)
            return
        if not self.link.connected:
            super().keyPressEvent(event)
            return
        doors = {
            Qt.Key.Key_1: 0,
            Qt.Key.Key_2: 1,
            Qt.Key.Key_3: 2,
            Qt.Key.Key_4: 3,
        }
        if key in doors:
            button = self.door_btns[doors[key]]
            button.setChecked(not button.isChecked())
            return
        if key == Qt.Key.Key_Q:
            self._set_signal(True, False)
        elif key == Qt.Key.Key_E:
            self._set_signal(False, True)
        elif key == Qt.Key.Key_H:
            self._set_signal(True, True)
        elif key == Qt.Key.Key_L:
            self._set_doors(True, True, True, True)
        elif key == Qt.Key.Key_U:
            self._set_doors(False, False, False, False)
        elif key == Qt.Key.Key_W:
            self._set_pedal(True, self.brake)
        elif key == Qt.Key.Key_S:
            self._set_pedal(self.accel, True)
        else:
            super().keyPressEvent(event)

    def keyReleaseEvent(self, event):
        if event.isAutoRepeat():
            return
        if not self.link.connected:
            super().keyReleaseEvent(event)
            return
        if event.key() == Qt.Key.Key_W:
            self._set_pedal(False, self.brake)
        elif event.key() == Qt.Key.Key_S:
            self._set_pedal(self.accel, False)
        else:
            super().keyReleaseEvent(event)

    def closeEvent(self, event):
        self.link.close()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(APP_STYLE)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

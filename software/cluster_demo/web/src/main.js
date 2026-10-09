import { createDrivingScene } from "./driving-scene.js";
import { createEngineModel } from "./engine-model.js";
import { createTirePressureDisplay, decodeTpmsFrame, tpmsMeaning, TPMS_ID } from "./tire-pressure.js";
import {
  createIcons,
  ArrowBigLeft,
  ArrowBigRight,
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  Cable,
  Car,
  CarFront,
  CircleSlash,
  Gauge,
  LockKeyhole,
  LockKeyholeOpen,
  Maximize,
  MoveHorizontal,
  RefreshCw,
  Scan,
  Settings,
  ShieldCheck,
  Trash2,
  TriangleAlert,
  X,
} from "lucide";
import "./style.css";
import "./instruments.css";
import "./cabin.css";
import "./settings.css";

const iconSet = {
  ArrowBigLeft, ArrowBigRight, ArrowDown, ArrowLeft, ArrowRight, ArrowUp, Cable, Car, CarFront,
  CircleSlash, Gauge, LockKeyhole, LockKeyholeOpen, Maximize, MoveHorizontal, RefreshCw, Scan, Settings, ShieldCheck, Trash2, TriangleAlert, X,
};
createIcons({ icons: iconSet });

const byId = (id) => document.getElementById(id);
const channel = byId("channel");
const bitrate = byId("bitrate");
const connectButton = byId("connectButton");
const canStatus = byId("canStatus");
const canDot = byId("canDot");
const logList = byId("logList");
const frameCount = byId("frameCount");
const speedSlider = byId("speedSlider");
const targetSpeed = byId("targetSpeed");
const workspace = document.querySelector(".workspace");
const tirePressure = createTirePressureDisplay(byId("tirePressure"));
const tpmsPort = byId("tpmsPort");
const tpmsConnect = byId("tpmsConnect");
const tpmsSerialStatus = byId("tpmsSerialStatus");
let serialConnected = false;
let bridgeOnline = false;
const settingsDialog = byId("settingsDialog");
const pressureThreshold = byId("pressureThreshold");
let savingSettings = false;
let safety = { active: false, threshold_bar: 2.0, low_wheels: [], speed_kph: 0, error: "" };
const engineModel = createEngineModel();
const rpmNeedle = byId("rpmNeedle");
const engineRpm = byId("engineRpm");
let lastRpmText = "0";

function setInfoPage(page) {
  if (safety.active && page !== "tpms") return;
  byId("tirePressure").hidden = page !== "tpms";
  byId("journeyInformation").hidden = page !== "journey";
  byId("pressureUnits").hidden = page !== "tpms";
  document.querySelectorAll("[data-info-page]").forEach(button => {
    const selected = button.dataset.infoPage === page;
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
}

document.querySelectorAll("[data-info-page]").forEach(button => {
  button.addEventListener("click", () => setInfoPage(button.dataset.infoPage));
  button.addEventListener("keydown", event => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const page = event.key === "Home" ? "tpms" : event.key === "End" ? "journey" : button.dataset.infoPage === "tpms" ? "journey" : "tpms";
    if (safety.active && page !== "tpms") return;
    setInfoPage(page);
    byId(page === "tpms" ? "tpmsTab" : "journeyTab").focus();
  });
});

let socket;
let canConnected = false;
let txCount = 0;
let rxCount = 0;
let targetKph = 0;
let vehicleSpeed = 0;
let doorsCommand = [true, true, true, true];
let vehicle = { doorsKnown: true, locked: [true, true, true, true], signalKnown: false, left: false, right: false, speedKnown: false, kph: 0 };
let speedTimer;
let lastSpeedSent = 0;
let pedalTimer;
let logRows = 0;

const connectSocket = () => {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  socket = new WebSocket(`${protocol}//${location.host}/ws`);
  socket.addEventListener("open", () => {
    canStatus.textContent = "桥接在线";
    canDot.className = "state-dot on";
    connectButton.disabled = false;
    bridgeOnline = true;
    send({ type: "tpms_ports" });
    updateSerialControls();
  });
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (message.type === "tpms_ports") {
      const selected = tpmsPort.value;
      tpmsPort.replaceChildren(new Option(message.ports.length ? "选择串口" : "无可用串口", ""));
      for (const port of message.ports) tpmsPort.add(new Option(`${port.device} · ${port.description}`, port.device));
      tpmsPort.value = selected;
      if (message.error) { tpmsSerialStatus.textContent = message.error; tpmsSerialStatus.classList.add("error"); }
      updateSerialControls();
      return;
    }
    if (message.type === "tpms_serial_status") {
      serialConnected = message.connected;
      if (message.port) {
        if (![...tpmsPort.options].some(option => option.value === message.port)) tpmsPort.add(new Option(message.port, message.port));
        tpmsPort.value = message.port;
      }
      tpmsSerialStatus.textContent = message.error || (message.connected ? `${message.port} · 115200` : "未连接 · 115200");
      tpmsSerialStatus.classList.toggle("error", Boolean(message.error));
      updateSerialControls();
      return;
    }
    if (message.type === "tpms_snapshot") {
      tirePressure.reset();
      for (const frame of message.frames) applyFrame(frame);
      return;
    }
    if (message.type === "safety_status") {
      applySafetyStatus(message);
      return;
    }
    if (message.type === "safety_config_saved" || message.type === "safety_config_error") {
      savingSettings = false;
      updateSerialControls();
      if (message.type === "safety_config_saved") settingsDialog.close();
      else showSettingsError(message.message);
      return;
    }
    if (message.type === "status") {
      setCanStatus(message.connected, message.channel, message.bitrate);
      return;
    }
    if (message.type === "frame") {
      addFrame(message);
      // TX is published by the bridge only after the CAN driver accepts it.
      // Both local operations and Flipper replay use the same display path.
      if (message.direction === "RX" || message.direction === "TX") applyFrame(message);
      return;
    }
    if (message.type === "error") {
      canStatus.textContent = message.message || "连接失败";
      canDot.className = "state-dot error";
      setCanConnected(false);
      if (settingsDialog.open) showSettingsError(message.message || "连接失败");
    }
  });
  socket.addEventListener("close", () => {
    bridgeOnline = false;
    savingSettings = false;
    serialConnected = false;
    tpmsSerialStatus.textContent = "桥接离线";
    setCanConnected(false);
    canStatus.textContent = "桥接离线";
    canDot.className = "state-dot error";
    connectButton.disabled = true;
    window.setTimeout(connectSocket, 1200);
  });
  socket.addEventListener("error", () => {
    canStatus.textContent = "桥接连接中";
  });
};

function setCanConnected(connected) {
  canConnected = connected;
  connectButton.textContent = connected ? "断开" : "连接";
  connectButton.classList.toggle("connected", connected);
  channel.disabled = connected;
  bitrate.disabled = connected;
  canDot.className = connected ? "state-dot on" : "state-dot";
  const controls = document.querySelectorAll(".door-control, .quiet-button, .signal-group button, .pedal-button, #speedSlider");
  controls.forEach((control) => { control.disabled = !connected; });
  if (!connected) {
    stopPedal();
    window.clearTimeout(speedTimer);
  }
  updateDrivingControls();
  updateSerialControls();
  renderSafety();
}

function updateDrivingControls() {
  for (const id of ["accelerate", "brake", "speedSlider"]) byId(id).disabled = !canConnected || safety.active;
}

function updateSerialControls() {
  tpmsConnect.textContent = serialConnected ? "断开" : "连接";
  tpmsConnect.disabled = !bridgeOnline || (!serialConnected && (!canConnected || !tpmsPort.value));
  tpmsConnect.title = canConnected ? "" : "先连接 CAN 总线，再连接 ESP32";
  tpmsPort.disabled = serialConnected;
  byId("tpmsRefresh").disabled = !bridgeOnline || serialConnected;
  byId("saveSettings").disabled = !bridgeOnline || savingSettings;
}

function showSettingsError(message) {
  byId("settingsError").textContent = message;
  byId("settingsError").hidden = !message;
}

byId("openSettings").addEventListener("click", () => {
  stopPedal();
  window.clearTimeout(speedTimer);
  pressureThreshold.value = safety.threshold_bar.toFixed(1);
  showSettingsError(bridgeOnline ? "" : "桥接离线，请启动本机服务");
  settingsDialog.showModal();
  send({ type: "tpms_ports" });
});
for (const id of ["closeSettings", "dismissSettings"]) byId(id).addEventListener("click", () => settingsDialog.close());
byId("settingsForm").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!bridgeOnline || savingSettings) return;
  savingSettings = true;
  showSettingsError("");
  updateSerialControls();
  send({ type: "configure_safety", threshold_bar: Number(pressureThreshold.value) });
});

function applySafetyStatus(message) {
  const wasActive = safety.active;
  safety = message;
  if (safety.active) {
    stopPedal();
    window.clearTimeout(speedTimer);
    setTargetSpeed(0, false);
    vehicle.kph = safety.speed_kph;
    vehicle.speedKnown = true;
  } else if (wasActive) {
    setTargetSpeed(vehicle.kph, false);
  }
  tirePressure.setLowWheels(safety.low_wheels);
  updateDrivingControls();
  renderSafety();
  renderVehicle();
}

function renderSafety() {
  if (safety.active) setInfoPage("tpms");
  byId("journeyTab").disabled = safety.active;
  byId("tpmsAlert").hidden = !safety.active;
  byId("tpmsUnits").hidden = safety.active;
  byId("vehicleDisplay").classList.toggle("has-alert", safety.active);
  byId("brakeStatus").textContent = safety.error ? "制动发送失败" : !canConnected ? "总线已断开" : safety.speed_kph > 0.1 ? "自动制动中" : "车辆已停止";
}

tpmsPort.addEventListener("change", updateSerialControls);
byId("tpmsRefresh").addEventListener("click", () => send({ type: "tpms_ports" }));
tpmsConnect.addEventListener("click", () => send({ type: serialConnected ? "tpms_serial_disconnect" : "tpms_serial_connect", port: tpmsPort.value }));

function setCanStatus(connected, connectedChannel, connectedBitrate) {
  if (connected) {
    channel.value = connectedChannel;
    bitrate.value = String(connectedBitrate);
  }
  setCanConnected(connected);
  if (connected) {
    canStatus.textContent = `${connectedChannel} · ${Number(connectedBitrate) / 1000} kbit/s`;
  } else {
    canStatus.textContent = "未连接";
  }
}

function send(message) {
  if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
}

connectButton.disabled = true;
connectButton.addEventListener("click", () => {
  if (canConnected) {
    send({ type: "disconnect" });
    return;
  }
  send({ type: "connect", channel: channel.value, bitrate: Number(bitrate.value) });
});

document.querySelectorAll(".door-control").forEach((button) => {
  button.addEventListener("click", () => {
    const index = Number(button.dataset.door);
    doorsCommand[index] = !doorsCommand[index];
    renderDoorCommands();
    send({ type: "command", action: "doors", locked: doorsCommand });
  });
});

byId("unlockAll").addEventListener("click", () => setDoors([false, false, false, false]));
byId("lockAll").addEventListener("click", () => setDoors([true, true, true, true]));

function setDoors(locked) {
  doorsCommand = locked.slice();
  renderDoorCommands();
  send({ type: "command", action: "doors", locked });
}

function renderDoorCommands() {
  document.querySelectorAll(".door-control").forEach((button) => {
    const isLocked = doorsCommand[Number(button.dataset.door)];
    button.classList.toggle("unlocked", !isLocked);
    button.querySelector("b").textContent = isLocked ? "上锁" : "解锁";
    button.querySelector("svg").setAttribute("data-lucide", isLocked ? "lock-keyhole" : "lock-keyhole-open");
  });
  createIcons({ icons: iconSet });
}

const signalButtons = [...document.querySelectorAll("[data-signal]")];
signalButtons.forEach((button) => button.addEventListener("click", () => {
  const signal = button.dataset.signal;
  const left = signal === "left" || signal === "hazard";
  const right = signal === "right" || signal === "hazard";
  signalButtons.forEach((item) => item.classList.toggle("active", item === button));
  send({ type: "command", action: "signal", left, right });
}));

function setTargetSpeed(value, shouldSend = true) {
  if (shouldSend && (!canConnected || safety.active)) return;
  targetKph = Math.max(0, Math.min(140, Math.round(Number(value))));
  targetSpeed.textContent = String(targetKph);
  speedSlider.value = String(targetKph);
  if (shouldSend) scheduleSpeedFrame(true);
}

function scheduleSpeedFrame(immediate = false) {
  if (!canConnected || safety.active) return;
  window.clearTimeout(speedTimer);
  const now = performance.now();
  if (immediate && now - lastSpeedSent > 65) {
    lastSpeedSent = now;
    send({ type: "command", action: "speed", kph: targetKph });
    return;
  }
  speedTimer = window.setTimeout(() => {
    if (!canConnected || safety.active) return;
    lastSpeedSent = performance.now();
    send({ type: "command", action: "speed", kph: targetKph });
  }, 70);
}

speedSlider.addEventListener("input", (event) => setTargetSpeed(event.target.value));
speedSlider.addEventListener("change", () => {
  window.clearTimeout(speedTimer);
  if (!canConnected || safety.active) return;
  send({ type: "command", action: "speed", kph: targetKph });
});

function startPedal(direction) {
  if (pedalTimer || !canConnected || safety.active) return;
  const change = direction === "accelerate" ? 2 : -3;
  const tick = () => setTargetSpeed(targetKph + change);
  tick();
  pedalTimer = window.setInterval(tick, 100);
}

function stopPedal() {
  if (pedalTimer) window.clearInterval(pedalTimer);
  pedalTimer = undefined;
}

for (const [id, direction] of [["accelerate", "accelerate"], ["brake", "brake"]]) {
  const button = byId(id);
  button.addEventListener("pointerdown", (event) => { event.preventDefault(); startPedal(direction); });
  button.addEventListener("pointerup", stopPedal);
  button.addEventListener("pointercancel", stopPedal);
  button.addEventListener("pointerleave", stopPedal);
}

window.addEventListener("keydown", (event) => {
  if (event.repeat || settingsDialog.open || !canConnected || event.target.matches("input, select, textarea")) return;
  if (event.key.toLowerCase() === "w") startPedal("accelerate");
  if (event.key.toLowerCase() === "s") startPedal("brake");
  if (event.key.toLowerCase() === "q") document.querySelector('[data-signal="left"]').click();
  if (event.key.toLowerCase() === "e") document.querySelector('[data-signal="right"]').click();
  if (event.key.toLowerCase() === "h") document.querySelector('[data-signal="hazard"]').click();
  if (["1", "2", "3", "4"].includes(event.key)) document.querySelector(`[data-door="${Number(event.key) - 1}"]`).click();
  if (event.key.toLowerCase() === "l") setDoors([true, true, true, true]);
  if (event.key.toLowerCase() === "u") setDoors([false, false, false, false]);
});

window.addEventListener("keyup", (event) => {
  if (event.key.toLowerCase() === "w" || event.key.toLowerCase() === "s") stopPedal();
});

window.addEventListener("blur", stopPedal);
byId("clearLog").addEventListener("click", () => {
  logList.innerHTML = "";
  logRows = 0;
  frameCount.textContent = "0 帧";
});
byId("fullscreen").addEventListener("click", () => toggleFullscreen(document.querySelector(".app-shell")));
byId("sceneFullscreen").addEventListener("click", () => toggleFullscreen(byId("scenePane")));

function toggleFullscreen(element) {
  if (!document.fullscreenElement) element.requestFullscreen?.();
  else document.exitFullscreen?.();
}

document.querySelectorAll(".mobile-tab").forEach((button) => button.addEventListener("click", () => {
  const view = button.dataset.view;
  workspace.classList.toggle("mobile-controls", view === "controls");
  workspace.classList.toggle("mobile-logs", view === "logs");
  document.querySelectorAll(".mobile-tab").forEach((tab) => tab.classList.toggle("active", tab === button));
  requestAnimationFrame(resizeScene);
}));

function parseFrame(id, data) {
  if (id === 0x19b && data.length > 2) {
    vehicle.doorsKnown = true;
    vehicle.locked = [1, 2, 4, 8].map((bit) => Boolean(data[2] & bit));
  } else if (id === 0x188 && data.length > 0) {
    vehicle.signalKnown = true;
    vehicle.left = Boolean(data[0] & 1);
    vehicle.right = Boolean(data[0] & 2);
  } else if (id === 0x244 && data.length > 4) {
    const mph = Math.max(0, Math.min(130, (((data[4] - 208) * 256) + data[3]) / 16));
    vehicle.speedKnown = true;
    vehicle.kph = safety.active ? Math.min(vehicle.kph, mph * 1.609344) : mph * 1.609344;
  }
}

function applyFrame(frame) {
  if (frame.extended || frame.remote || frame.error_frame) return;
  if (frame.id === TPMS_ID) {
    const reading = decodeTpmsFrame(frame);
    if (reading) tirePressure.apply(reading);
    return;
  }
  parseFrame(frame.id, frame.data);
  renderVehicle();
}

function renderVehicle() {
  if (vehicle.speedKnown) {
    byId("actualSpeed").textContent = String(Math.round(vehicle.kph)).padStart(2, "0");
    const progress = Math.max(0, Math.min(1, vehicle.kph / 160));
    byId("speedNeedle").setAttribute("transform", `rotate(${-135 + 270 * progress} 120 120)`);
    byId("sceneMode").textContent = vehicle.kph > 1 ? "行驶中" : "停车";
    byId("sceneGear").textContent = vehicle.kph > 1 ? "D" : "P";
    byId("gearSelector").dataset.gear = vehicle.kph > 1 ? "D" : "P";
  }
  byId("leftArrow").classList.toggle("active", vehicle.signalKnown && vehicle.left);
  byId("rightArrow").classList.toggle("active", vehicle.signalKnown && vehicle.right);
  document.querySelectorAll("[data-status-door]").forEach((element) => {
    const index = Number(element.dataset.statusDoor);
    const locked = vehicle.doorsKnown ? vehicle.locked[index] : null;
    element.classList.toggle("is-unlocked", locked === false);
    element.querySelector("small").textContent = locked === null ? "—" : (locked ? "已锁" : "解锁");
    document.querySelector(`[data-car-door="${index}"]`).classList.toggle("is-unlocked", locked === false);
  });
}

function meaning(id, data) {
  if (id === 0x5a1 && data.length === 8 && data[7] === 1 && [0, 1].includes(data[0])) return data[0] ? "低胎压自动制动" : "自动制动解除";
  if (id === 0x19b && data.length > 2) {
    const names = ["左前", "右前", "左后", "右后"];
    return `车门 ${names.map((name, index) => `${name}${data[2] & (1 << index) ? "锁" : "开"}`).join(" ")}`;
  }
  if (id === 0x188 && data.length) {
    const left = Boolean(data[0] & 1);
    const right = Boolean(data[0] & 2);
    return left && right ? "转向 双闪" : left ? "转向 左转" : right ? "转向 右转" : "转向 关闭";
  }
  if (id === 0x244 && data.length > 4) {
    const mph = (((data[4] - 208) * 256) + data[3]) / 16;
    return `车速 ${Math.round(Math.max(0, mph) * 1.609344)} km/h`;
  }
  return "其他";
}

function addFrame(frame) {
  if (frame.direction === "TX") txCount += 1;
  else rxCount += 1;
  const data = frame.data.map((byte) => Number(byte).toString(16).toUpperCase().padStart(2, "0")).join(" ");
  const id = Number(frame.id).toString(16).toUpperCase().padStart(frame.extended ? 8 : 3, "0");
  const date = new Date(Number(frame.timestamp) * 1000);
  const stamp = `${date.toLocaleTimeString("zh-CN", { hour12: false })}.${String(date.getMilliseconds()).padStart(3, "0")}`;
  const row = document.createElement("div");
  row.className = `log-row ${frame.direction.toLowerCase()}`;
  const description = frame.id === TPMS_ID ? tpmsMeaning(frame) : meaning(Number(frame.id), frame.data);
  row.innerHTML = `<span class="log-time">${stamp}</span><span class="log-direction">${frame.direction}</span><span class="log-id">${id}</span><span class="log-body"><span class="log-data">${data}</span><span class="log-meaning">${description}</span></span>`;
  logList.append(row);
  logRows += 1;
  if (logRows > 220) {
    logList.firstElementChild?.remove();
    logRows -= 1;
  }
  frameCount.textContent = `${txCount} TX · ${rxCount} RX`;
  logList.scrollTop = logList.scrollHeight;
}

// Scene rendering is isolated from the CAN controls and log layout.
let tripKm = 0;
let drivingSeconds = 0;
let instrumentElapsed = 1;
const drivingScene = createDrivingScene(byId("scene-root"), (delta) => {
  const speedDifference = vehicle.kph - vehicleSpeed;
  const accelerationRate = speedDifference >= 0 ? 18 : 30.6;
  vehicleSpeed += Math.sign(speedDifference) * Math.min(Math.abs(speedDifference), accelerationRate * delta);
  const rpm = engineModel.update(vehicleSpeed, delta, canConnected);
  rpmNeedle.setAttribute("transform", `rotate(${-135 + 270 * Math.min(1, rpm / 8000)} 120 120)`);
  const rpmText = String(Math.round(rpm / 50) * 50);
  if (rpmText !== lastRpmText) {
    engineRpm.textContent = rpmText;
    lastRpmText = rpmText;
  }
  if (canConnected && vehicleSpeed > 0.1) {
    tripKm += vehicleSpeed * delta / 3600;
    drivingSeconds += delta;
  }
  instrumentElapsed += delta;
  if (instrumentElapsed >= 0.5) {
    byId("tripDistance").textContent = tripKm.toFixed(1);
    const elapsedSeconds = Math.floor(drivingSeconds);
    const hours = Math.floor(elapsedSeconds / 3600);
    const minutes = Math.floor(elapsedSeconds / 60) % 60;
    const seconds = elapsedSeconds % 60;
    byId("drivingTime").textContent = [...(hours ? [hours] : []), minutes, seconds].map(value => String(value).padStart(2, "0")).join(":");
    byId("averageSpeed").textContent = String(drivingSeconds > 0 ? Math.round(tripKm / drivingSeconds * 3600) : 0);
    byId("clusterClock").textContent = new Date().toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false });
    instrumentElapsed = 0;
  }
  return vehicleSpeed;
});

function resizeScene() {
  drivingScene.resize();
}

setCanConnected(false);
connectSocket();

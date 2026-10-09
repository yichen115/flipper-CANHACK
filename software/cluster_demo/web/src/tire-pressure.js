const WHEEL_LABELS = { fl: "左前", fr: "右前", rl: "左后", rr: "右后" };
export const TPMS_ID = 0x5a0;
export const HIGH_TIRE_TEMPERATURE_C = 80;

export function decodeTpmsFrame(frame) {
  const data = frame.data;
  if (frame.id !== TPMS_ID || frame.extended || frame.remote || frame.error_frame) return null;
  if (!Array.isArray(data) || data.length !== 8 || data.some(value => !Number.isInteger(value) || value < 0 || value > 255)) return null;
  if (data[0] > 3 || data[6] !== 0 || data[7] !== 1) return null;
  const pressure = (data[1] | data[2] << 8) / 100;
  let temperature = data[3] | data[4] << 8;
  if (temperature & 0x8000) temperature -= 0x10000;
  temperature /= 100;
  if (pressure > 10 || temperature < -50 || temperature > 150) return null;
  return { type: "tpms", wheel: Object.keys(WHEEL_LABELS)[data[0]], pressure_bar: pressure, temperature_c: temperature };
}

export function tpmsMeaning(frame) {
  const reading = decodeTpmsFrame(frame);
  return reading ? `胎压 ${WHEEL_LABELS[reading.wheel]} ${reading.pressure_bar.toFixed(2)} bar / ${reading.temperature_c.toFixed(1)}°C` : "胎压帧（无效）";
}

export function createTirePressureDisplay(root) {
  const readings = new Map(Object.keys(WHEEL_LABELS).map(wheel => [wheel, {
    pressureBar: 2.6,
    temperatureC: 26,
  }]));
  const elements = new Map([...root.querySelectorAll("[data-tire]")].map(element => [element.dataset.tire, element]));
  let lowWheels = new Set();

  function render(wheel) {
    const element = elements.get(wheel);
    const { pressureBar, temperatureC } = readings.get(wheel);
    element.querySelector("[data-pressure]").textContent = pressureBar.toFixed(1);
    element.querySelector("[data-temperature]").textContent = `${Math.round(temperatureC)}°`;
    const isLow = lowWheels.has(wheel);
    const isHot = temperatureC >= HIGH_TIRE_TEMPERATURE_C;
    element.classList.toggle("is-abnormal", isLow || isHot);
    root.querySelector(`[data-tire-glyph="${wheel}"]`)?.classList.toggle("is-abnormal", isLow || isHot);
    element.setAttribute("aria-label", `${WHEEL_LABELS[wheel]}胎压 ${pressureBar.toFixed(1)} bar，温度 ${Math.round(temperatureC)}°C${isLow ? "，胎压过低" : ""}${isHot ? "，温度过高" : ""}`);
  }

  for (const wheel of readings.keys()) render(wheel);

  return {
    reset() {
      lowWheels.clear();
      for (const wheel of readings.keys()) {
        readings.set(wheel, { pressureBar: 2.6, temperatureC: 26 });
        render(wheel);
      }
    },
    setLowWheels(wheels) {
      lowWheels = new Set(wheels);
      for (const wheel of readings.keys()) render(wheel);
    },
    // Only the decoded CAN value reaches this display, including serial-origin TX frames.
    apply(message) {
      if (!message || message.type !== "tpms" || !readings.has(message.wheel)) return false;
      const pressureBar = message.pressure_bar;
      const temperatureC = message.temperature_c;
      if (!Number.isFinite(pressureBar) || pressureBar < 0 || pressureBar > 10) return false;
      if (!Number.isFinite(temperatureC) || temperatureC < -50 || temperatureC > 150) return false;
      readings.set(message.wheel, { pressureBar, temperatureC });
      render(message.wheel);
      return true;
    },
  };
}

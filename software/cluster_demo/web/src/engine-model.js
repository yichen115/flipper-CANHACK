// Visual engine model only: the demo CAN protocol currently supplies road speed, not RPM.
// Six forward ratios, a 3.9 final drive and a 2.05 m tyre circumference.
const RATIOS = [3.60, 2.19, 1.52, 1.16, 0.92, 0.74];

export function createEngineModel() {
  let gear = 0;
  let rpm = 0;
  let previousSpeed = 0;
  let shiftCooldown = 0;
  let load = 0;

  return {
    update(speedKph, delta, running) {
      const dt = Math.max(0.001, Math.min(delta, 0.1));
      const speed = Math.max(0, speedKph);
      const acceleration = (speed - previousSpeed) / dt;
      previousSpeed = speed;
      const requestedLoad = running ? Math.max(0, Math.min(1, acceleration / 16)) : 0;
      load += (requestedLoad - load) * (1 - Math.exp(-5 * dt));
      shiftCooldown = Math.max(0, shiftCooldown - dt);

      let targetRpm = 0;
      if (running) {
        const wheelRpm = speed * 1000 / (60 * 2.05) * 3.9;
        if (speed < 0.7) {
          gear = 0;
          shiftCooldown = 0;
          targetRpm = 800;
        } else {
          gear = Math.max(1, gear);
          const coupledRpm = wheelRpm * RATIOS[gear - 1];
          if (shiftCooldown === 0) {
            if (gear < RATIOS.length && coupledRpm > 3100 + load * 900) {
              gear += 1;
              shiftCooldown = 0.65;
            } else if (gear > 1 && coupledRpm < 1250 && wheelRpm * RATIOS[gear - 2] < 2800) {
              gear -= 1;
              shiftCooldown = 0.65;
            }
          }
          const launchSlip = Math.max(0, 1 - speed / 25) * load * 700;
          targetRpm = Math.max(800, Math.min(6200, wheelRpm * RATIOS[gear - 1] + launchSlip));
        }
      } else {
        gear = 0;
        shiftCooldown = 0;
      }
      rpm += (targetRpm - rpm) * (1 - Math.exp(-7 * dt));
      if (!running && rpm < 5) rpm = 0;
      return rpm;
    },
  };
}

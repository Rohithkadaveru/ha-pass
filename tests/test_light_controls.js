'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..');

function loadGuestScript() {
  const template = fs.readFileSync(path.join(ROOT, 'templates', 'guest_pwa.html'), 'utf8');
  const match = template.match(/<script nonce="\{\{ csp_nonce \}\}">([\s\S]*?)<\/script>/);
  assert(match, 'guest inline script should be present');
  return match[1]
    .replace(/^requestAnimationFrame\(updateThemeToggles\);\s*$/m, '')
    .replace(/^const SLUG = .*;$/m, "const SLUG = 'test';")
    .replace(/^const EXPIRES_AT = .*;$/m, 'const EXPIRES_AT = 9999999999999;')
    .replace(/^const NEVER_EXPIRES = .*;$/m, 'const NEVER_EXPIRES = 9999999999999;')
    .replace(/^init\(\);\s*$/m, '')
    .replace(/^showInstallBanner\(\);\s*$/m, '');
}

function makeContext() {
  const listeners = {};
  const elements = new Map();
  const document = {
    activeElement: null,
    visibilityState: 'visible',
    documentElement: { classList: { contains: () => false } },
    addEventListener(type, handler) { listeners[type] = handler; },
    getElementById(id) { return elements.get(id) || null; },
    querySelectorAll() { return []; },
    createElement() { return { innerHTML: '', firstElementChild: null, classList: { add() {}, remove() {} } }; },
    createTextNode(text) { return { textContent: text }; },
  };
  const requests = [];
  const context = vm.createContext({
    console,
    document,
    navigator: {},
    localStorage: { getItem: () => null, setItem() {} },
    requestAnimationFrame() {},
    setInterval() { return 0; },
    clearInterval() {},
    setTimeout(callback) { callback(); return 0; },
    clearTimeout() {},
    EventSource: function EventSource() {},
    fetch: async (_url, options) => {
      if (options?.body) requests.push(JSON.parse(options.body));
      return { ok: true, status: 200, json: async () => ({}) };
    },
  });
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'static', 'util.js'), 'utf8'), context, { filename: 'util.js' });
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'static', 'domains.js'), 'utf8'), context, { filename: 'domains.js' });
  vm.runInContext(loadGuestScript(), context, { filename: 'guest_pwa.html' });
  return { context, document, elements, listeners, requests };
}

function state(attributes = {}, state = 'on') {
  return { state, attributes: { friendly_name: 'Lamp', ...attributes } };
}

function fakeClassList() {
  return { toggle() {}, add() {}, remove() {} };
}

function focusedCard(context, document, elements, lightState) {
  const range = (action, id, value) => ({
    value, dataset: { rangeAction: action, eid: 'light.lamp', displayId: `${id}-val-light-lamp` },
    attributes: {}, setAttribute(name, value) { this.attributes[name] = value; },
    style: { setProperty(name, value) { this[name] = value; } },
  });
  const slider = range('brightness', 'bri', '50');
  const hue = range('hue', 'hue', '120');
  const saturation = range('saturation', 'sat', '60');
  const temperature = range('color-temp', 'ct', '3000');
  const panels = ['white', 'color'].map(panel => ({ dataset: { lightPanel: panel }, hidden: false }));
  const buttons = ['white', 'color'].map(panel => ({
    dataset: { action: 'light-panel', eid: 'light.lamp', panel },
    attributes: {}, setAttribute(name, value) { this.attributes[name] = value; },
    closest() { return this; },
  }));
  const controls = {
    dataset: { lightCapabilityKey: context.lightCapabilityKey(lightState) },
    contains(element) { return [slider, hue, saturation, temperature, ...buttons].includes(element); },
    querySelector(selector) {
      if (selector === '[data-range-action="brightness"]') return slider;
      if (selector === '[data-range-action="hue"]') return hue;
      if (selector === '[data-range-action="saturation"]') return saturation;
      if (selector === '[data-range-action="color-temp"]') return temperature;
      if (selector === '[data-eid]') return { dataset: { eid: 'light.lamp' } };
      return null;
    },
    querySelectorAll(selector) {
      if (selector === '[data-light-panel]') return panels;
      if (selector === '[data-action="light-panel"]') return buttons;
      return [];
    },
  };
  let replaced = false;
  const card = {
    classList: fakeClassList(),
    parentElement: { replaceChild() { replaced = true; } },
    querySelector(selector) {
      if (selector === '.toggle-track') return null;
      if (selector === '[data-light-controls]') return controls;
      return null;
    },
  };
  controls.closest = selector => selector === '[data-light-controls]' ? controls : null;
  for (const input of [slider, hue, saturation, temperature]) {
    input.closest = selector => selector === '[data-light-controls]' ? controls : null;
  }
  elements.set('card-light-lamp', card);
  for (const [id, input, label] of [
    ['bri', slider, '50%'], ['hue', hue, '120°'], ['sat', saturation, '60%'], ['ct', temperature, '3000 K'],
  ]) {
    elements.set(`${id}-light-lamp`, input);
    elements.set(`${id}-val-light-lamp`, { textContent: label });
  }
  return { card, slider, hue, saturation, temperature, panels, buttons, controls, wasReplaced: () => replaced };
}

const plain = value => JSON.parse(JSON.stringify(value));

async function main() {
  const { context, document, elements, listeners, requests } = makeContext();

  assert.equal(
    context.buildLightControls('light.onoff', state({ supported_color_modes: ['onoff'] })),
    '',
    'onoff-only lights must not show a brightness or color control',
  );
  const brightnessMarkup = context.buildLightControls(
    'light.dimmer', state({ supported_color_modes: ['brightness'], brightness: 128 }),
  );
  assert.match(brightnessMarkup, /data-range-action="brightness"/);
  assert.doesNotMatch(brightnessMarkup, /data-range-action="(?:hue|saturation|color-temp)"/);

  for (const mode of ['rgb', 'rgbw', 'rgbww', 'hs', 'xy']) {
    const markup = context.buildLightControls(
      `light.${mode}`,
      state({ supported_color_modes: [mode], rgb_color: [17, 34, 51], hs_color: [210, 67, 20] }),
    );
    assert.match(markup, /data-range-action="hue"/);
    assert.match(markup, /data-range-action="saturation"/);
    assert.doesNotMatch(markup, /type="color"|data-action="light-panel"/);
  }

  for (const status of ['off', 'unavailable', 'unknown']) {
    assert.equal(context.buildLightControls('light.rgb', state({ supported_color_modes: ['rgb'] }, status)), '');
  }

  // Color is independent of brightness, including integrations reporting only RGB.
  assert.deepEqual(plain(context.colorHsForState(state({ hs_color: [210, 67], rgb_color: [255, 0, 0] }))), { hue: 210, saturation: 67 });
  for (const attribute of ['rgb_color', 'rgbw_color', 'rgbww_color']) {
    assert.deepEqual(plain(context.colorHsForState(state({ [attribute]: [0, 40, 80, 100, 100], brightness: 80 }))), { hue: 210, saturation: 100 });
  }
  assert.deepEqual(plain(context.colorHsForState(state({ xy_color: [0.64, 0.33] }))), { hue: 0, saturation: 100 });
  assert.deepEqual(plain(context.colorHsForState(state({ hs_color: [0, 0] }), 210)), { hue: 210, saturation: 0 });
  assert.deepEqual(plain(context.colorHsForState(state({ rgb_color: [0, 0, 0] }), 210)), { hue: 210, saturation: 0 });
  assert.deepEqual(plain(context.colorHsForState(state({ hs_color: ['bad', 50], rgb_color: [0, 255, 0] }))), { hue: 120, saturation: 100 });

  const kelvinState = state({
    supported_color_modes: ['color_temp'],
    min_color_temp_kelvin: 2700,
    max_color_temp_kelvin: 6500,
    color_temp_kelvin: 3200,
  });
  const kelvinMarkup = context.buildLightControls('light.kelvin', kelvinState);
  assert.match(kelvinMarkup, /min="2700" max="6500"/);
  assert.match(kelvinMarkup, /value="3200"/);
  assert.doesNotMatch(kelvinMarkup, /data-range-action="hue"|data-action="light-panel"/);
  assert.deepEqual(plain(context.colorTempBounds(state({
    supported_color_modes: ['color_temp'], min_mireds: 153, max_mireds: 500,
  }))), { min: 2000, max: 6536 });

  const miredMarkup = context.buildLightControls('light.mired', state({
    supported_color_modes: ['color_temp'], min_mireds: 153, max_mireds: 500, color_temp: 370,
  }));
  assert.match(miredMarkup, /min="2000" max="6536"/);
  assert.match(miredMarkup, /value="2703"/);

  const unknownTemp = state({ supported_color_modes: ['color_temp'], color_temp_kelvin: null });
  assert.match(context.buildLightControls('light.unknown', unknownTemp), /aria-valuetext="Not reported"/);
  assert.equal(context.colorTempLabel(unknownTemp, context.colorTempBounds(unknownTemp)), 'Not reported');

  const combinedState = state({
    supported_color_modes: ['rgb', 'color_temp'], brightness: 128, hs_color: [120, 60],
    color_mode: 'color_temp', color_temp_kelvin: 3000,
  });
  const combinedMarkup = context.buildLightControls('light.lamp', combinedState);
  assert.match(combinedMarkup, /data-panel="white"\s+aria-controls="white-panel-light-lamp" aria-pressed="true"/);
  assert.match(combinedMarkup, /data-panel="color"\s+aria-controls="color-panel-light-lamp" aria-pressed="false"/);
  assert.equal(context.lightControlPanel('light.other', state({ supported_color_modes: ['rgb', 'color_temp'], color_mode: 'rgb' })), 'color');

  vm.runInContext(`states = {
    'light.rgb': ${JSON.stringify(state({ supported_color_modes: ['rgb'], rgb_color: [0, 0, 0] }))},
    'light.kelvin': ${JSON.stringify(kelvinState)},
    'light.onoff': ${JSON.stringify(state({ supported_color_modes: ['onoff'] }))},
    'light.lamp': ${JSON.stringify(combinedState)},
  };`, context);

  await context.sendColor('light.rgb', 210, 80);
  assert.deepEqual(requests.at(-1), {
    entity_id: 'light.rgb', service: 'light.turn_on', data: { rgb_color: [51, 153, 255] },
  });
  await context.sendColor('light.rgb', 210, 0);
  assert.deepEqual(requests.at(-1).data, { rgb_color: [255, 255, 255] }, 'zero saturation means white, not black');
  await context.sendColor('light.rgb', -120, 150);
  assert.deepEqual(requests.at(-1).data, { rgb_color: [0, 0, 255] });
  const requestCount = requests.length;
  await context.sendColor('light.rgb', 'invalid', 50);
  await context.sendColor('light.rgb', 120, undefined);
  await context.sendColor('light.rgb', Infinity, 50);
  await context.sendColor('light.missing', 120, 50);
  await context.sendColor('light.onoff', 120, 50);
  assert.equal(requests.length, requestCount, 'invalid and unsupported color changes must not send');

  await context.sendColorTemp('light.kelvin', 1000);
  assert.deepEqual(requests.at(-1).data, { color_temp_kelvin: 2700 });
  await context.sendColorTemp('light.kelvin', 8000);
  assert.deepEqual(requests.at(-1).data, { color_temp_kelvin: 6500 });

  const active = focusedCard(context, document, elements, combinedState);
  const beforePanel = requests.length;
  listeners.click({ target: active.buttons[1] });
  assert.equal(requests.length, beforePanel, 'panel selection does not send a lamp command');
  assert.equal(active.panels[0].hidden, true);
  assert.equal(active.panels[1].hidden, false);
  assert.equal(active.buttons[1].attributes['aria-pressed'], 'true');
  context.setLightPanel('light.lamp', 'invalid');
  context.setLightPanel('light.rgb', 'white');
  assert.equal(context.lightControlPanel('light.lamp', combinedState), 'color', 'explicit panel choice survives reported color mode');
  assert.equal(context.lightControlPanel('light.rgb', state({ supported_color_modes: ['rgb'] })), 'color');

  active.hue.value = '210';
  active.saturation.value = '80';
  listeners.input({ target: active.hue });
  assert.equal(requests.length, beforePanel, 'drag preview must not send commands on every input event');
  assert.equal(elements.get('hue-val-light-lamp').textContent, '210°');
  assert.equal(elements.get('sat-val-light-lamp').textContent, '80%');
  assert.equal(active.saturation.style['--light-hue'], '210');
  listeners.change({ target: active.hue });
  assert.deepEqual(requests.at(-1).data, { rgb_color: [51, 153, 255] });
  active.saturation.value = '0';
  listeners.change({ target: active.saturation });
  assert.deepEqual(requests.at(-1).data, { rgb_color: [255, 255, 255] });
  const tempTarget = { value: '2800', dataset: { rangeAction: 'color-temp', eid: 'light.kelvin' } };
  listeners.change({ target: tempTarget });
  assert.deepEqual(requests.at(-1).data, { color_temp_kelvin: 2800 });

  active.temperature.value = '3100';
  listeners.input({ target: active.temperature });
  assert.equal(active.temperature.attributes['aria-valuetext'], '3100 K');
  assert.equal(elements.get('ct-val-light-lamp').textContent, '3100 K');

  const unsafeName = '<img src=x onerror=alert(1)>&"';
  const escaped = context.buildCard('light.unsafe', state({
    friendly_name: unsafeName, supported_color_modes: ['onoff'],
  }));
  assert.ok(escaped.includes('&lt;img src=x onerror=alert(1)&gt;&amp;&quot;'));
  assert.ok(!escaped.includes(unsafeName));
  assert.match(context.buildLightControls('light.unsafe"', state({
    friendly_name: unsafeName, supported_color_modes: ['rgb'],
  })), /aria-label="Light settings for &lt;img/);

  const incomingState = state({ ...combinedState.attributes, brightness: 230, hs_color: [300, 40], color_temp_kelvin: null });
  document.activeElement = active.slider;
  context.updateLightCard('light.lamp', incomingState, active.card);
  assert.equal(active.slider.value, '50', 'SSE brightness updates must not move the active slider');
  assert.equal(active.temperature.attributes['aria-valuetext'], 'Not reported');
  document.activeElement = null;
  context.updateLightCard('light.lamp', incomingState, active.card);
  assert.equal(active.slider.value, String(Math.round((230 / 255) * 100)));

  for (const input of [active.hue, active.saturation]) {
    active.hue.value = '210';
    active.saturation.value = '80';
    document.activeElement = input;
    context.updateLightCard('light.lamp', incomingState, active.card);
    assert.equal(active.hue.value, '210', 'SSE must preserve both halves of a focused color edit');
    assert.equal(active.saturation.value, '80');
  }
  document.activeElement = null;
  context.updateLightCard('light.lamp', incomingState, active.card);
  assert.equal(active.hue.value, '300');
  assert.equal(active.saturation.value, '40');

  document.activeElement = active.temperature;
  context.updateLightCard('light.lamp', combinedState, active.card);
  assert.equal(active.temperature.attributes['aria-valuetext'], 'Not reported', 'focused Kelvin control stays intact');
  document.activeElement = null;
  context.updateLightCard('light.lamp', combinedState, active.card);
  assert.equal(active.temperature.attributes['aria-valuetext'], '3000 K');

  vm.runInContext(`states['light.lamp'] = ${JSON.stringify(state(combinedState.attributes, 'off'))};`, context);
  document.activeElement = active.slider;
  context.updateLightCard('light.lamp', state(combinedState.attributes, 'off'), active.card);
  assert.equal(active.wasReplaced(), false, 'an active control must defer an off-state replacement');
  document.activeElement = null;
  listeners.focusout({ target: active.slider });
  assert.equal(active.wasReplaced(), true, 'focusout must reconcile the deferred off-state update');

  console.log('light controls tests passed');
}

main().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});

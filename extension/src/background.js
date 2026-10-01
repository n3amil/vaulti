// Auto-lock: the vault key lives in session-only storage (memory, never on
// disk, gone when the browser closes). Drop it after inactivity.
const LOCK_AFTER_MIN = 5;

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'lock') return;
  const { until } = await chrome.storage.session.get('until');
  if (!until || Date.now() >= until) await chrome.storage.session.clear();
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg === 'touch') chrome.alarms.create('lock', { delayInMinutes: LOCK_AFTER_MIN });
});

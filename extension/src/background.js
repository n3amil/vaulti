// Background tasks that must outlive the popup:
// - auto-lock: the vault key lives in session-only storage (memory, never on
//   disk, gone when the browser closes); drop it after inactivity.
// - clipboard: clear copied passwords after 30 seconds.
const LOCK_AFTER_MIN = 5;
const CLEAR_CLIPBOARD_MIN = 0.5;

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'lock') {
    const { until } = await chrome.storage.session.get('until');
    if (!until || Date.now() >= until) await chrome.storage.session.clear();
  }
  if (alarm.name === 'clear-clipboard') await clearClipboard();
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg === 'touch') chrome.alarms.create('lock', { delayInMinutes: LOCK_AFTER_MIN });
  if (msg === 'copied-secret') chrome.alarms.create('clear-clipboard', { delayInMinutes: CLEAR_CLIPBOARD_MIN });
});

async function clearClipboard() {
  if (typeof document !== 'undefined') {
    // Firefox: the background is an event page with a DOM.
    writeEmpty();
  } else if (chrome.offscreen) {
    // Chrome: a service worker has no clipboard access; use an offscreen page.
    if (!(await chrome.offscreen.hasDocument?.())) {
      await chrome.offscreen.createDocument({
        url: 'offscreen.html',
        reasons: ['CLIPBOARD'],
        justification: 'Clear a copied password from the clipboard',
      });
    }
    await chrome.runtime.sendMessage({ target: 'offscreen', clear: true }).catch(() => {});
  }
}

function writeEmpty() {
  const area = document.createElement('textarea');
  area.value = ' ';
  document.body.append(area);
  area.select();
  document.execCommand('copy');
  area.remove();
}

// Chrome only: clears the clipboard for the background service worker.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.target !== 'offscreen' || !msg.clear) return;
  const area = document.createElement('textarea');
  area.value = ' ';
  document.body.append(area);
  area.select();
  document.execCommand('copy');
  area.remove();
  window.close();
});

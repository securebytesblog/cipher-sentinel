// Create a new panel in DevTools
chrome.devtools.panels.create(
  "CipherSentinel",
  "icons/icon16.png",
  "panel.html",
  function(panel) {
    console.log('CipherSentinel panel loaded.');
  }
);

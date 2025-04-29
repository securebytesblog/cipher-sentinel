// Create a new panel in DevTools
chrome.devtools.panels.create(
  "SSL Checker",
  "icons/icon16.png",
  "panel.html",
  function(panel) {
    console.log('SSL Checker panel loaded.');
  }
);

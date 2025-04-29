(async () => {
  const rules = await fetch(chrome.runtime.getURL('rules.json')).then(r => r.json());

  // Analyze all network requests and display security details per host
  function analyze() {
    chrome.devtools.network.getHAR((harLog) => {
      const hosts = {};
      harLog.entries.forEach(entry => {
        const sec = entry.response.securityDetails;
        if (!sec) return;
        try {
          const url = new URL(entry.request.url);
          const host = url.host;
          if (!hosts[host]) hosts[host] = sec;
        } catch (e) {
          // skip invalid URLs
        }
      });

      const table = document.getElementById('details');
      const alertsEl = document.getElementById('alerts');
      // Clear existing rows except header
      table.querySelectorAll('tr:not(:first-child)').forEach(r => r.remove());
      const alerts = [];

      Object.entries(hosts).forEach(([host, sec]) => {
        const row = table.insertRow();
        row.insertCell().textContent = host;
        row.insertCell().textContent = sec.protocol;
        row.insertCell().textContent = sec.cipher;
        row.insertCell().textContent = sec.keyExchange + (sec.keyExchangeGroup ? ` (${sec.keyExchangeGroup})` : '');
        row.insertCell().textContent = sec.issuer;
        row.insertCell().textContent = new Date(sec.validFrom * 1000).toLocaleString();
        row.insertCell().textContent = new Date(sec.validTo * 1000).toLocaleString();
        const rsaBits = sec.keyExchange.includes('RSA')
          ? parseInt(sec.keyExchange.split('_')[2], 10)
          : null;
        row.insertCell().textContent = rsaBits ? `${rsaBits} bits` : '—';

        // Rule checks
        if (sec.protocol < rules.minTlsVersion) {
          alerts.push(`${host}: protocol ${sec.protocol} is below ${rules.minTlsVersion}`);
        }
        rules.weakCiphers.forEach(wc => {
          if (sec.cipher.includes(wc)) {
            alerts.push(`${host}: weak cipher ${sec.cipher}`);
          }
        });
        if (rsaBits && rsaBits < rules.minRsaBits) {
          alerts.push(`${host}: RSA key size ${rsaBits} bits is below ${rules.minRsaBits}`);
        }
      });

      alertsEl.innerHTML = alerts.length
        ? `<p class="alert">${alerts.join('<br>')}</p>`
        : '<p>All hosts comply with your security rules.</p>';
    });
  }

  // Initial analysis
  analyze();
  // Refresh on button click
  document.getElementById('refresh').addEventListener('click', analyze);
})();

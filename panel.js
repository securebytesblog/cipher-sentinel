(async () => {
  const protocolMap = {
    "SSL 3.0": 3.0,
    "TLS 1.0": 1.0,
    "TLS 1.1": 1.1,
    "TLS 1.2": 1.2,
    "TLS 1.3": 1.3,
    "QUIC":    1.3,
    "HTTP/3":  1.3,
    "h3":      1.3
  };
  const toNum = proto => protocolMap[proto] || 0;

  const rules = await fetch(chrome.runtime.getURL('rules.json')).then(r => r.json());
  const minProto = toNum(rules.minTlsVersion);

  // map known ciphers to CVEs for threat lookup
  const cipherCVEMap = {
    "RC4": ["CVE-2013-2566"],
    "3DES": ["CVE-2016-2183"]
  };
  const getCipherCves = cipher => 
    Object.entries(cipherCVEMap)
      .filter(([key]) => cipher.includes(key))
      .flatMap(([_k, cves]) => cves);

  const hosts = {};
  const tab = { tabId: chrome.devtools.inspectedWindow.tabId };

  // attach debugger and enable network
  chrome.debugger.attach(tab, "1.3", () =>
    chrome.debugger.sendCommand(tab, "Network.enable")
  );

  // clear and rescan on navigation
  chrome.devtools.network.onNavigated.addListener(() => {
    Object.keys(hosts).forEach(h => delete hosts[h]);
    console.log('🔄 Page navigated – cleared hosts map');
    // scanning resumes automatically on new responses
  });

  // listen for each response to capture TLS and headers
  chrome.debugger.onEvent.addListener((src, method, params) => {
    if (src.tabId !== tab.tabId || method !== "Network.responseReceived") return;
    const res = params.response;
    if (!res.securityDetails) return;

    const host = new URL(res.url).host;
    if (!hosts[host]) hosts[host] = { sec: null, headers: {} };
    hosts[host].sec = res.securityDetails;
    if (params.type === "Document") {
      hosts[host].headers = res.headers || {};
    }
    updateUI();
  });

  window.addEventListener('unload', () => {
    chrome.debugger.detach(tab);
  });

  function updateUI() {
    const filterVal = document.getElementById('filter').value.toLowerCase();
    const showInfo = document.getElementById('filter-info').checked;
    const showWarning = document.getElementById('filter-warning').checked;
    const showCritical = document.getElementById('filter-critical').checked;

    const table = document.getElementById('details');
    table.querySelectorAll('tr:not(:first-child)').forEach(r => r.remove());
    const alertsEl = document.getElementById('alerts');
    alertsEl.innerHTML = '';

    const headerChecks = [
      'strict-transport-security',
      'content-security-policy',
      'x-frame-options',
      'x-content-type-options'
    ];

    const severityRank = { info: 1, warning: 2, critical: 3 };

    for (const [host, data] of Object.entries(hosts)) {
      const { sec, headers } = data;
      if (!sec) continue;
      if (filterVal && !host.includes(filterVal)) continue;

      const protoNum = toNum(sec.protocol);
      const validToMs = sec.validTo * 1000;
      const expiresDays = Math.round((validToMs - Date.now()) / 86400000);
      const rsaBits = sec.keyExchange.includes('RSA')
        ? parseInt(sec.keyExchange.split('_')[2], 10)
        : null;

      // build alerts with severity
      const hostAlerts = [];
      if (sec.protocol.startsWith('TLS') && protoNum < minProto) {
        hostAlerts.push({
          message: `protocol ${sec.protocol} < ${rules.minTlsVersion}`,
          severity: 'critical'
        });
      }
      if (rsaBits !== null && rsaBits < rules.minRsaBits) {
        hostAlerts.push({
          message: `RSA ${rsaBits} bits < ${rules.minRsaBits}`,
          severity: 'warning'
        });
      }
      if (rules.weakCiphers.includes(sec.cipher)) {
        hostAlerts.push({
          message: `cipher ${sec.cipher} is weak`,
          severity: 'info'
        });
      }
      // CVE lookup
      const cves = getCipherCves(sec.cipher);
      cves.forEach(cve => hostAlerts.push({
        message: `cipher ${sec.cipher} has advisory ${cve}`,
        severity: 'critical'
      }));
      // expiration countdown
      if (expiresDays <= 7) {
        hostAlerts.push({ message: `expires in ${expiresDays} days`, severity: 'critical' });
      } else if (expiresDays <= 30) {
        hostAlerts.push({ message: `expires in ${expiresDays} days`, severity: 'warning' });
      }

      // determine row severity
      const rowSeverity = hostAlerts.reduce(
        (acc, a) => severityRank[a.severity] > severityRank[acc] ? a.severity : acc,
        'info'
      );
      if (rowSeverity === 'critical' && !showCritical) continue;
      if (rowSeverity === 'warning'  && !showWarning)  continue;
      if (rowSeverity === 'info'     && !showInfo)     continue;

      // render row
      const row = table.insertRow();
      row.className = rowSeverity;
      row.insertCell().textContent = host;
      row.insertCell().textContent = sec.protocol;
      row.insertCell().textContent = sec.cipher;
      row.insertCell().textContent = sec.keyExchange + (sec.keyExchangeGroup ? ` (${sec.keyExchangeGroup})` : '');
      row.insertCell().textContent = sec.issuer;
      row.insertCell().textContent = new Date(sec.validFrom * 1000).toLocaleString();
      row.insertCell().textContent = new Date(validToMs).toLocaleString();
      row.insertCell().textContent = `${expiresDays} days`;
      row.insertCell().textContent = rsaBits ? `${rsaBits} bits` : '—';
      row.insertCell().textContent = hostAlerts
        .map(a => `[${a.severity.toUpperCase()}] ${a.message}`)
        .join('; ');

      // headers column
      const headerResults = headerChecks.map(name => (
        Object.keys(headers).some(h => h.toLowerCase() === name)
          ? name
          : `${name} (missing)`
      ));
      row.insertCell().textContent = headerResults.join('; ');

      // global alerts area
      hostAlerts.forEach(a => {
        const div = document.createElement('div');
        div.className = 'alert';
        div.textContent = `${host}: [${a.severity.toUpperCase()}] ${a.message}`;
        alertsEl.appendChild(div);
      });
    }
  }

  function downloadCSV() {
    const cols = [
      'Host','Protocol','Cipher','KeyExchange','Issuer',
      'ValidFrom','ValidTo','ExpiresIn','RSA','Alerts','Headers'
    ];
    const rows = [cols.join(',')];
    const headerChecks = [
      'strict-transport-security',
      'content-security-policy',
      'x-frame-options',
      'x-content-type-options'
    ];
    for (const [host, data] of Object.entries(hosts)) {
      const sec = data.sec;
      if (!sec) continue;
      const cves = getCipherCves(sec.cipher);
      const rsaBits = sec.keyExchange.includes('RSA')
        ? parseInt(sec.keyExchange.split('_')[2], 10)
        : '';
      const expiresDays = Math.round((sec.validTo*1000 - Date.now())/86400000);
      const hostAlerts = [];
      if (sec.protocol.startsWith('TLS') && toNum(sec.protocol) < minProto)
        hostAlerts.push(`protocol ${sec.protocol} < ${rules.minTlsVersion}`);
      if (rsaBits && rsaBits < rules.minRsaBits)
        hostAlerts.push(`RSA ${rsaBits} bits < ${rules.minRsaBits}`);
      if (rules.weakCiphers.includes(sec.cipher))
        hostAlerts.push(`cipher ${sec.cipher} is weak`);
      cves.forEach(cve => hostAlerts.push(`cipher ${sec.cipher} has advisory ${cve}`));
      if (expiresDays <= 7)
        hostAlerts.push(`expires in ${expiresDays} days`);
      else if (expiresDays <= 30)
        hostAlerts.push(`expires in ${expiresDays} days`);
      const headerResults = headerChecks.map(name => (
        Object.keys(data.headers).some(h => h.toLowerCase() === name)
          ? name
          : `${name} (missing)`
      ));
      rows.push([
        host,
        sec.protocol,
        sec.cipher,
        `"${sec.keyExchange}${sec.keyExchangeGroup?` (${sec.keyExchangeGroup})`:''}"`,
        sec.issuer,
        new Date(sec.validFrom*1000).toISOString(),
        new Date(sec.validTo*1000).toISOString(),
        expiresDays,
        rsaBits,
        `"${hostAlerts.join('; ')}"`,
        `"${headerResults.join('; ')}"`
      ].join(','));
    }
    const blob = new Blob([rows.join('\r\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'ssl-checker-report.csv'; a.click(); URL.revokeObjectURL(url);
  }

  // bind controls
  document.getElementById('filter').addEventListener('input', updateUI);
  document.getElementById('filter-info').addEventListener('change', updateUI);
  document.getElementById('filter-warning').addEventListener('change', updateUI);
  document.getElementById('filter-critical').addEventListener('change', updateUI);
  document.getElementById('download').addEventListener('click', downloadCSV);
})();
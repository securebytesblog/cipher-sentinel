# SSL Checker Chrome DevTools Extension

**SSL Checker** is a Chrome DevTools extension that inspects SSL/TLS configurations for all network requests on a page, displaying protocol, cipher suite, certificate details, and flagging any weak or deprecated settings.

## Features

- Shows TLS version and cipher suite for each host
- Displays certificate issuer and validity period
- Alerts on:
  - TLS versions below 1.2
  - Weak ciphers (RC4, 3DES, AES-CBC, MD5-based)
  - RSA key sizes below 2048 bits

## Installation

1. Clone or download this repository.
2. Open Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select this folder.
5. Open DevTools (`F12`), switch to the **SSL Checker** panel, and click **Refresh**.

## Usage

- Click **Refresh** in the panel to re-scan all network requests.
- Review alerts for any hosts with weak configurations.

## Contributing

1. Fork the repo.
2. Create a feature branch: `git checkout -b feature-name`.
3. Commit your changes and push: `git push origin feature-name`.
4. Open a Pull Request.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

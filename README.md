# RoboEnum

RoboEnum is a modular HTTP enumeration and fingerprinting tool designed for reconnaissance and security assessments. It automates the discovery of endpoints, fetches and parses TLS certificate info, fingerprint favicons, identifies HTTP methods, and more — all while aggregating results in JSON for easy consumption.

---

## Features

- **Target Discovery**: Enumerate accessible endpoints and files from robots.txt and sitemap.xml.
- **TLS Certificate Info**: Extract and store certificate subject, issuer, validity, and fingerprints.
- **Favicon Hashing**: Fetch favicons and generate MD5 and SHA256 hashes for fingerprinting.
- **HTTP Methods Enumeration**: Detect allowed HTTP methods on discovered endpoints.
- **Error Handling**: Graceful handling of network errors and invalid responses.
- **JSON Output**: Save or append structured JSON output for integration or post-processing.
- **Configurable Logging**: Console output with colorized logs and clean file logging.
- **Extensible Framework**: Easily add new fingerprinting or enumeration modules.

## Usage

- Basic Usage
    ```
    roboenum --url http[s]://example.com
    ```
- Save Output to JSON
    ```
    roboenum --url http[s]://example.com --json
    ```
- Brute Force Enum
    ```
    roboenum --url http[s]://example.com --brute [--wordlist]
    ```
- Verbose mode
    ```
    roboenum --url http[s]://example.com --verbose | -v
    ```
- Help Page
    ```
    roboenum --help | -h
    ```


## Installation

Clone this repo and install dependencies:

```bash
git clone https://github.com/qtshade/roboenum.git
cd roboenum
pip install -r requirements.txt

```
OR
```
pip install roboenum
```
```
-On Kali Linux-
pipx install roboenum
```

### Distributions

#### NixOS/Nixpkgs

For Nix or NixOS users is a package available. Keep in mind that the lastest releases might only
be present in the `unstable` channel.

```bash
nix-shell -p roboenum
```

## Contributing
Contributions are welcome! Please follow these guidelines:

1. Fork the repository.

1. Create a feature branch (git checkout -b feature-name).

1. Commit your changes (git commit -m 'Add feature').

1. Push to the branch (git push origin feature-name).

1. Open a Pull Request.

Please ensure your code adheres to the existing style and includes appropriate tests. See CONTRIBUTING.md and CODE_OF_CONDUCT.md for more details.

## License
This project is licensed under the MIT License - see the LICENSE file for details.




## Disclaimer

- RoboEnum is provided "as-is" with no warranty of any kind.
- Use this tool responsibly and only on targets you own or have explicity permission to test.
- The author assums no liability for any damager or legal issues arising from misuse.


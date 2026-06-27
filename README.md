# OmniAdminFinder

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md)

A powerful tool for discovering admin accounts and access points across web applications.

## Features

- **Comprehensive Admin Discovery**: Scan websites for common admin panels, login pages, and administration interfaces
- **Pattern Recognition**: Uses intelligent pattern matching to identify admin endpoints
- **User Agent Rotation**: Prevents detection by rotating user agents across requests
- **Proxy Support**: Route requests through proxy servers for anonymity
- **Custom Wordlists**: Support for custom endpoint wordlists
- **Multi-threaded Scanning**: Fast parallel scanning of multiple endpoints
- **Detailed Reporting**: Comprehensive results with status codes and response metadata
- **Configurable Timeouts**: Adjust request timeouts for network conditions
- **SSL/TLS Support**: Works with both HTTP and HTTPS endpoints

## Installation

### From Source

```bash
git clone https://github.com/PN777/OmniAdminFinder.git
cd OmniAdminFinder
pip install -r requirements.txt
```

### Using pip

```bash
pip install omniadminfinder
```

## Quick Start

```python
from admin_finder import AdminFinder

# Create a finder instance
finder = AdminFinder(target_url='https://example.com')

# Run the scan
results = finder.scan()

# Print results
for result in results:
    print(f"{result['url']}: {result['status_code']}")
```

## Usage

### Command Line

```bash
python admin_finder.py https://example.com
```

### Advanced Options

```bash
python admin_finder.py https://example.com \
  --threads 10 \
  --timeout 5 \
  --proxy http://proxy.example.com:8080 \
  --wordlist custom_endpoints.txt
```

### Python API

```python
from admin_finder import AdminFinder

finder = AdminFinder(
    target_url='https://example.com',
    threads=10,
    timeout=5,
    proxy='http://proxy.example.com:8080',
    wordlist='custom_endpoints.txt'
)

results = finder.scan()
```

## Configuration

Create a `config.ini` file in the project directory:

```ini
[target]
url = https://example.com

[scanner]
threads = 10
timeout = 5
verify_ssl = true

[proxy]
enabled = false
url = http://proxy.example.com:8080

[wordlist]
custom = true
path = custom_endpoints.txt
```

## Documentation

- [Installation Guide](docs/INSTALL.md)
- [Usage Examples](docs/examples/basic_usage.md)
- [FAQ](docs/FAQ.md)
- [API Reference](docs/API.md)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Please report security vulnerabilities responsibly. See [SECURITY.md](SECURITY.md) for details.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Users are solely responsible for their actions and compliance with applicable laws. The authors assume no liability for misuse.

## Support

- Open an [issue](https://github.com/PN777/OmniAdminFinder/issues) for bug reports
- Start a [discussion](https://github.com/PN777/OmniAdminFinder/discussions) for questions
- Check the [FAQ](docs/FAQ.md) for common questions

## Authors

**PN777** - Initial work and maintenance

See also the list of [contributors](https://github.com/PN777/OmniAdminFinder/graphs/contributors).

## Acknowledgments

- Thanks to the open source security community
- Inspired by similar security scanning tools
- Built with Python and community feedback

---

Made with ❤️ by the OmniAdminFinder team

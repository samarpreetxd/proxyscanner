
# ProxyScanner

ProxyScanner is a high-performance, concurrent proxy scanner written in Go. It supports detecting HTTP, SOCKS4, and SOCKS5 proxies across configurable IP ranges and port ranges.



## Features

- **Concurrent scanning:** Utilizes multiple workers (default is double your CPU cores) for fast scanning
- **Flexible input:** Reads IP ranges in CIDR notation from `Cidr.txt`
- **Port ranges support:** Supports single ports and port ranges (e.g., `80` or `1080-1085`) from `Ports.txt`
- **Protocol detection:** Identifies HTTP, SOCKS4, and SOCKS5 proxies
- **Configurable:** Use CLI flags or a JSON config file to set timeout, concurrency, output directory, and log level
- **Output:** Writes detected proxies with protocol type to `proxies.txt`

---

## Getting Started

### Build

Make sure you have [Go](https://golang.org/dl/) installed, then build the binary:

```bash
go build -o proxyscanner main.go
````

### Prepare Input Files

* `Cidr.txt` — List your target IP ranges here, one CIDR per line. Example:

```
192.168.1.0/24
10.0.0.0/24
```

* `Ports.txt` — List ports or port ranges, one per line. Example:

```
80
1080-1085
```

### Run

Basic usage with default settings:

```bash
./proxyscanner
```

Custom flags example:

```bash
./proxyscanner -timeout=5 -workers=20 -output-dir=output -log-level=debug
```

### Configuration File (optional)

Create a JSON config file (e.g., `config.json`):

```json
{
  "timeout": 5,
  "workers": 20,
  "refresh_interval": 60,
  "output_dir": "./output",
  "log_level": "debug"
}
```

Then run:

```bash
./proxyscanner -config=config.json
```

---

## Flags

| Flag                | Description                              | Default                 |
| ------------------- | ---------------------------------------- | ----------------------- |
| `-timeout`          | Connection timeout in seconds            | 3                       |
| `-workers`          | Number of concurrent workers             | `runtime.NumCPU()*2`    |
| `-refresh-interval` | Minutes to re-test proxies               | 60                      |
| `-output-dir`       | Directory for output file                | Current directory (`.`) |
| `-log-level`        | Logging level (`info`, `debug`, `quiet`) | `info`                  |
| `-config`           | Path to JSON config file                 | none                    |

---

## Output

Detected proxies are saved in:

```
<output-dir>/proxies.txt
```

Format example:

```
192.168.1.5:1080 - SOCKS5
10.0.0.12:80 - HTTP
```

---

## License

This project is licensed under the MIT License.

---

## Notes

* Large IP ranges and port sets can take time; tune `-workers` and `-timeout` accordingly.
* Ensure your network/firewall allows scanning on target IPs and ports.
* Use responsibly and only scan IPs/networks you own or have permission to test.

---

Feel free to contribute or open issues for improvements!




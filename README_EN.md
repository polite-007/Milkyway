<p align="center"> <img src="static/images/Milkyway-logo.svg" width="100px" alt="milkyway"> </p>

[![Latest release](https://img.shields.io/github/v/release/polite-007/Milkyway)](https://github.com/polite-007/Milkyway/releases/latest)![GitHub Release Date](https://img.shields.io/github/release-date/polite-007/Milkyway)![GitHub All Releases](https://img.shields.io/github/downloads/polite-007/Milkyway/total)[![GitHub issues](https://img.shields.io/github/issues/polite-007/Milkyway)](https://github.com/polite-007/Milkyway/issues)

> This tool is intended for use by authorized security testers only. Unauthorized testing is prohibited and will be at your own risk.

## Milkyway

Milkyway is an all-in-one scanning tool with efficient features for host discovery, port scanning, protocol identification, fingerprinting, vulnerability scanning, and more.

* Protocol recognition implemented in pure Go
* Rich scanning modes
* Support for randomized port scanning (the larger the target, the faster and more accurate the scan)

> If you like this tool, please star it~


## What can Milkyway do?

1. Information Gathering
    * IP & Port live detection
    * Web probing
    * Protocol identification (`mysql`, `redis`, `smb`, `ldap`, `ssh`, `vnc`, `ftp`, `smtp`, `rdp`)
2. Brute Force
    * `ssh`, `mysql`, `redis`, `vnc`
    * to be continued
3. Vulnerability Detection
    * redis unauthorized access
    * EternalBlue / EternalBlack
    * nuclei vulnerability engine
    * Select POC by `tags` or `id`
4. Additional Features
    * Real-time log printing
    * Custom fingerprint file loading
    * Custom POC preload directories or files
    * `http` / `socks5` proxy support
    * Support `fofa` query, pull targets from `fofa` 
    * Supports `url` input
    * Supports extracting targets from files

## Advanced Parameters
* `--finger-file` Custom web fingerprint file loading
* `--scan-random` Whether to randomize port scanning
* `--full-scan` Perform full protocol identification on open ports (default only specific ports are identified)
* `--verbose` Print detailed protocol information
* `--no-match` Skip fingerprint rule matching before vulnerability scanning
* `--poc-file` Custom nuclei poc file/directory
* `--fofa-query` Use fofa query to extract targets (When using fofa query to import targets, system environment variable FOFA_KEY must be set to your fofa-key)

## Basic Usage

`milkyway.exe -t 192.168.1.1/24` (Ports default to the "default" list, scanning the top 809 ports)

`milkyway.exe --fofa-query 'domain=baidu.com'` (Extract targets using fofa query)

`milkyway.exe -t 192.168.1.1/24 -s socks5://127.0.0.1:1080` (Use socks5 proxy)

`milkyway.exe -t 192.168.1.1/24 -c 500` (Set the number of workers in the thread pool)

## Demo Use Cases

1. Using fofa for external network probing, and using unordered scan:

    `milkyway.exe --fofa-query 'domain=vulfocus.cn||host=vulfocus.cn' -p all --no-ping --scan-random`
    ![img.png](./static/images/running_picture6.png) 
2. Setting concurrency to 1000 and using unordered scan for all internal ports:
    
    `milkyway.exe -t 192.168.1.0/24 -p all --scan-random -c 1000 --no-ping`
    ![img.png](./static/images/running_picture7.png)

## Advanced Parameters Usage

`milkyway.exe -t 192.168.1.1/24 -p company` (Scan the 87 most commonly used ports for companies)

`milkyway.exe -t 192.168.1.1/24 -p small --full-scan` (Full protocol scan on the first 12 ports)

`milkyway.exe -t 192.168.1.1/24 --no-ping` (Skip ICMP scan)

`milkyway.exe -t 192.168.1.1/24 --finger-file ./your_file` (Use custom fingerprint file)

`milkyway.exe -t 192.168.1.1/24 --verbose` (Print detailed protocol information)

`milkyway.exe -t 192.168.1.1/24 --no-match` (Do not match fingerprints before vulnerability scanning)

`milkyway.exe -t 192.168.1.1/24 --poc-file ./your_file` (Custom POC directory)

`milkyway.exe -t 192.168.1.1/24 --poc-tags cve,cnvd` (Specify multiple POC tags)

> `sql`: Common database ports, `small`: Top 12 common ports, `all`: All ports

### Running Picture

![img.png](./static/images/running_picture1.png)

![img.png](./static/images/running_picture2.png)

![img.png](./static/images/running_picture5.png)

![img.png](./static/images/running_picture4.png)

**Special thanks to FOFA official**

Milkyway has joined the FOFA [Co-creation Plan]((https://fofa.info/development)). Thanks to FOFA for providing account support.

<img width="318" alt="image" src="https://user-images.githubusercontent.com/67818638/210543196-b76f6808-b5dd-4933-9451-0c3217dca8f5.png">

# Reference Projects
https://github.com/shadow1ng/fscan

https://github.com/EdgeSecurityTeam/EHole

https://github.com/chainreactors/neutron

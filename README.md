# Saar

Saar is a bug bounty script combining the best tools for a smooth recon workflow.

## Install

1. Install Saar and its dependencies
   ```sh
   curl -fLSs -o /usr/local/bin/saar https://raw.githubusercontent.com/xthezealot/saar/main/saar.sh && saar update
   ```
2. Configure dependencies:
   - To find more subdomains, add API keys to [`$HOME/.config/subfinder/provider-config.yaml`](https://github.com/projectdiscovery/subfinder#post-installation-instructions)
   - To find more hosts, Add API keys to [`$HOME/.config/uncover/provider-config.yaml`](https://github.com/projectdiscovery/uncover#provider-configuration)
   - To be notified of new findings, add your Telegram bot to [`$HOME/.config/notify/provider-config.yaml`](https://github.com/projectdiscovery/notify#provider-config)
     ```yml
     telegram:
       - id: "saar"
         telegram_api_key: "<API_KEY>"
         telegram_chat_id: "<CHAT_ID>"
         telegram_format: "{{data}}"
         telegram_parsemode: "MarkdownV2"
     ```

## Usage

For every new hunt:

1. Make a new directory and move in
2. Create a `scope.txt` file and add your targets (domain, IP, CIDR, ASN), one per line
3. Run `saar` (you can skip steps with `-skip` flags)
4. Once the scan is complete, see:
   - `ports.txt` for open ports
   - `ports.gnnmap` for additional port info from Nmap
   - `http.txt` (and the `http` directory) for successful HTTP requests (use command `saar pphttp` for a better view)
   - `secrets.txt` for secret keys found in HTTP responses
   - `vulns.txt` for common vulnerabilities found by scanners
5. Find an interesting entry point and get to work

## Help

```
   _________ _____ ______
  / ___/ __ `/ __ `/ ___/
 (__  ) /_/ / /_/ / /
/____/\__,_/\__,_/_/  v1.0.0


Saar is a bug bounty script that discovers targets from a scope and performs all the usual scans.

Usage:
    saar <command> [flags]

Commands:
    pphttp    pretty print http.txt results
    update    update saar and its dependencies

Flags:
    -s, -skip string    skip a step (flag can be used multiple times) (choices: subs, uncover, portscan, wordlists, http, vulns)
```

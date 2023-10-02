# Saar

Saar is a bug bounty script combining the best tools for a smooth recon workflow.

## Install

1. ```sh
   curl -fLSs -o /usr/local/bin/saar https://raw.githubusercontent.com/xthezealot/saar/   main/saar.sh
   ```
2. Configure dependencies

## Usage

1. Make a fresh directory for the hunt
2. Create a `scope.txt` file a add your targets inside (domain, IP, CIDR, ASN), 1 per line
3. Run `saar` (you can skip steps with `-skip` flags)

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

Flags:
    -s, -skip string    skip a step (flag can be used multiple times) (choices: subs, uncover, portscan, wordlists, http, vulns)
    -up, -update        update saar and its dependencies
```

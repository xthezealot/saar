#!/bin/bash

log_msg() {
	echo -e "\e[2m$(date '+%Y-%m-%d %H:%M:%S')\e[0m  $1"
}

in_array() {
	local value_to_check="$1"
	shift
	local array=("$@")

	for value in "${array[@]}"; do
		if [[ "$value" == "$value_to_check" ]]; then
			return 0 # success
		fi
	done

	return 1 # fail
}

# remove blank lines, sort lines, and remove duplicates
clean_file() {
	sed '/^\s*$/d' "$1" | sort -u -o "$1"
}

# shellcheck disable=SC2016
echo '
   _________ _____ ______
  / ___/ __ `/ __ `/ ___/
 (__  ) /_/ / /_/ / /
/____/\__,_/\__,_/_/  v1.0.0

'

SCOPE_FILE="scope.txt"               # the source scope
HOSTS_FILE="hosts.txt"               # all potential hosts that have existed through times, can only grow
PORTS_FILE="ports.txt"               # only active hosts with open ports since the last scan
HTTP_FILE="http.txt"                 # responses from http requests
HTTP_RES_DIR="http"                  # saved responses from http requests
PORTS_NMAP_FILE="ports.gnnmap"       # additional map results
PATHS_WORDLIST="wordlists/paths.txt" # paths wordlist from wayback archive and other sources, can only grow
SECRETS_FILE="secrets.txt"           # found secrets, based on entropy and known formats
VULNS_FILE="vulns.txt"               # found vulnerabilities

GENERIC_PATHS_WORDLIST="/usr/local/share/wordlists/saar_paths.txt"

http_portlist=(80 443 3000 5000 8000 8008 8080 8081 8443 8888)
portlist=("${http_portlist[@]}" 21 22 23 445 1433 1521 2375 3306 5432 9200 10250 27017)

re_domain="[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
re_ipv4="(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
re_ipv6="([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
re_cidr="(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}"
re_asn="(?i)AS[0-9]+"

declare -a skips

# parse arguments
while [[ "$#" -gt 0 ]]; do
	case $1 in
	pphttp)
		jq -r '
			"\(.final_url // .url)  " +
			(if .status_code >= 200 and .status_code <= 299 then "\u001b[32m\(.status_code)\u001b[0m" else "\u001b[31m\(.status_code)\u001b[0m" end) +
			"  \u001b[35m\(.content_type)\u001b[0m" +
			"  \u001b[37m\(.tech)\u001b[0m" +
			"  \u001b[36m\(.title // "")\u001b[0m"
			' "$HTTP_FILE"
		exit
		;;
	-s | -skip | --skip)
		shift
		skips+=("$1")
		;;
	-up | -update | --update)
		log_msg "updating saar and its dependencies"

		apt update && apt install -y gcc jq libpcap-dev nmap
		CGO_ENABLED=1 go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
		go install github.com/mikefarah/yq/v4@latest
		go install github.com/projectdiscovery/alterx/cmd/alterx@latest
		go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
		go install github.com/projectdiscovery/httpx/cmd/httpx@latest
		go install github.com/projectdiscovery/notify/cmd/notify@latest
		go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
		go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
		go install github.com/projectdiscovery/uncover/cmd/uncover@latest
		go install github.com/tomnomnom/waybackurls@latest
		curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

		mkdir -p /usr/local/share/wordlists
		# download wordlists

		exit
		;;
	-h | -help | --help)
		echo "Saar is a bug bounty script that discovers targets from a scope and performs all the usual scans.

Usage:
    saar <command> [flags]

Commands:
    pphttp    pretty print $HTTP_FILE results

Flags:
    -s, -skip string    skip a step (flag can be used multiple times) (choices: subs, uncover, portscan, wordlists, http, vulns)
    -up, -update        update saar and its dependencies
		"
		exit
		;;
	*)
		echo "unknown argument: $1"
		;;
	esac
	shift
done

### handle scope ###

if [ ! -f "$SCOPE_FILE" ]; then
	touch "$SCOPE_FILE"
	echo "add scope (domain, IP, CIDR, ASN) to $SCOPE_FILE"
	exit
fi

mkdir -p wordlists

SCOPE_DOMAINS=$(grep -P "^$re_domain$" "$SCOPE_FILE")
SCOPE_IPV4=$(grep -P "^$re_ipv4$" "$SCOPE_FILE")
SCOPE_IPV6=$(grep -P "^$re_ipv6$" "$SCOPE_FILE")
SCOPE_CIDRS=$(grep -P "^$re_cidr$" "$SCOPE_FILE")
SCOPE_ASNS=$(grep -P "^$re_asn$" "$SCOPE_FILE" | tr "[:lower:]" "[:upper:]")
SCOPE_NAMES=$(grep -vP "^$re_domain$|^$re_ipv4$|^$re_ipv6$|^$re_cidr$|^$re_asn$" "$SCOPE_FILE")

### make hosts file ###

for list in "$SCOPE_DOMAINS" "$SCOPE_IPV4" "$SCOPE_IPV6" "$SCOPE_CIDRS" "$SCOPE_ASNS"; do
	echo "$list" >>"$HOSTS_FILE"
done

# find subdomains
if ! in_array "subs" "${skips[@]}"; then
	log_msg "discovering subdomains"
	subfinder -all -silent <<<"$SCOPE_DOMAINS" | tee -a "$HOSTS_FILE"

	function trickest_inventory() {
		encoded=$(echo "$1" | jq -Rr '@uri') # urlencode
		res_file=$(mktemp)
		if curl -s -f --max-time 10 "https://raw.githubusercontent.com/trickest/inventory/main/$encoded/hostnames.txt" -o "$res_file"; then
			cat "$res_file" >>"$HOSTS_FILE"
		fi
		rm "$res_file"
	}

	# get chaos project data
	chaos_file=$(mktemp)
	curl -s "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/chaos-bugbounty-list.json" -o "$chaos_file"

	# loop trough generic scope names
	while read -r line; do
		log_msg "fetching trickest/inventory and chaos project for $line"
		trickest_inventory "$line" &
		jq -r ".programs[] | select(.name == \"$line\") | .domains[]" "$chaos_file" >>"$HOSTS_FILE" &
	done <<<"$SCOPE_NAMES"
	wait

	rm "$chaos_file"

	log_msg "discovering alternative subdomains"
	grep -P "$re_domain" "$HOSTS_FILE" | alterx -silent | dnsx -silent | tee -a "$HOSTS_FILE"
fi

clean_file "$HOSTS_FILE"

# discover other ips from found domains and subdomains
if ! in_array "uncover" "${skips[@]}"; then
	function uncover_search() {
		local extra_args=("$@")
		uncover -silent -field "host,ip" "${extra_args[@]}" | awk -v hosts_file="$HOSTS_FILE" -F, '{ print $1 >> hosts_file; print $2 >> hosts_file }'
	}

	grep -P "$re_domain" "$HOSTS_FILE" | while read -r line; do
		log_msg "discovering hosts for $line"
		uncover_search "-hunterhow" "domain=\"$line\"" &
		uncover_search "-censys" "$line" &
	done

	wait
fi

clean_file "$HOSTS_FILE"

### scan ports ###

if ! in_array "portscan" "${skips[@]}"; then
	log_msg "scanning ports"

	naabu -silent -exclude-cdn -nmap-cli "nmap -sV -T5 -oG $PORTS_NMAP_FILE" -list "$HOSTS_FILE" -o "$PORTS_FILE" -p "$(
		IFS=","
		echo "${portlist[*]}"
	)"

	{
		echo "*Port scan done:*"
		echo "\`$(realpath "$PORTS_FILE")\`"
	} | notify -silent -bulk
fi

### make path wordlist ###

if ! in_array "wordlists" "${skips[@]}"; then
	domains=$(grep -P "$re_domain" "$HOSTS_FILE")

	# get disallowed paths from robots.txt
	log_msg "making paths wordlist from robots.txt"
	while read -r line; do
		curl -s --max-time 10 "$line/robots.txt" | grep "Disallow:" | grep -v "\*" | awk '{print $2}' | sort -u >>"$PATHS_WORDLIST" &
	done <<<"$domains"

	wait

	log_msg "making paths wordlist from wayback archive"
	# gets paths from wayback archive
	waybackurls <<<"$domains" |
		awk -F'//[^/]+' '{sub(/\?.*/, "", $2); print $2}' |                                                          # keep only paths from urls
		grep -viE "\.(css|jpg|jpeg|png|gif|svg|webp|bmp|ico|eot|otf|ttf|woff|woff2|doc|docx|pdf|mp4|avi|mov|mkv)$" | # remove useless urls based on extensions
		sort -u >>"$PATHS_WORDLIST"

	clean_file "$PATHS_WORDLIST"
fi

### http probe ###

if ! in_array "http" "${skips[@]}"; then
	# merge path wordlists
	paths_wl_file=$(mktemp)
	cat "$GENERIC_PATHS_WORDLIST" "$PATHS_WORDLIST" 2>/dev/null | sort -u >"$paths_wl_file"

	rm -r "$HTTP_RES_DIR"

	# probe both http and https with paths wordlist, on each open ports detected by port scan
	log_msg "probing http ports"
	grep -E "($(
		IFS="|"
		echo "${http_portlist[*]}"
	))$" "$PORTS_FILE" |
		httpx -silent -status-code -content-type -title -server -location -tech-detect -no-fallback -follow-redirects -match-code "200,201,204,401,403" -rsts 64000000 -rstr 64000000 -path "$paths_wl_file" -store-response-dir "$HTTP_RES_DIR" -json |
		jq -cs 'unique_by(.final_url // .url)[]' >"$HTTP_FILE"

	rm "$paths_wl_file"

	if [ -s "$HTTP_FILE" ]; then
		{
			echo "*HTTP endpoints found:*"
			echo "\`$(realpath "$HTTP_FILE")\`"
		} | notify -silent -bulk
	fi

	# find secrets
	trufflehog filesystem --json "$HTTP_RES_DIR" |
		jq -cs 'unique_by(.Raw)[] | {file: .SourceMetadata.Data.Filesystem.file, line: .SourceMetadata.Data.Filesystem.line, detector: .DetectorName, raw: .Raw}' >"$SECRETS_FILE"

	# notify for secrets
	if [ -s "$SECRETS_FILE" ]; then
		{
			echo "*Secrets found:*"
			echo "\`$(realpath "$SECRETS_FILE")\`"
		} | notify -silent -bulk
	fi
fi

### vulnerabilities scan ###

if ! in_array "vulns" "${skips[@]}"; then
	# log_msg "checking CRLF vulns"
	# jq -r 'select(.status_code >= 200 and .status_code <= 299) | .final_url // .url' "$HTTP_FILE" | awk -F/ '{print $1 "//" $3}' | sort -u | crlfuzz -s

	rm "$VULNS_FILE"

	scan_vulns() {
		local port=$1
		local tags=$2

		log_msg "checking vulns on $tags"
		grep -E ":$port$" "$PORTS_FILE" | nuclei -silent -tags "$tags" -severity low,medium,high,critical,unknown >>"$VULNS_FILE"
	}

	scan_vulns "21" "ftp,sftp" &
	scan_vulns "22" "ssh" &
	scan_vulns "23" "telnet" &
	scan_vulns "445" "smb" &
	scan_vulns "1433" "sql,db,microsoft,sqlserver," &
	scan_vulns "1521" "sql,db,oracle" &
	scan_vulns "2375" "docker,container,containers" &
	scan_vulns "3306" "sql,db,mysql,maria,mariadb" &
	scan_vulns "5432" "sql,db,postgresql,postgre,postgres,psql,pgsql" &
	scan_vulns "9200" "elasticsearch,elastic,db" &
	scan_vulns "10250" "kubernetes,kubelet,container,containers" &
	scan_vulns "27017" "mongodb,mongo,nosql" &
	scan_vulns "($(
		IFS="|"
		echo "${http_portlist[*]}"
	))" "http,https,tls,ssl,iis,cms" &

	wait

	clean_file "$VULNS_FILE"

	# notify for vulns
	if [ -s "$VULNS_FILE" ]; then
		{
			echo "*Vulns found:*"
			echo "\`$(realpath "$VULNS_FILE")\`"
			echo
			echo "\`\`\`"
			cat "$VULNS_FILE"
			echo "\`\`\`"
		} | notify -silent -bulk
	fi
fi

# todo: try 40x bypass (see http://github.com/lobuhi/byp4xx)
# todo: bruteforce default credentials (see github.com/x90skysn3k/brutespray): brutespray -c -f "$PORTS_NMAP_FILE" -o brutespray.json --threads 15 --hosts 15
# todo: bruteforce login forms (+ default credentials based on tech)
# todo: ssl config scan (see http://github.com/drwetter/testssl.sh)
# todo: scan for cors (see http://github.com/s0md3v/corsy)
# todo: scan for open redirection (see http://github.com/r0075h3ll/oralyzer)
# todo: scan for prototype pollution (see http://github.com/dwisiswant0/ppfuzz)
# todo: scan for sqli
# todo: scan for ssrf
# todo: scan for ssti according to detected tech
# todo: scan for cache poisoning (see http://github.com/hackmanit/web-cache-vulnerability-scanner)
# todo: cms-adapted scan (see http://github.com/tuhinshubhra/cmseek)

# todo: google dorks search (see github.com/six2dez/dorks_hunter)
# todo: github dorks search (see github.com/obheda12/gitdorker & github.com/damit5/gitdorks_go)
# todo: github leaks (see github.com/gitleaks/gitleaks & github.com/trufflesecurity/trufflehog)

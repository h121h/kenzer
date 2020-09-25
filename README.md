# KENZER | Automated web assets enumeration & scanning

## Instructions for running
1. Create an account on [Zulip](https://zulipchat.com)<br>
2. Navigate to `Settings > Your Bots > Add a new bot`<br>
3. Create a new generic bot named `kenzer`<br>
4. Add all the configurations in `configs/kenzer.conf`<br>
5. Install & run using `./install.sh` or just run using `./run.sh`<br>
6. You can interact with **KENZER** using multi-platform Zulip Clients.<br>
7. `kenzer man` as input can be used to display the user manual while interaction.<br>

## Built-in Functionalities
>* `subenum` - enumerates subdomains
>* `webenum` - enumerates webservers
>* `portenum` - enumerates open ports
>* `asnenum` - enumerates asn
>* `urlenum` - enumerates urls
>* `subscan` - hunts for subdomain takeovers
>* `cvescan` - hunts for CVEs
>* `vulnscan` - hunts for other common vulnerabilites
>* `portscan` - scans open ports
>* `parascan` - hunts for vulnerable parameters
>* `endscan` - hunts for vulnerable endpoints
>* `buckscan` - hunts for unreferenced aws s3 buckets
>* `favscan` - fingerprints webservers using favicon
>* `idscan` - identifies applications running on webservers
>* `enum` - runs all enumerator modules
>* `scan` - runs all scanner modules
>* `recon` - runs all modules
>* `hunt` - runs your custom workflow
>* `remlog` - removes log files
>* `upload` - switches upload functionality
>* `kenzer <module>` - runs a specific modules
>* `kenzer man` - shows this manual
>* `kenzer man <module>` - shows manual for a specific module

**COMPATIBILITY TESTED ON ARCHLINUX(x64) & DEBIAN(x64) ONLY**<br>
**FEEL FREE TO SUBMIT PULL REQUESTS**
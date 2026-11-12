<h1 align="center">
  csprecon
  <br>
</h1>
<h4 align="center">Discover new target domains using Content Security Policy</h4>
<h6 align="center"> Coded with 💙 by edoardottt </h6>
<p align="center">
  <a href="https://github.com/edoardottt/csprecon/actions">
      <img src="https://github.com/edoardottt/csprecon/actions/workflows/go.yml/badge.svg" alt="go action">
  </a>
<br>
  <!--Tweet button-->
  <a href="https://twitter.com/intent/tweet?text=csprecon%20-%20Reconnaissance%20tool%20based%20on%20Content%20Security%20Policy%20https%3A%2F%2Fgithub.com%2Fedoardottt%2Fcsprecon%20%23golang%20%23github%20%23linux%20%23infosec%20%23bugbounty" target="_blank">Share on Twitter!
  </a>
</p>

<p align="center">
  <a href="#install-">Install</a> •
  <a href="#get-started-">Get Started</a> •
  <a href="#examples-">Examples</a> •
  <a href="#changelog-">Changelog</a> •
  <a href="#contributing-">Contributing</a> •
  <a href="#license-">License</a>
</p>

<p align="center">
  <img src="https://github.com/edoardottt/images/blob/main/csprecon/csprecon.gif">
</p>
  
Install 📡
----------

### Homebrew

```console
brew install csprecon
```

### Snap

```console
sudo snap install csprecon
```

### Go

```console
go install github.com/edoardottt/csprecon/cmd/csprecon@latest
```

Get Started 🎉
----------

```console
Usage:
  csprecon [flags]

Flags:
INPUT:
   -u, -url string   Input domain
   -l, -list string  File containing input domains
   -cidr             Interpret input as CIDR

CONFIGURATIONS:
   -d, -domain string[]  Filter results belonging to these domains (comma separated)
   -c, -concurrency int  Concurrency level (default 50)
   -t, -timeout int      Connection timeout in seconds (default 10)
   -rl, -rate-limit int  Set a rate limit (per second)
   -px, -proxy string    Set a proxy server (URL)

BYPASS:
   -b, -bypass               Report known CSP bypass gadgets (CSPBypass dataset)
   -bf, -bypass-file string  Use a local data.tsv (CSPBypass format) instead of fetching

OUTPUT:
   -o, -output string  File to write output results
   -v, -verbose        Verbose output
   -s, -silent         Silent output. Print only results
   -j, -json           JSON output
```

Examples 💡
----------

Grab all possible results from single domain

```bash
csprecon -u https://www.github.com
```

```bash
echo https://www.github.com | csprecon
```

Grab all possible results from a list of domains (protocols needed!)

```bash
csprecon -l targets.txt
```

```bash
cat targets.txt | csprecon
```

Grab all possible results belonging to specific target(s) from a list of domains (protocols needed!)

```bash
cat targets.txt | csprecon -d google.com
```

Grab all possible results from single CIDR

```bash
csprecon -u 192.168.1.0/24 -cidr
```

Set a rate limit of 10 requests per second

```bash
cat targets.txt | csprecon -rl 10
```

JSON Output

```bash
cat targets.txt | csprecon -j
```

Use a Proxy (`http`, `https`, `socks5` or `socks5h`)

```bash
cat targets.txt | csprecon -px http://127.0.0.1:8080
```

Report known CSP bypass gadgets found in the target's CSP

```bash
csprecon -u https://www.github.com -b
```

Bring your own gadget list instead of fetching (CSPBypass `data.tsv` format)

```bash
csprecon -u https://www.github.com -bf ./data.tsv
```

> [!NOTE]
> The gadget dataset comes from the [CSPBypass](https://github.com/renniepak/CSPBypass) project (GPL-3.0).  
> csprecon does not bundle it: with `-b` it is fetched at runtime from the upstream repository
> and cached locally per user (`~/.cache/csprecon/` or the OS equivalent), falling back to the cached copy if the fetch fails.  
> Credit to [@renniepak](https://github.com/renniepak) and the CSPBypass contributors.

Changelog 📌
-------

Detailed changes for each release are documented in the [release notes](https://github.com/edoardottt/csprecon/releases).

Contributing 🛠
-------

Just open an [issue](https://github.com/edoardottt/csprecon/issues) / [pull request](https://github.com/edoardottt/csprecon/pulls).

Before opening a pull request, download [golangci-lint](https://golangci-lint.run/welcome/install/) and run

```bash
golangci-lint run
```

If there aren't errors, go ahead :)

In the news 📰
-------

- [Hive Five Newsletter by Securibee](https://www.hivefive.community/t/newsletter)
- [Trickest](https://twitter.com/trick3st/status/1788877498731696256)
- [Critical Thinking - Bug Bounty Podcast](https://blog.criticalthinkingpodcast.io/p/jason-haddix-returns)
- [tl;dr sec Newsletter](https://tldrsec.com/p/tldr-sec-225)

License 📝
-------

This repository is under [MIT License](https://github.com/edoardottt/csprecon/blob/main/LICENSE).  
[edoardottt.com](https://edoardottt.com/) to contact me.

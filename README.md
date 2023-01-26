<h1 align="center">
  csprecon
  <br>
</h1>

<h4 align="center">Discover new target domains using Content Security Policy</h4>

<h6 align="center"> Coded with 💙 by edoardottt </h6>

<p align="center">

  <a href="https://edoardoottavianelli.it">
      <img src="https://github.com/edoardottt/csprecon/actions/workflows/go.yml/badge.svg" alt="go action">
  </a>

  <a href="https://goreportcard.com/report/github.com/edoardottt/csprecon">
      <img src="https://goreportcard.com/badge/github.com/edoardottt/csprecon" alt="go report card">
  </a>

<br>
  <!--Tweet button-->
  <a href="https://twitter.com/intent/tweet?text=csprecon%20-%20Reconnaissance%20tool%20based%20on%20Content%20Security%20Policy%20https%3A%2F%2Fgithub.com%2Fedoardottt%2Fcsprecon%20%23golang%20%23github%20%23linux%20%23infosec%20%23bugbounty" target="_blank">Share on Twitter!
  </a>
</p>

<p align="center">
  <a href="#install-">Install</a> •
  <a href="#get-started-">Get Started</a> •
  <a href="#examples-bulb">Examples</a> •
  <a href="#changelog-">Changelog</a> •
  <a href="#contributing-">Contributing</a> •
  <a href="#license-">License</a>
</p>

<p align="center">
  <img src="https://github.com/edoardottt/images/blob/main/csprecon/csprecon.gif">
</p>
  
Install 📡
----------

```
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

CONFIGURATIONS:
   -d, -domain string[]  Filter results belonging to these domains (comma separated)
   -c, -concurrency int  Concurrency level (default 100)
   -t, -timeout int      Connection timeout in seconds (default 10)

OUTPUT:
   -o, -output string  File to write output results
   -v, -verbose        Verbose output
   -s, -silent         Silent output. Print only results
```

Examples :bulb:
----------

Grab all possible results from single domain
```bash
csprecon -u https://www.github.com
```

Grab all possible results from a list of domains (protocols needed!)
```bash
csprecon -l targets.txt
```

```bash
cat targets.txt | csprecon
```

Grab all possible results belonging to a specific target(s) from a list of domains (protocols needed!)
```bash
cat targets.txt | csprecon -d google.com
```

Changelog 📌
-------
Detailed changes for each release are documented in the [release notes](https://github.com/edoardottt/csprecon/releases).

Contributing 🛠
-------

Just open an [issue](https://github.com/edoardottt/csprecon/issues) / [pull request](https://github.com/edoardottt/csprecon/pulls).

Before opening a pull request, download [golangci-lint](https://golangci-lint.run/usage/install/) and run
```bash
golangci-lint run
```
If there aren't errors, go ahead :)


In the news 📰
-------

- [Hive Five Newsletter by Securibee](https://securib.ee/newsletter/)

License 📝
-------

This repository is under [MIT License](https://github.com/edoardottt/csprecon/blob/main/LICENSE).  
[edoardoottavianelli.it](https://www.edoardoottavianelli.it) to contact me.

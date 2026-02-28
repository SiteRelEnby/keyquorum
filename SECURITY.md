# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in keyquorum, **please do not open a public issue.**

Instead, use [GitHub Security Advisories](https://github.com/SiteRelEnby/keyquorum/security/advisories/new) to report it privately. This allows us to assess and fix the issue before public disclosure.

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment (what can an attacker do?)
- Suggested fix, if you have one

## Response

- Acknowledgement within 72 hours
- Assessment and plan within 1 week
- Fix released as soon as practical, coordinated with reporter

## Scope

Vulnerabilities in keyquorum itself, including:
- Secret material leaking via memory, logs, error messages, process table, or client responses
- Bypasses of memory protections (mlock, zeroize, DONTFORK, DONTDUMP)
- Bypasses of lockdown or strict_hardening mode
- Share format parsing issues that could cause crashes or undefined behavior
- Privilege escalation via the daemon or child processes

Out of scope:
- Vulnerabilities in upstream dependencies (report those to the dependency maintainer, but do let us know so we can track and update)
- Issues requiring physical access to the machine
- Social engineering attacks against share holders
- Theoretical attacks against Shamir's Secret Sharing itself (GF(256) is well-understood math from 1979)

## Supported Versions

Only the latest release is supported with security fixes. This project is pre-1.0; update promptly.

## macOS / Non-Linux

macOS builds are experimental and untested. Memory hardening features (DONTFORK, DONTDUMP, prctl) are unavailable on macOS. If you are using keyquorum on macOS for anything security-sensitive, you are on your own.

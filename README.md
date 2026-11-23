# xidor

Simple multithreaded IDOR parameter and value fuzzer in Python.

It takes a wordlist of parameter names and values, compares responses against a baseline (and an optional reference ID), strips out dynamic noise like UUIDs and timestamps, and flags responses that look different or expose interesting JSON keys.

> Only run this on targets you have permission to test (authorized pentests, bug bounty scope, or your own local labs).

## Setup

Requires Python 3.9+.

```bash
git clone [https://github.com/YOUR-USERNAME/xidor.git](https://github.com/YOUR-USERNAME/xidor.git)
cd xidor
pip install -r requirements.txt

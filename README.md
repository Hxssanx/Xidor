# xidor

A lightweight, multithreaded Python utility for identifying potential Insecure Direct Object Reference (IDOR) and broken access control issues during authorized web security assessments.

`xidor` tests query parameter keys and identifier patterns against a baseline and optional reference response, scoring anomalies using status codes, response similarity diffing, and sensitive JSON key detection.

> **Disclaimer:** This tool is intended strictly for authorized penetration testing, bug bounty programs within explicit scope, and local lab environments. Do not test targets without prior written permission.

# Go-guard

Protect your Go application with minimal effort.

Features:
* zero external dependencies, only std go library
* pluggable storage; included in-memory and file-based
* supports token and basic auth
* prevents bruteforce by slowing down failed request
* supports granular control by using zones
* can be used in most HTTP router - it's working as http.Handler wrapper

Check demo app for examples
# vscan-default-credentials-detector
Tries a set of known default username and password pairs, plus any operator supplied pairs from a JSON file, against the login form of the target supplied by the operator, and reports which username matched. Passwords are never written in clear: a successful record reports the username and a fixed masked marker in place of the password, in the console output, in verbose logs, and in the saved JSON file. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-default-credentials-detector`

## Usage
`./vscan-default-credentials-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `-d`: No description provided
- `-v`: Enable verbose output for debugging.
- `-o`: No description provided

## License
Copyright (c) ShadowStrikeHQ

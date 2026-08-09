# Credential Scanner

A lightweight Python utility that recursively scans the current user's home directory for potential hard-coded credentials.

It looks for items such as passwords, API keys, tokens, secrets, private keys, compound credential names, and credential-bearing connection URIs while applying filters to reduce common false positives.

## Features

- Scans common source-code, configuration, shell, infrastructure, and text-based file types
- Checks credential-sensitive files such as `.env`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, and common SSH private-key filenames
- Detects common credential assignments such as `password`, `api_key`, `client_secret`, and `AWS_SECRET_ACCESS_KEY`
- Detects URI-style embedded credentials such as `postgresql://user:password@host`
- Detects PEM private-key blocks
- Filters placeholders, environment-variable references, symbolic identifiers, and common code expressions
- Skips common dependency/build/cache directories
- Avoids scanning the scanner itself and its generated `credentials.txt` report
- Includes a `unittest` regression test suite

## Requirements

- Python 3
- No third-party packages are required

## Usage

Run the scanner:

`python Credential_Scanner.py`

The program scans `Path.home()` and writes detected findings to:

`credentials.txt`

in the same directory as the script.

## Testing

Run the included test suite with:

`python -m unittest -v test_credential_scanner.py`

If the scanner file is named `Credential_Scanner.py`, make sure the test file imports it with:

`import Credential_Scanner as scanner`

## Security Note

`credentials.txt` may contain complete credential values and private keys. Treat the report as sensitive data, review it carefully, and delete or protect it when it is no longer needed.

## Limitations

This is a heuristic scanner. It can produce false positives and may miss credentials that do not match its supported patterns or file-selection rules. A clean scan should not be treated as proof that no credentials are present.

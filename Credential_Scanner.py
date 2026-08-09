# Credential Scanner 
#
# Scans files in the user's home directory for potential hard-coded
# credentials, including passwords, API keys, tokens, secrets, and
# private keys.
#
# The scanner attempts to reduce false positives by ignoring placeholders,
# environment-variable references, symbolic identifiers, and common code expressions.



from pathlib import Path
import re
import ctypes
import sys

# -----------------------------
# Configuration
# -----------------------------

# File names commonly used to store application credentials or configuration.
INTERESTING_NAMES = {
    ".env",
    "credentials.json",
    "config.ini",
    "settings.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".envrc",
    ".terraformrc",
    ".dockercfg",
    "credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk"
}

# 
SHELL_SUBEXPRESSION_EXTENSIONS = {".ps1", ".sh", ".bash", ".zsh"}

# Text-based file types that may reasonably contain hard-coded credentials.
ALLOWED_EXTENSIONS = {
    ".txt",
    ".ini",
    ".cfg",
    ".json",
    ".yaml",
    ".yml",
    ".py",
    ".ps1",
    ".bat",
    ".cmd",
    ".pem",
    ".key",
    ".conf",
    ".cnf",
    ".properties",
    ".toml",
    ".xml",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".tf",
    ".tfvars",
    ".tfstate",
    ".hcl",
    ".js",
    ".ts",
    ".tsx",
    ".php",
    ".rb",
    ".java",
    ".cs",
    ".c",
    ".go",
    ".rs",
    ".kt",
    ".kts",
    ".swift",
    ".scala",
    ".groovy",
    ".gradle",
    ".lua",
    ".pl",
    ".pm",
    ".sql",
    ".ipynb",
    ".ovpn"
}

# Directories skipped to avoid dependencies, generated files, caches, and excessive noise
EXCLUDED_DIRECTORIES = {
    ".git",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "site-packages",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".idea",
    ".vscode",
}

# Common non-secret values that should not be reported as credentials.
PLACEHOLDER_VALUES = {
    "",
    "none",
    "null",
    "nil",
    "undefined",
    "true",
    "false",

    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",

    "example",
    "sample",
    "test",
    "testing",
    "dummy",
    "placeholder",

    "changeme",
    "change_me",
    "change-me",

    "your_password",
    "your-password",
    "yourpassword",

    "your_token",
    "your-token",
    "yourtoken",

    "your_api_key",
    "your-api-key",
    "yourapikey",

    "insert_here",
    "replace_me",
}

# Prefixes indicating that a value is obtained dynamically rather than hard-coded.
REFERENCE_PREFIXES = (
    "os.getenv(",
    "getenv(",
    "input(",
    "getpass(",
    "config.get(",
    "self.",
    "settings.",
)

# Patterns used to recognize customizable example values such as YOUR_TOKEN or INSERT_HERE.
PLACEHOLDER_PATTERNS = [
    r"^your[_-]",
    r"[_-]here$",
    r"^insert[_-]",
    r"^replace[_-]",
    r"^enter[_-]",
    r"^example[_-]",
    r"^sample[_-]",
    r"^dummy[_-]",
    r"^(?:[A-Za-z][A-Za-z0-9]*[_-])?x{8,}$",
    r"^variable\d+$",
    r"^string\d+$",
]
PLACEHOLDER_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in PLACEHOLDER_PATTERNS
]

# Common language/type identifiers that can appear near credential-like names but are not secrets.
MIN_SECRET_LENGTH = 8

# Common programming-language/type words that frequently appear after a
# credential-looking name but are not credential values.
NON_SECRET_WORDS = {
    "str", "string", "int", "integer", "float", "bool", "boolean",
    "bytes", "bytearray", "dict", "list", "tuple", "set", "object",
    "any", "optional", "value", "values", "default", "config",
    "settings", "data", "result", "response", "request", "pwr", 
    "instagram", "pass:insta", "$insta::secret",
    "search-result", "response?.password", "operator", "variable", "string",
    "invalid refresh token"
}

IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

DOTTED_REFERENCE_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$"
)

FUNCTION_CALL_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*\("
)

BRACKET_REFERENCE_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*\["
)

CODE_OPERATOR_EXPRESSION_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.]*(?:\[[^\r\n]*\])?\s*[+\-*/%&|^]"
)

POWERSHELL_REFERENCE_PATTERN = re.compile(
    r"^\$(?:(?:env|global|script|local|private):)?"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    r"(?:\[[^\r\n]*\])?$",
    re.IGNORECASE,
)

BATCH_REFERENCE_PATTERN = re.compile(
    r"^(?:%[A-Za-z_][A-Za-z0-9_]*%|![A-Za-z_][A-Za-z0-9_]*!)$"
)

OPERATOR_ONLY_PATTERN = re.compile(r"^[=:+\-*/%&|^~<>!?]+$")

# File types where unquoted credential-like values are more
# likely to be code expressions or variable references than literal secrets.
REFERENCE_HEAVY_EXTENSIONS = {".py", ".ps1"}

# Used to reject quoted or unquoted names that look like symbolic credential
# identifiers, e.g. SendGridAPIKey or PROJECT_SECRET, rather than secret data.
CREDENTIAL_IDENTIFIER_SUFFIXES = (
    "apikey",
    "privatekey",
    "secretkey",
    "secretaccesskey",
    "accesskeyid",
    "encryptionkey",
    "signingkey",
    "masterkey",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
)

# Recognizes beginning of private key (-----BEGIN PRIVATE KEY-----, -----BEGIN RSA PRIVATE KEY-----, etc.)
PRIVATE_KEY_HEADER_PATTERN = re.compile(
    r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----",
    re.IGNORECASE,
)

# Recognizes the end of a private key.
PRIVATE_KEY_END_PATTERN = re.compile(
    r"-----END (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----",
    re.IGNORECASE,
)

# This pattern deliberately distinguishes quoted and unquoted values and avoids
# treating comparison operators such as ==, !=, <=, and >= as assignments.
SECRET_PATTERN = re.compile(
    r"""
        (?<![A-Za-z0-9])
        (?P<key_quote>["']?)
        (?P<credential_type>secret[_-]?access[_-]?key|access[_-]?key[_-]?id|encryption[_-]?key|signing[_-]?key|master[_-]?key|client[_-]?secret|consumer[_-]?secret|refresh[_-]?token|access[_-]?token|auth[_-]?token|private[_-]?key|secret[_-]?key|api[_-]?key|password|passwd|pwd|secret|token)
        (?P=key_quote)
        \s*
        (?P<operator>
            :(?!=)
            |
            (?<![=!<>:])=(?!=)
        )
        \s*
        (?:
            (?P<value_quote>["'])
            (?P<quoted_value>[^"'\r\n]*)
            (?P=value_quote)
            |
            (?P<bare_value>[^\s,}\];#]+)
        )
    """,
    re.IGNORECASE | re.VERBOSE
)

# Recognizes URI-style connection strings containing embedded credentials.
CONNECTION_URI_PATTERN = re.compile(
    r"""
        (?P<connection_uri>
            [A-Za-z][A-Za-z0-9+.-]*://
            (?P<username>[^:@/\s"'<>]*)
            :
            (?P<password>[^@/\s"'<>]+)
            @
            [^\s"'<>]+
        )
    """,
    re.IGNORECASE | re.VERBOSE
)


# -----------------------------
# Administrator Functions
# -----------------------------
# Return True if the program is running with administrator privileges.
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Request administrator privileges on Windows and relaunch the program if necessary.
def request_admin():
    if is_admin():
        return

    script_path = str(Path(sys.argv[0]).resolve())

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        f'"{script_path}"',
        None,
        1
    )

    if result <= 32:
        print("Failed to launch program as administrator.")
        print(f"ShellExecuteW error code: {result}")
        input("Press Enter to exit.")
        sys.exit(1)

    sys.exit()


# -----------------------------
# File Selection Functions
# -----------------------------
# Return True if the file name is explicitly marked as credential-sensitive.
def is_interesting_file(path):
    name = path.name.lower()
    if name in INTERESTING_NAMES:
        return True
    elif name.startswith(".env."):
        return True
    else:
        return False

# Return True if a file should be scanned based on its name or extension.
def should_scan_file(path):
    if is_interesting_file(path):
        return True

    elif path.suffix.lower() in ALLOWED_EXTENSIONS:
        return True
    else:
        return False

# Return True if any part of a path belongs to an excluded directory.        
def is_excluded_path(path):
    return any(
        part.lower() in EXCLUDED_DIRECTORIES
        for part in path.parts
    )

# Return True if a path is the scanner itself or its generated results file.
def is_scanner_file(path):
    program_path = (
        Path(sys.executable).resolve()
        if getattr(sys, "frozen", False)
        else Path(__file__).resolve()
    )
    output_path = program_path.parent / "credentials.txt"
    resolved_path = path.resolve()
    return resolved_path == program_path or resolved_path == output_path

# -----------------------------
# Credential Scanning Functions
# -----------------------------
# Display a detected credential and add its formatted information to the findings list.
def record_finding(findings, path, line_num, credential_type, credential_value):
    print(f"[Path: {path}:{line_num}]")
    print(f"Type: {credential_type}")
    print(f"Credential: {credential_value}")
    print()

    findings.append(
        f"Path: {path}\n"
        f"Line: {line_num}\n"
        f"Type: {credential_type}\n"
        f"Credential: {credential_value}\n\n"
    )
    

# -----------------------------
# False Positive Filtering
# -----------------------------
# Normalize surrounding syntax before evaluating a candidate for false positives.
def normalize_candidate_value(value):
    cleaned = value.strip()

    if cleaned.startswith(r'\"') and cleaned.endswith(r'\"'):
        cleaned = cleaned[2:-2]
    elif cleaned.startswith(r"\'") and cleaned.endswith(r"\'"):
        cleaned = cleaned[2:-2]

    return cleaned.strip().strip("\"'<>")

# Return True if a value appears to be an example, placeholder, or intentionally empty value.    
def is_placeholder(value):
    cleaned = value.strip().strip("\"'<>").lower()

    if cleaned in PLACEHOLDER_VALUES:
        return True

    for pattern in PLACEHOLDER_PATTERNS:
        if pattern.search(cleaned):
            return True

    return False

# Return True if a value references an environment variable instead of containing a literal secret.
def is_environment_reference(value):
    value = value.strip()

    patterns = [
        r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$",
        r"^\$[A-Za-z_][A-Za-z0-9_]*$",
        r"^\$(?:env|global|script|local|private):[A-Za-z_][A-Za-z0-9_]*$",
        r"^\$\{(?:env|global|script|local|private):[A-Za-z_][A-Za-z0-9_]*\}$",
        r"^%[A-Za-z_][A-Za-z0-9_]*%$",
        r"^![A-Za-z_][A-Za-z0-9_]*!$",
    ]

    return any(
        re.fullmatch(pattern, value, re.IGNORECASE)
        for pattern in patterns
    )

# Return True if a value appears to reference another variable, configuration value, or user input.
def is_variable_reference(value):
    cleaned = value.strip().lower()

    if cleaned.startswith(REFERENCE_PREFIXES):
        return True

    return False

# "Return True if a value resembles a credential variable name rather than credential data.
def looks_like_symbolic_credential_name(value):
    """Return True for names such as SendGridAPIKey or PROJECT_SECRET."""
    cleaned = value.strip().strip("\"'<> ")

    if not IDENTIFIER_PATTERN.fullmatch(cleaned):
        return False

    compact = re.sub(r"[_-]", "", cleaned).lower()
    if not compact.endswith(CREDENTIAL_IDENTIFIER_SUFFIXES):
        return False

    # Require obvious identifier-style formatting so an all-lowercase literal
    # such as "mysecretphrase" is not automatically discarded.
    has_identifier_formatting = (
        "_" in cleaned
        or "-" in cleaned
        or cleaned.isupper()
        or bool(re.search(r"[a-z][A-Z]", cleaned))
        or bool(re.search(r"[A-Z]{2,}[A-Z][a-z]", cleaned))
    )
    return has_identifier_formatting


# "Return True if a value appears to be a code expression or variable reference rather than a literal secret.
def looks_like_code_expression(value):
    cleaned = value.strip()
    expression_candidate = cleaned
    
    if OPERATOR_ONLY_PATTERN.fullmatch(cleaned):
        return True
    
    # Shell command substitution such as $(python3 ...) is code, not a literal secret

    if FUNCTION_CALL_PATTERN.match(expression_candidate):
        return True

    # Covers indexing/slicing and references such as token[len(h):] or
    # os.environ["TOKEN"]. The bare-value regex may stop before a closing ']'.
    if BRACKET_REFERENCE_PATTERN.match(expression_candidate):
        return True

    if CODE_OPERATOR_EXPRESSION_PATTERN.match(expression_candidate):
        return True

    if POWERSHELL_REFERENCE_PATTERN.fullmatch(cleaned):
        return True

    if BATCH_REFERENCE_PATTERN.fullmatch(cleaned):
        return True

    if DOTTED_REFERENCE_PATTERN.fullmatch(expression_candidate):
        return True

    # The scanner's bare-value capture can include closing punctuation from a
    # surrounding function call, e.g. t.projectSecret). Classify the underlying
    # dotted/name reference instead of reporting the punctuation as a secret.
    reference_candidate = expression_candidate.rstrip(")]},;:")
    
    if reference_candidate != expression_candidate:
        if DOTTED_REFERENCE_PATTERN.fullmatch(reference_candidate):
            return True
        if IDENTIFIER_PATTERN.fullmatch(reference_candidate):
            return True

    # Common expression/template prefixes rather than literal credentials.
    if cleaned.startswith(("${", "{{", "<%", "lambda", "f\"", "f'")):
        return True
    else:
        return False

# Return True if a credential-like match should be ignored as a likely false positive.
def is_false_positive(
    value,
    *,
    path=None,
    is_quoted=False,
    key_quoted=False,
    operator=None,
):
    cleaned = normalize_candidate_value(value)
    lowered = cleaned.lower()

    if is_placeholder(cleaned):
        return True

    if is_environment_reference(cleaned):
        return True

    if is_variable_reference(cleaned):
        return True

    # In Powershell, and unquoted $(...) value is a subexpression and not a secret
    if(path is not None and path.suffix.lower() in SHELL_SUBEXPRESSION_EXTENSIONS and not is_quoted and cleaned.startswith("$(")):
        return True

    # Gets rid of one-character matches, short variable names such as pwr,
    # short type names such as str, and other tiny fragments.
    if len(cleaned) < MIN_SECRET_LENGTH:
        return True

    if lowered in NON_SECRET_WORDS:
        return True

    # Reject symbolic credential names even when they are quoted or appear in
    # a non-Python file. Examples: SendGridAPIKey, SENDGRID_API_KEY.
    if looks_like_symbolic_credential_name(cleaned):
        return True

    if OPERATOR_ONLY_PATTERN.fullmatch(cleaned):
        return True

    # In Python, "password: str" is a type annotation, not a YAML-style
    # key/value pair. Quoted keys such as {"password": "..."} remain valid.
    if (
        path is not None
        and path.suffix.lower() == ".py"
        and operator == ":"
        and not key_quoted
    ):
        return True

    # In reference-heavy code files, unquoted identifiers are variables or
    # expressions, not hard-coded string literals. This now covers PowerShell
    # as well as Python.
    if (
        path is not None
        and path.suffix.lower() in REFERENCE_HEAVY_EXTENSIONS
        and not is_quoted
    ):
        code_candidate = cleaned.lstrip("(").strip()
        if IDENTIFIER_PATTERN.fullmatch(code_candidate):
            return True

        if looks_like_code_expression(code_candidate):
            return True

    # For every file type, obvious calls/dotted/indexed references are code when
    # they are unquoted. This catches getenv(...), config.value, token[idx], etc.
    if not is_quoted and looks_like_code_expression(cleaned):
        return True

    return False


# -----------------------------
# Credential Scanning
# -----------------------------
# Scan one line for private-key headers and hard-coded credential assignments.
def scan_line(path, line_num, line):
    findings = []

    for match in SECRET_PATTERN.finditer(line):
        credential_type = match.group("credential_type")
        credential_value = (
            match.group("quoted_value")
            if match.group("quoted_value") is not None
            else match.group("bare_value")
        )
        is_quoted = match.group("value_quote") is not None
        key_quoted = bool(match.group("key_quote"))
        operator = match.group("operator")
            
        if is_false_positive(
            credential_value,
            path=path,
            is_quoted=is_quoted,
            key_quoted=key_quoted,
            operator=operator,
        ):
            continue
        record_finding(findings,path,line_num,credential_type,credential_value)

    for match in CONNECTION_URI_PATTERN.finditer(line):
        connection_uri = match.group("connection_uri")
        connection_password = match.group("password")
        if is_false_positive(connection_password,path=path,is_quoted=True):
            continue
        record_finding(findings,path,line_num,"connection_uri",connection_uri)  
        
    return findings     

# Scan a text file line by line and return all credential findings from that file.
def scan_file(path):
    findings = []
    private_key_lines = []
    private_key_start_line = None
    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line_num, line in enumerate(file, 1):
                if private_key_lines:
                    private_key_lines.append(line.rstrip("\n"))
                    if PRIVATE_KEY_END_PATTERN.fullmatch(line.strip()):
                        private_key = "\n".join(private_key_lines)
                        record_finding(findings, path, private_key_start_line, "private_key", private_key)
                        private_key_lines = []
                        private_key_start_line = None
                    continue
                if PRIVATE_KEY_HEADER_PATTERN.fullmatch(line.strip()):
                    private_key_start_line = line_num
                    private_key_lines = [line.rstrip("\n")]
                    continue
                findings.extend(scan_line(path, line_num, line))
            
    except PermissionError:
        pass
    except OSError as error:
        print(f"[Warning] Could not read {path}: {error}")

    return findings

# Recursively scan eligible files below root and return all detected credential findings.
def scan_directory(root):
    findings = []
    for path in root.rglob("*"):

        if is_excluded_path(path):
            continue
        if not path.is_file():
            continue
        if is_scanner_file(path):
            continue

        if is_interesting_file(path):
            print(f"[Interesting file] - {path}")

        if not should_scan_file(path):
            continue

        findings.extend(scan_file(path))
    return findings


# -----------------------------
# Output Functions
# -----------------------------
# Write all credential findings to credentials.txt beside the script or packaged executable.
def save_results(findings):
    base_dir = (
        Path(sys.executable).resolve().parent
        if getattr(sys, "frozen", False)
        else Path(__file__).resolve().parent
    )

    output_file = base_dir / "credentials.txt"

    output_file.write_text(
        "\n".join(findings) + "\n",
        encoding="utf-8"
    )

    print(f"Results saved to: {output_file}")



# -----------------------------
# Main Function
# -----------------------------


# Set the scan root, run the credential scan, and save the resulting findings.
def main():
    # request_admin() # Most likely NOT required
    # print(f"Running as administrator: {bool(is_admin())}")  

    root = Path.home() # Set the root to the home directory
    print(f"\nScanning: {root}\n")
    findings = scan_directory(root)
    save_results(findings)
    input()

if __name__ == "__main__":
    main()

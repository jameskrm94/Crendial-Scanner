# Kyle Martin
# Description: This program scans files in the user's home directory
# for potential passwords, keys, tokens, and other credentials.
# Use py -m PyInstaller --clean --onefile "credential_scanner.py" to create .exe file

from pathlib import Path
import re
import ctypes
import sys

# -----------------------------
# Configuration
# -----------------------------

INTERESTING_NAMES = {
    ".env",
    "credentials.json",
    "config.ini",
    "settings.json",
}

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
}

EXCLUDED_DIRECTORIES = {
    ".git",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "site-packages",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".idea",
    ".vscode",
}

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

REFERENCE_PREFIXES = (
    "os.getenv(",
    "getenv(",
    "input(",
    "getpass(",
    "config.get(",
    "self.",
    "settings.",
)

PLACEHOLDER_PATTERNS = [
    r"^your[_-]",
    r"[_-]here$",
    r"^insert[_-]",
    r"^replace[_-]",
    r"^enter[_-]",
    r"^example[_-]",
    r"^sample[_-]",
    r"^dummy[_-]",
]

PLACEHOLDER_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in PLACEHOLDER_PATTERNS
]

# Values shorter than this are usually variable names, operators, or placeholders
# rather than useful hard-coded secrets. Raise this for fewer false positives.
MIN_SECRET_LENGTH = 8

# Common programming-language/type words that frequently appear after a
# credential-looking name but are not credential values.
NON_SECRET_WORDS = {
    "str", "string", "int", "integer", "float", "bool", "boolean",
    "bytes", "bytearray", "dict", "list", "tuple", "set", "object",
    "any", "optional", "value", "values", "default", "config",
    "settings", "data", "result", "response", "request", "pwr",
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

# Python and PowerShell normally require literal strings to be quoted. In these
# files, a bare identifier such as SendGridAPIKey is much more likely to be a
# variable/reference than an actual secret value.
REFERENCE_HEAVY_EXTENSIONS = {".py", ".ps1"}

# Used to reject quoted or unquoted names that look like symbolic credential
# identifiers, e.g. SendGridAPIKey or PROJECT_SECRET, rather than secret data.
CREDENTIAL_IDENTIFIER_SUFFIXES = (
    "apikey", "token", "secret", "password", "passwd", "pwd"
)

# This pattern deliberately distinguishes quoted and unquoted values and avoids
# treating comparison operators such as ==, !=, <=, and >= as assignments.
SECRET_PATTERN = re.compile(
    r"""
        (?<![A-Za-z0-9_])
        (?P<key_quote>["']?)
        (?P<credential_type>password|passwd|pwd|api[_-]?key|secret|token)
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


# -----------------------------
# Administrator Functions
# -----------------------------

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

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
# File Functions
# -----------------------------

def is_interesting_file(path):
    return path.name.lower() in INTERESTING_NAMES


def should_scan_file(path):
    if is_interesting_file(path):
        return True

    if path.suffix.lower() in ALLOWED_EXTENSIONS:
        return True

    return False


def scan_file(path):
    try:
        with path.open(
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line_num, line in enumerate(file, 1):

                # finditer() catches more than one credential-looking assignment
                # on the same line instead of stopping after the first one.
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

                    print(f"[Possible secret] {path}:{line_num}")
                    print(f"Type: {credential_type}")
                    print(f"Credential: {credential_value}")
                    print()

    except PermissionError:
        pass

    except OSError as error:
        print(f"[Warning] Could not read {path}: {error}")

        

def is_placeholder(value):
    cleaned = value.strip().strip("\"'<>").lower()

    if cleaned in PLACEHOLDER_VALUES:
        return True

    for pattern in PLACEHOLDER_PATTERNS:
        if pattern.search(cleaned):
            return True

    return False


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


def is_variable_reference(value):
    cleaned = value.strip().lower()

    if cleaned.startswith(REFERENCE_PREFIXES):
        return True

    return False



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


def looks_like_code_expression(value):
    cleaned = value.strip()

    if OPERATOR_ONLY_PATTERN.fullmatch(cleaned):
        return True

    if FUNCTION_CALL_PATTERN.match(cleaned):
        return True

    # Covers indexing/slicing and references such as token[len(h):] or
    # os.environ["TOKEN"]. The bare-value regex may stop before a closing ']'.
    if BRACKET_REFERENCE_PATTERN.match(cleaned):
        return True

    if CODE_OPERATOR_EXPRESSION_PATTERN.match(cleaned):
        return True

    if POWERSHELL_REFERENCE_PATTERN.fullmatch(cleaned):
        return True

    if BATCH_REFERENCE_PATTERN.fullmatch(cleaned):
        return True

    if DOTTED_REFERENCE_PATTERN.fullmatch(cleaned):
        return True

    # The scanner's bare-value capture can include closing punctuation from a
    # surrounding function call, e.g. t.projectSecret). Classify the underlying
    # dotted/name reference instead of reporting the punctuation as a secret.
    reference_candidate = cleaned.rstrip(")]},;:")
    if reference_candidate != cleaned:
        if DOTTED_REFERENCE_PATTERN.fullmatch(reference_candidate):
            return True
        if IDENTIFIER_PATTERN.fullmatch(reference_candidate):
            return True

    # Common expression/template prefixes rather than literal credentials.
    if cleaned.startswith(("${", "{{", "<%", "lambda", "f\"", "f'")):
        return True

    return False


def is_false_positive(
    value,
    *,
    path=None,
    is_quoted=False,
    key_quoted=False,
    operator=None,
):
    cleaned = value.strip().strip("\"'<>")
    lowered = cleaned.lower()

    if is_placeholder(cleaned):
        return True

    if is_environment_reference(cleaned):
        return True

    if is_variable_reference(cleaned):
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
        if IDENTIFIER_PATTERN.fullmatch(cleaned):
            return True

        if looks_like_code_expression(cleaned):
            return True

    # For every file type, obvious calls/dotted/indexed references are code when
    # they are unquoted. This catches getenv(...), config.value, token[idx], etc.
    if not is_quoted and looks_like_code_expression(cleaned):
        return True

    return False

        
def is_excluded_path(path):
    return any(
        part.lower() in EXCLUDED_DIRECTORIES
        for part in path.parts
    )


def scan_directory(root):
    for path in root.rglob("*"):

        if is_excluded_path(path):
            continue

        if not path.is_file():
            continue

        if is_interesting_file(path):
            print(f"[Interesting file] - {path}")

        if not should_scan_file(path):
            continue

        scan_file(path)


# -----------------------------
# Main Function
# -----------------------------


def main():
    # request_admin() # Most likely not required
    # print(f"Running as administrator: {bool(is_admin())}")  


    root = Path.home() # Set the root to the home directory
    print(f"\nScanning: {root}\n")
    scan_directory(root)
    input()

if __name__ == "__main__":
    main()

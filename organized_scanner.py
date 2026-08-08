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

SECRET_PATTERN = re.compile(
    r"""["']?(password|passwd|pwd|api[_-]?key|secret|token)["']?
        \s*[:=]\s*
        ["']?([^"'\s,}]+)""",
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

                match = SECRET_PATTERN.search(line)

                if not match:
                    continue

                credential_type = match.group(1)
                credential_value = match.group(2)

                if is_false_positive(credential_value):
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
        r"^%[A-Za-z_][A-Za-z0-9_]*%$",
    ]

    return any(
        re.fullmatch(pattern, value)
        for pattern in patterns
    )


def is_variable_reference(value):
    cleaned = value.strip().lower()

    if cleaned.startswith(REFERENCE_PREFIXES):
        return True

    return False



def is_false_positive(value):
    if is_placeholder(value):
        return True

    if is_environment_reference(value):
        return True

    if is_variable_reference(value):
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

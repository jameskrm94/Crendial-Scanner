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
import os
import codecs

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
    r"^variable-\d+$",
    r"^string-\d+$",
]
PLACEHOLDER_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in PLACEHOLDER_PATTERNS
]

# Common language/type identifiers that can appear near credential-like names but are not secrets.
DEFAULT_MIN_SECRET_LENGTH = 8

MIN_SECRET_LENGTH_BY_TYPE = {
    "password": 4,
    "passwd": 4,
    "pwd": 4,
}

# Common programming-language/type words that frequently appear after a
# credential-looking name but are not credential values.
NON_SECRET_WORDS = {
    "str", "string", "int", "integer", "float", "bool", "boolean",
    "bytes", "bytearray", "dict", "list", "tuple", "set", "object",
    "any", "optional", "value", "values", "default", "config",
    "settings", "data", "result", "response", "request", "pwr", 
    "instagram", "pass:insta", "$insta::secret",
    "search-result", "response?.password", "operator", "variable", "string",
    "invalid refresh token", "$dir/private/cakey.pem", "$(python3", "selected",
    "token", "files", "await"
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
REFERENCE_HEAVY_EXTENSIONS = {
    ".py",
    ".ps1",
    ".js",
    ".ts",
    ".tsx",
}

# JavaScript/TypeScript files may contain generated or minified application
# bundles where generic words such as token, password, and secret occur
# thousands of times as normal program identifiers.
HIGH_CONFIDENCE_ONLY_EXTENSIONS = {
    ".js",
    ".ts",
    ".tsx",
}

# Extremely long source lines are usually minified/generated code.
MINIFIED_LINE_LENGTH = 2000

# Directory names commonly associated with installed/generated application code.
GENERATED_CODE_PATH_PARTS = {
    "extensions",
    "solutionpackages",
    "offlinefiles",
    "vendor",
}

# Known test/fixture locations that may intentionally contain sample
# credentials, private keys, certificates, or authentication data.
EXCLUDED_PATH_PATTERNS = (
    r"\\Programs\\Python\\Python\d+\\Lib\\test\\",
)

# Tracks findings that have already been reported during the current scan.
# This prevents identical matches at the same file and line from being
# printed and saved multiple times.
SEEN_FINDINGS = set()


# Confidence thresholds. Scores are heuristic evidence scores,
# not probabilities that a credential is valid.
CONFIDENCE_HIGH_THRESHOLD = 80
CONFIDENCE_MEDIUM_THRESHOLD = 50

# Configuration-oriented file types are stronger evidence of an
# intentionally stored literal credential than ordinary source code.
CONFIG_LIKE_EXTENSIONS = {
    ".ini",
    ".cfg",
    ".json",
    ".yaml",
    ".yml",
    ".conf",
    ".cnf",
    ".properties",
    ".toml",
    ".tfvars",
    ".hcl",
}

# Generic credential names that provide stronger evidence than broad
# terms such as simply "token" or "secret".
STRONG_GENERIC_CREDENTIAL_TYPES = {
    "secretaccesskey",
    "clientsecret",
    "consumersecret",
    "privatekey",
    "secretkey",
    "apikey",
    "password",
    "passwd",
    "pwd",
    "refreshtoken",
    "accesstoken",
    "authtoken",
    "encryptionkey",
    "signingkey",
    "masterkey",
}

# Contexts where credential-shaped strings are more likely to be
# examples or documentation. Findings are downgraded, not discarded.
EXAMPLE_CONTEXT_PARTS = {
    "docs",
    "documentation",
    "example",
    "examples",
    "sample",
    "samples",
    "fixtures",
}


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
            "
            (?P<double_quoted_value>(?:\\.|[^"\\\r\n])*)
            "
            |
            '
            (?P<single_quoted_value>(?:\\.|[^'\\\r\n])*)
            '
            |
            (?!["'])
            (?P<bare_value>[^\s,}\];#]+)
        )
    """,
    re.IGNORECASE | re.VERBOSE
)

# Provider-specific credential formats.
#
# IMPORTANT:
# Some providers officially guarantee only the prefix, not the complete
# token length/character set. In those cases the suffix rules below are
# intentionally conservative scanner heuristics.
PROVIDER_SECRET_PATTERNS = (
    {
        "provider": "GitHub",
        "credential_type": "github_token",
        "base_score": 90,
        "pattern": re.compile(
            r"(?<![A-Za-z0-9_])"
            r"(?:"
            r"github_pat_[A-Za-z0-9_]{20,}"
            r"|(?:ghp|gho|ghu|ghr)_[A-Za-z0-9]{20,}"
            r"|ghs_[A-Za-z0-9_.-]{20,}"
            r")"
            r"(?![A-Za-z0-9_.-])"
        ),
    },

    {
        "provider": "Stripe",
        "credential_type": "stripe_secret",
        "base_score": 90,
        "pattern": re.compile(
            r"(?<![A-Za-z0-9_])"
            r"(?:"
            r"sk_(?:live|test)_[A-Za-z0-9]{16,}"
            r"|whsec_[A-Za-z0-9]{16,}"
            r")"
            r"(?![A-Za-z0-9])"
        ),
    },

    {
        "provider": "GitLab",
        "credential_type": "gitlab_token",
        "base_score": 88,
        "pattern": re.compile(
            r"(?<![A-Za-z0-9_-])"
            r"(?:"
            r"glpat-|gloas-|gldt-|glrt-|glrtr-|glcbt-|"
            r"glptt-|glft-|glimt-|glagent-|glwt-|glsoat-|glffct-"
            r")"
            r"[A-Za-z0-9_-]{12,}"
            r"(?![A-Za-z0-9_-])"
        ),
    },

    {
        "provider": "PyPI",
        "credential_type": "pypi_token",
        "base_score": 95,
        "pattern": re.compile(
            r"(?<![A-Za-z0-9_-])"
            r"pypi-[A-Za-z0-9_-]{85,}"
            r"(?![A-Za-z0-9_-])"
        ),
    },

    {
        "provider": "Slack",
        "credential_type": "slack_token",
        "base_score": 88,
        "pattern": re.compile(
            r"(?<![A-Za-z0-9_-])"
            r"(?:xoxb|xoxp|xapp|xwfp)-"
            r"[A-Za-z0-9-]{10,}"
            r"(?![A-Za-z0-9-])"
        ),
    },
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


def is_excluded_path(path):
    """
    Return True when a file belongs to a known test or fixture location
    that intentionally contains credential-like sample data.
    """

    path_string = str(path)

    return any(
        re.search(
            pattern,
            path_string,
            re.IGNORECASE
        )
        for pattern in EXCLUDED_PATH_PATTERNS
    )

# 
def should_use_high_confidence_only(path, line):
    """
    Return True when generic credential-name matching should be disabled
    because the file appears to contain generated or minified JS/TS code.
    """

    extension = path.suffix.lower()

    if extension not in HIGH_CONFIDENCE_ONLY_EXTENSIONS:
        return False

    # Very long lines are characteristic of minified bundles.
    if len(line) >= MINIFIED_LINE_LENGTH:
        return True

    # Common explicitly minified/bundled filenames.
    filename = path.name.lower()

    if ".min." in filename:
        return True

    if filename.endswith(".bundle.js"):
        return True

    # Installed/generated application directories.
    path_parts = {
        part.lower()
        for part in path.parts
    }

    if path_parts.intersection(GENERATED_CODE_PATH_PARTS):
        return True

    return False


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
def record_finding(
    findings,
    path,
    line_num,
    credential_type,
    credential_value,
    *,
    confidence,
    confidence_score,
    detection_method,
    confidence_reasons,
    provider=None,
):
    fingerprint = (
        str(path),
        line_num,
        credential_type.lower(),
        credential_value,
    )

    if fingerprint in SEEN_FINDINGS:
        return

    SEEN_FINDINGS.add(fingerprint)

    print(f"[Path: {path}:{line_num}]")
    print(f"Type: {credential_type}")

    if provider:
        print(f"Provider: {provider}")

    print(f"Confidence: {confidence}")
    print(f"Confidence Score: {confidence_score}/100")
    print(f"Detection: {detection_method}")
    print(
        f"Confidence Basis: "
        f"{'; '.join(confidence_reasons)}"
    )
    print(f"Credential: {credential_value}")
    print()

    output_lines = [
        f"Path: {path}",
        f"Line: {line_num}",
        f"Type: {credential_type}",
    ]

    if provider:
        output_lines.append(
            f"Provider: {provider}"
        )

    output_lines.extend(
        [
            f"Confidence: {confidence}",
            f"Confidence Score: {confidence_score}/100",
            f"Detection: {detection_method}",
            (
                f"Confidence Basis: "
                f"{'; '.join(confidence_reasons)}"
            ),
            f"Credential: {credential_value}",
            "",
        ]
    )

    findings.append(
        "\n".join(output_lines) + "\n"
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

# Get the minimum length that a secret can be based on credential type
def get_min_secret_length(credential_type):
    normalized_type = (
        credential_type
        .lower()
        .replace("_", "")
        .replace("-", "")
    )

    return MIN_SECRET_LENGTH_BY_TYPE.get(normalized_type, DEFAULT_MIN_SECRET_LENGTH)


def looks_like_non_secret_structure(value, *, is_quoted=False):
    """Return True for obvious non-secret paths, URLs, and code structures."""
    cleaned = value.strip()

    # XPath / DOM selectors are locations in a document, not credentials.
    if re.match(
        r"^(?:/html/|//\*?\[|//[A-Za-z])",
        cleaned,
        re.IGNORECASE
    ):
        return True

    # Ordinary HTTP/HTTPS URLs are endpoints or documentation rather than
    # credential values. Credential-bearing connection URIs are handled
    # separately by CONNECTION_URI_PATTERN.
    if re.match(r"^https?://", cleaned, re.IGNORECASE):
        return True

    # Be more aggressive with syntax detection only for unquoted values.
    # A quoted password may legitimately contain punctuation such as + or &&.
    if not is_quoted:

        # Values beginning with these characters are commonly expressions,
        # arrays, objects, calls, concatenations, or member references.
        if cleaned.startswith(("{", "[", "(", "+", ".")):
            return True

        # Common JavaScript / TypeScript expression syntax.
        code_markers = (
            "?.",
            "??",
            "=>",
            ".concat(",
            "&&",
            "||",
            "===",
            "!==",
            "prototype.",
            "=void",
        )

        if any(marker in cleaned for marker in code_markers):
            return True

    return False


# Return True if a credential-like match should be ignored as a likely false positive.
def is_false_positive(value,*,credential_type=None,path=None,is_quoted=False,key_quoted=False,operator=None,):
    
    cleaned = normalize_candidate_value(value)
    lowered = cleaned.lower()

    if is_placeholder(cleaned):
        return True

    if is_environment_reference(cleaned):
        return True

    if is_variable_reference(cleaned):
        return True

    if looks_like_non_secret_structure(cleaned, is_quoted=is_quoted):
        return True

    # In Powershell, and unquoted $(...) value is a subexpression and not a secret
    if(path is not None and path.suffix.lower() in SHELL_SUBEXPRESSION_EXTENSIONS and not is_quoted and cleaned.startswith("$(")):
        return True

    # Gets rid of one-character matches, short variable names such as pwr,
    # short type names such as str, and other tiny fragments.
    minimum_length = (
        get_min_secret_length(credential_type)
        if credential_type
        else DEFAULT_MIN_SECRET_LENGTH
    )
        
    if len(cleaned) < minimum_length:
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
    if (path is not None and path.suffix.lower() in REFERENCE_HEAVY_EXTENSIONS and not is_quoted
    ):
        return True

    # For every file type, obvious calls/dotted/indexed references are code when
    # they are unquoted. This catches getenv(...), config.value, token[idx], etc.
    if not is_quoted and looks_like_code_expression(cleaned):
        return True

    return False

# -----------------------------
# Provider / Confidence Functions
# -----------------------------

def detect_provider_secrets(line):
    """
    Return provider-specific credential matches found in a line.
    """

    detections = []

    for rule in PROVIDER_SECRET_PATTERNS:
        for match in rule["pattern"].finditer(line):
            detections.append(
                {
                    "provider": rule["provider"],
                    "credential_type": rule["credential_type"],
                    "credential_value": match.group(0),
                    "base_score": rule["base_score"],
                }
            )

    return detections

def confidence_level_from_score(score):
    """
    Convert a heuristic confidence score into a readable level.
    """

    if score >= CONFIDENCE_HIGH_THRESHOLD:
        return "HIGH"

    if score >= CONFIDENCE_MEDIUM_THRESHOLD:
        return "MEDIUM"

    return "LOW"

def assess_confidence(
    *,
    credential_type,
    credential_value,
    path,
    detection_method,
    is_quoted=False,
    provider_base_score=None,
    high_confidence_only=False,
):
    """
    Calculate a heuristic evidence score for a credential finding.

    The score estimates how strongly the finding resembles actual
    credential material. It does not determine whether the credential
    is currently valid.
    """

    reasons = []

    # -----------------------------
    # Base score by detection method
    # -----------------------------

    if detection_method == "private_key":
        score = 95
        reasons.append("complete PEM private-key structure")

    elif detection_method == "incomplete_private_key":
        score = 75
        reasons.append("private-key header found but key is incomplete")

    elif detection_method == "connection_uri":
        score = 90
        reasons.append("URI contains embedded username/password credentials")

    elif detection_method == "provider_pattern":
        score = provider_base_score or 85
        reasons.append("provider-specific credential signature")

    else:
        score = 40
        reasons.append("generic credential-name assignment")

    # -----------------------------
    # Generic assignment evidence
    # -----------------------------

    if detection_method == "generic_assignment":

        if is_quoted:
            score += 10
            reasons.append("credential value is a quoted literal")

        if path is not None:

            if is_interesting_file(path):
                score += 25
                reasons.append("credential-oriented filename")

            elif path.suffix.lower() in CONFIG_LIKE_EXTENSIONS:
                score += 10
                reasons.append("configuration-oriented file type")

            if path.suffix.lower() in REFERENCE_HEAVY_EXTENSIONS:
                score -= 5
                reasons.append("ordinary source-code context")

        normalized_type = (
            credential_type
            .lower()
            .replace("_", "")
            .replace("-", "")
        )

        if normalized_type in STRONG_GENERIC_CREDENTIAL_TYPES:
            score += 5
            reasons.append("specific credential type")

    # -----------------------------
    # Context modifiers
    # -----------------------------

    if path is not None:
        path_parts = {
            part.lower()
            for part in path.parts
        }

        if path_parts.intersection(EXAMPLE_CONTEXT_PARTS):
            if detection_method in {
                "generic_assignment",
                "provider_pattern",
            }:
                score -= 20
                reasons.append("example/documentation context")

    if (
        detection_method == "provider_pattern"
        and high_confidence_only
    ):
        score -= 5
        reasons.append("generated/minified source context")

    # Never allow scores outside 0-100.
    score = max(0, min(100, score))

    level = confidence_level_from_score(score)

    return level, score, reasons

# Display
def run_confidence_self_tests():
    """
    Run synthetic tests against provider detection and confidence scoring.
    No real credentials are used.
    """

    provider_tests = [
        (
            "GitHub",
            "ghp_" + ("A1b2" * 8),
        ),
        (
            "Stripe",
            "sk_live_" + ("A1b2" * 6),
        ),
        (
            "GitLab",
            "glpat-" + ("A1b2" * 5),
        ),
        (
            "PyPI",
            "pypi-" + ("A1b2" * 22),
        ),
        (
            "Slack",
            "xoxb-" + ("A1b2" * 6),
        ),
    ]

    for expected_provider, sample in provider_tests:
        detections = detect_provider_secrets(sample)

        providers = {
            detection["provider"]
            for detection in detections
        }

        if expected_provider not in providers:
            raise AssertionError(
                f"Provider test failed: {expected_provider}"
            )

    confidence_tests = [
        {
            "name": "provider token",
            "expected": "HIGH",
            "arguments": {
                "credential_type": "github_token",
                "credential_value": "synthetic",
                "path": Path("project/app.js"),
                "detection_method": "provider_pattern",
                "provider_base_score": 90,
            },
        },
        {
            "name": "provider token in examples",
            "expected": "MEDIUM",
            "arguments": {
                "credential_type": "github_token",
                "credential_value": "synthetic",
                "path": Path("project/examples/app.js"),
                "detection_method": "provider_pattern",
                "provider_base_score": 90,
            },
        },
        {
            "name": "password in .env",
            "expected": "HIGH",
            "arguments": {
                "credential_type": "password",
                "credential_value": "SyntheticPassword123!",
                "path": Path(".env"),
                "detection_method": "generic_assignment",
                "is_quoted": True,
            },
        },
        {
            "name": "password in JavaScript",
            "expected": "MEDIUM",
            "arguments": {
                "credential_type": "password",
                "credential_value": "SyntheticPassword123!",
                "path": Path("project/login.js"),
                "detection_method": "generic_assignment",
                "is_quoted": True,
            },
        },
        {
            "name": "generic token in JavaScript",
            "expected": "LOW",
            "arguments": {
                "credential_type": "token",
                "credential_value": "SomeGenericTokenValue",
                "path": Path("project/app.js"),
                "detection_method": "generic_assignment",
                "is_quoted": True,
            },
        },
        {
            "name": "plain unquoted token",
            "expected": "LOW",
            "arguments": {
                "credential_type": "token",
                "credential_value": "SomeGenericTokenValue",
                "path": Path("notes.txt"),
                "detection_method": "generic_assignment",
                "is_quoted": False,
            },
        },
        {
            "name": "private key",
            "expected": "HIGH",
            "arguments": {
                "credential_type": "private_key",
                "credential_value": "synthetic-private-key",
                "path": Path("server.pem"),
                "detection_method": "private_key",
            },
        },
        {
            "name": "incomplete private key",
            "expected": "MEDIUM",
            "arguments": {
                "credential_type": "incomplete_private_key",
                "credential_value": "synthetic-incomplete-key",
                "path": Path("server.pem"),
                "detection_method": "incomplete_private_key",
            },
        },
        {
            "name": "credential connection URI",
            "expected": "HIGH",
            "arguments": {
                "credential_type": "connection_uri",
                "credential_value": "synthetic-uri",
                "path": Path("settings.json"),
                "detection_method": "connection_uri",
            },
        },
    ]

    for test in confidence_tests:
        level, score, reasons = assess_confidence(
            **test["arguments"]
        )

        if level != test["expected"]:
            raise AssertionError(
                f"{test['name']}: expected "
                f"{test['expected']}, got {level} "
                f"(score={score}, reasons={reasons})"
            )

    print(
        f"Confidence self-tests passed: "
        f"{len(provider_tests)} provider tests, "
        f"{len(confidence_tests)} scoring tests."
    )

# -----------------------------
# Credential Scanning
# -----------------------------
# Scan one line for private-key headers and hard-coded credential assignments.
def scan_line(path, line_num, line, *, high_confidence_only=False,):
    findings = []
    provider_values = set()
    for provider_match in detect_provider_secrets(line):
        credential_value = provider_match["credential_value"]

        confidence, confidence_score, confidence_reasons = assess_confidence(
            credential_type=provider_match["credential_type"],
            credential_value=credential_value,
            path=path,
            detection_method="provider_pattern",
            provider_base_score=provider_match["base_score"],
            high_confidence_only=high_confidence_only,
        )

        record_finding(
            findings,
            path,
            line_num,
            provider_match["credential_type"],
            credential_value,
            provider=provider_match["provider"],
            confidence=confidence,
            confidence_score=confidence_score,
            detection_method="provider_pattern",
            confidence_reasons=confidence_reasons,
        )

        provider_values.add(credential_value)
        
    if not high_confidence_only:
        for match in SECRET_PATTERN.finditer(line):
            credential_type = match.group("credential_type")
        
            double_quoted_value = match.group("double_quoted_value")
            single_quoted_value = match.group("single_quoted_value")
            bare_value = match.group("bare_value")

            if double_quoted_value is not None:
                credential_value = double_quoted_value
                is_quoted = True
            elif single_quoted_value is not None:
                credential_value = single_quoted_value
                is_quoted = True
            else:
                credential_value = bare_value
                is_quoted = False

            if credential_value in provider_values:
                continue

            key_quoted = bool(match.group("key_quote"))
            operator = match.group("operator")
            
            if is_false_positive(
                credential_value,
                credential_type=credential_type,
                path=path,
                is_quoted=is_quoted,
                key_quoted=key_quoted,
                operator=operator,
            ):
                continue
            confidence, confidence_score, confidence_reasons = assess_confidence(
                credential_type=credential_type,
                credential_value=credential_value,
                path=path,
                detection_method="generic_assignment",
                is_quoted=is_quoted,
                high_confidence_only=high_confidence_only
                )
            record_finding(
                findings,
                path,
                line_num,
                credential_type,
                credential_value,
                confidence=confidence,
                confidence_score=confidence_score,
                detection_method="generic_assignment",
                confidence_reasons=confidence_reasons,
                )

    for match in CONNECTION_URI_PATTERN.finditer(line):
        connection_uri = match.group("connection_uri")
        connection_password = match.group("password")
        if is_false_positive(connection_password,path=path,is_quoted=True):
            continue
        confidence, confidence_score, confidence_reasons = assess_confidence(
            credential_type="connection_uri",
            credential_value=connection_uri,
            path=path,
            detection_method="connection_uri",
            is_quoted=True,
            )
        record_finding(
            findings,
            path,
            line_num,
            "connection_uri",
            connection_uri,
            confidence=confidence,
            confidence_score=confidence_score,
            detection_method="connection_uri",
            confidence_reasons=confidence_reasons,
            )  
        
    return findings     


def detect_text_encoding(path):
    with path.open("rb") as file:
        sample = file.read(4096)

    # UTF-8 with BOM
    if sample.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"

    # Check UTF-32 before UTF-16 because some BOM prefixes overlap.
    if sample.startswith(
        (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)
    ):
        return "utf-32"

    # UTF-16 with BOM
    if sample.startswith(
        (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)
    ):
        return "utf-16"

    # Try to recognize UTF-16 without a BOM.
    even_bytes = sample[0::2]
    odd_bytes = sample[1::2]

    if even_bytes and odd_bytes:
        even_null_ratio = even_bytes.count(0) / len(even_bytes)
        odd_null_ratio = odd_bytes.count(0) / len(odd_bytes)

        # ASCII-like UTF-16 LE usually has null bytes
        # in the odd byte positions.
        if odd_null_ratio > 0.30 and even_null_ratio < 0.05:
            return "utf-16-le"

        # ASCII-like UTF-16 BE usually has null bytes
        # in the even byte positions.
        if even_null_ratio > 0.30 and odd_null_ratio < 0.05:
            return "utf-16-be"

    # Most source/configuration files will be UTF-8.
    return "utf-8"


# Scan a text file line by line and return all credential findings from that file.
def scan_file(path):
    findings = []
    private_key_lines = []
    private_key_start_line = None
    try:
        encoding = detect_text_encoding(path)
        with path.open(
            "r",
            encoding=encoding,
            errors="replace"
        ) as file:
            for line_num, line in enumerate(file, 1):
                if private_key_lines:
                    private_key_lines.append(line.rstrip("\n"))
                    if PRIVATE_KEY_END_PATTERN.fullmatch(line.strip()):
                        private_key = "\n".join(private_key_lines)
                        
                        confidence, confidence_score, confidence_reasons = assess_confidence(
                            credential_type="private_key",
                            credential_value=private_key,
                            path=path,
                            detection_method="private_key"
                        )
                            
                        record_finding(findings,
                                       path,
                                       private_key_start_line,
                                       "private_key",
                                       private_key,
                                       confidence=confidence,
                                       confidence_score=confidence_score,
                                       detection_method="private_key",
                                       confidence_reasons=confidence_reasons,
                                       )
                        private_key_lines = []
                        private_key_start_line = None
                    continue
                if PRIVATE_KEY_HEADER_PATTERN.fullmatch(line.strip()):
                    private_key_start_line = line_num
                    private_key_lines = [line.rstrip("\n")]
                    continue
                high_confidence_only = should_use_high_confidence_only(path, line)
                findings.extend(
                    scan_line(path, line_num, line, high_confidence_only=high_confidence_only,)
                    )
            if private_key_lines:
                incomplete_private_key = "\n".join(private_key_lines)
                confidence, confidence_score, confidence_reasons = assess_confidence(
                    credential_type="incomplete_private_key",
                    credential_value=incomplete_private_key,
                    path=path,
                    detection_method="incomplete_private_key",
                    )
                    
                record_finding(
                    findings,
                    path,
                    private_key_start_line,
                    "incomplete_private_key",
                    incomplete_private_key,
                    confidence=confidence,
                    confidence_score=confidence_score,
                    detection_method="incomplete_private_key",
                    confidence_reasons=confidence_reasons,
                    )
            
    except PermissionError:
        pass
    except OSError as error:
        print(f"[Warning] Could not read {path}: {error}")

    return findings

# Recursively scan eligible files below root and return all detected credential findings.
def scan_directory(root):
    findings = []

    for current_root, dirs, files in os.walk(root):
        # Prevent os.walk from entering excluded directories.
        dirs[:] = [
            directory
            for directory in dirs
            if directory.lower() not in EXCLUDED_DIRECTORIES
        ]

        for filename in files:
            path = Path(current_root) / filename

            if is_scanner_file(path):
                continue

            if is_excluded_path(path):
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

    SEEN_FINDINGS.clear()
    
    print(f"\nScanning: {root}\n")
    
    findings = scan_directory(root)
    
    save_results(findings)
    
    input()

if __name__ == "__main__":
    main()

"""
ModSecurity Transformation Functions
Implements ModSecurity transformation functions such as t:lowercase, t:urlDecode, t:htmlEntityDecode, etc.
"""
import base64
import html
import re
import urllib.parse
from typing import Callable, Dict, List


def t_lowercase(val: str) -> str:
    """t:lowercase - Converts all characters to lowercase."""
    return val.lower()


def t_url_decode(val: str) -> str:
    """t:urlDecode - Decodes a URL-encoded string."""
    try:
        # Standard unquote_plus handles both %xx and + as space
        return urllib.parse.unquote_plus(val)
    except Exception:
        try:
            return urllib.parse.unquote(val)
        except Exception:
            return val


def t_url_decode_uni(val: str) -> str:
    """t:urlDecodeUni - Decodes %uXXXX style unicode encoding as well as %XX."""
    val = t_url_decode(val)
    def _replace_uni(match):
        try:
            return chr(int(match.group(1), 16))
        except Exception:
            return match.group(0)
    return re.sub(r"%u([0-9a-fA-F]{4})", _replace_uni, val)


def t_html_entity_decode(val: str) -> str:
    """t:htmlEntityDecode - Decodes HTML entities (e.g. &lt;, &#x3c;, &#60;)."""
    try:
        return html.unescape(val)
    except Exception:
        return val


def t_remove_whitespace(val: str) -> str:
    """t:removeWhitespace - Removes all whitespace characters (spaces, tabs, newlines)."""
    return re.sub(r"\s+", "", val)


def t_compress_whitespace(val: str) -> str:
    """t:compressWhitespace - Replaces sequences of whitespace with a single space and trims."""
    return re.sub(r"\s+", " ", val).strip()


def t_trim(val: str) -> str:
    """t:trim - Strips leading and trailing whitespace."""
    return val.strip()


def t_base64_decode(val: str) -> str:
    """t:base64Decode - Decodes base64 encoded data, fallback to original if invalid."""
    try:
        # Pad if necessary
        padded = val + "=" * ((4 - len(val) % 4) % 4)
        decoded = base64.b64decode(padded, validate=True).decode("utf-8", errors="ignore")
        return decoded if decoded else val
    except Exception:
        return val


def t_normalize_path(val: str) -> str:
    """t:normalizePath - Replaces multiple slashes, backslashes and resolves ./ and ../."""
    # Convert Windows backslashes to forward slashes
    val = val.replace("\\", "/")
    # Reduce consecutive slashes
    val = re.sub(r"/{2,}", "/", val)
    # Remove /./
    val = re.sub(r"/\./", "/", val)
    return val


def t_none(val: str) -> str:
    """t:none - No-op or reset."""
    return val


TRANSFORMATION_REGISTRY: Dict[str, Callable[[str], str]] = {
    "lowercase": t_lowercase,
    "urldecode": t_url_decode,
    "urldecodeuni": t_url_decode_uni,
    "htmlentitydecode": t_html_entity_decode,
    "removewhitespace": t_remove_whitespace,
    "compresswhitespace": t_compress_whitespace,
    "trim": t_trim,
    "base64decode": t_base64_decode,
    "normalizepath": t_normalize_path,
    "none": t_none,
}


def apply_transformations(val: str, transformation_names: List[str]) -> str:
    """
    Applies an ordered list of transformation names to the given input string.
    If 'none' is encountered, previous transformations are discarded and subsequent ones applied.
    """
    if val is None:
        return ""
    if not isinstance(val, str):
        val = str(val)

    current = val
    for name in transformation_names:
        clean_name = name.lower().replace("t:", "").strip()
        if clean_name == "none":
            current = val
            continue
        func = TRANSFORMATION_REGISTRY.get(clean_name)
        if func:
            try:
                current = func(current)
            except Exception:
                pass
    return current

#!/usr/bin/env python3
"""Authenticated HTTP client for VNT client and VNTS administration APIs."""

import argparse
import getpass
import json
import os
import re
import ssl
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit, urlunsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)


class ApiError(Exception):
    """An expected input, transport, or API error safe to show after redaction."""


class NoRedirectHandler(HTTPRedirectHandler):
    """Do not forward Authorization headers across redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def fail(message: str) -> None:
    print("error: {}".format(message), file=sys.stderr)
    raise SystemExit(1)


def redact(text: str, secrets: Sequence[Optional[str]]) -> str:
    result = text
    for secret in secrets:
        if secret:
            result = result.replace(secret, "<redacted>")
    return result


def read_stdin_secret(label: str) -> str:
    if sys.stdin.isatty():
        value = getpass.getpass("{}: ".format(label))
    else:
        value = sys.stdin.readline().rstrip("\r\n")
    if not value:
        raise ApiError("{} is empty".format(label))
    return value


def read_env(name: str, label: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ApiError("environment variable {} does not contain {}".format(name, label))
    return value


def validate_base_url(raw: str) -> str:
    parsed = urlsplit(raw.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ApiError("base URL must be an absolute http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ApiError("credentials in URL userinfo are not supported")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def parse_access_url(raw: str) -> Tuple[str, Optional[str]]:
    parsed = urlsplit(raw.strip())
    base_url = validate_base_url(raw)
    values = parse_qs(parsed.query, keep_blank_values=True).get("token", [])
    token = values[-1] if values else None
    if token == "":
        token = None
    return base_url, token


def build_endpoint(base_url: str, path: str) -> str:
    request_path = path.strip()
    if not request_path.startswith("/"):
        raise ApiError("API path must start with '/'")
    parsed_path = urlsplit(request_path)
    if parsed_path.scheme or parsed_path.netloc or parsed_path.fragment:
        raise ApiError("API path must be relative to the supplied API host")
    return "{}{}".format(base_url.rstrip("/"), request_path)


def ssl_context(ca_file: Optional[str]) -> ssl.SSLContext:
    try:
        return ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError) as exc:
        raise ApiError("cannot load CA file: {}".format(exc))


def decode_error_body(raw: bytes) -> str:
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    try:
        payload = json.loads(text)
        if isinstance(payload, dict) and payload.get("msg"):
            return str(payload["msg"])
    except json.JSONDecodeError:
        pass
    compact = " ".join(text.split())
    return compact[:500]


def exchange(
    url: str,
    method: str,
    token: Optional[str],
    body: Optional[bytes],
    timeout: float,
    ca_file: Optional[str],
    secrets: Sequence[Optional[str]],
) -> Tuple[bytes, Dict[str, str], int]:
    headers = {
        "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.8",
        "User-Agent": "vnt-operations/1",
    }
    if token:
        headers["Authorization"] = "Bearer {}".format(token)
    if body is not None:
        headers["Content-Type"] = "application/json"

    request = Request(url=url, data=body, headers=headers, method=method)
    opener = build_opener(NoRedirectHandler(), HTTPSHandler(context=ssl_context(ca_file)))
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.read(), dict(response.headers.items()), response.status
    except HTTPError as exc:
        detail = decode_error_body(exc.read())
        message = "HTTP {}".format(exc.code)
        if 300 <= exc.code < 400:
            message += " redirect refused to protect credentials"
        elif detail:
            message += ": {}".format(detail)
        raise ApiError(redact(message, secrets))
    except URLError as exc:
        raise ApiError(redact("request failed: {}".format(exc.reason), secrets))
    except TimeoutError:
        raise ApiError("request timed out")
    except OSError as exc:
        raise ApiError(redact("request failed: {}".format(exc), secrets))


def parse_envelope(
    raw: bytes,
    expected_code: int,
    label: str,
    secrets: Sequence[Optional[str]],
) -> Dict[str, object]:
    try:
        text = raw.decode("utf-8")
        payload = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiError("{} returned invalid JSON: {}".format(label, exc))
    if not isinstance(payload, dict):
        raise ApiError("{} returned a non-object JSON response".format(label))
    if payload.get("code") != expected_code:
        message = str(payload.get("msg") or "unknown API error")
        raise ApiError(redact("{} business error: {}".format(label, message), secrets))
    return payload


def load_json_body(args: argparse.Namespace) -> Optional[bytes]:
    raw = None
    if args.json_body is not None:
        raw = args.json_body
    elif args.json_file is not None:
        path = Path(args.json_file)
        if str(path) == "-":
            raise ApiError("--json-file '-' is not supported because stdin may carry credentials")
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ApiError("cannot read JSON file: {}".format(exc))
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ApiError("invalid JSON request body: {}".format(exc))
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def write_output(path_value: str, raw: bytes, force: bool) -> None:
    path = Path(path_value)
    if path.exists() and not force:
        raise ApiError("output file already exists; pass --force to replace it")
    if not path.parent.exists():
        raise ApiError("output directory does not exist: {}".format(path.parent))
    try:
        path.write_bytes(raw)
    except OSError as exc:
        raise ApiError("cannot write output file: {}".format(exc))
    print("wrote {} bytes to {}".format(len(raw), path))


def show_json(payload: Dict[str, object]) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def request_api(
    args: argparse.Namespace,
    base_url: str,
    token: str,
    expected_code: int,
    label: str,
    secrets: Sequence[Optional[str]],
) -> None:
    method = args.method.upper()
    if not re.fullmatch(r"[A-Z]+", method):
        raise ApiError("HTTP method must contain letters only")
    if args.timeout <= 0:
        raise ApiError("--timeout must be greater than zero")

    body = load_json_body(args)
    url = build_endpoint(base_url, args.path)
    raw, headers, _status = exchange(
        url, method, token, body, args.timeout, args.ca_file, secrets
    )
    if args.output:
        content_type = next(
            (value for key, value in headers.items() if key.lower() == "content-type"), ""
        )
        if "json" in content_type.lower():
            parse_envelope(raw, expected_code, label, secrets)
        write_output(args.output, raw, args.force)
        return
    payload = parse_envelope(raw, expected_code, label, secrets)
    show_json(payload)


def optional_token(args: argparse.Namespace) -> Optional[str]:
    if args.token is not None:
        return args.token
    if args.token_stdin:
        return read_stdin_secret("Bearer token")
    if args.token_env:
        return read_env(args.token_env, "Bearer token")
    return None


def resolve_client(args: argparse.Namespace) -> Tuple[str, str, List[Optional[str]]]:
    access_url = None
    if args.access_url is not None:
        access_url = args.access_url
    elif args.access_url_stdin:
        access_url = read_stdin_secret("VNT Web access URL")
    elif args.access_url_env:
        access_url = read_env(args.access_url_env, "VNT Web access URL")

    explicit_token = optional_token(args)
    if access_url is not None:
        base_url, url_token = parse_access_url(access_url)
        if explicit_token and url_token and explicit_token != url_token:
            raise ApiError("access URL token and explicit token do not match")
        token = explicit_token or url_token
        if not token:
            raise ApiError("access URL has no token; provide one with a token option")
        return base_url, token, [token, access_url]

    if args.base_url is None:
        raise ApiError("provide an access URL or --base-url")
    if not explicit_token:
        raise ApiError("--base-url requires a token option")
    return validate_base_url(args.base_url), explicit_token, [explicit_token]


def server_login(
    args: argparse.Namespace, base_url: str
) -> Tuple[str, List[Optional[str]]]:
    token = optional_token(args)
    if token:
        return token, [token]
    if not args.username:
        raise ApiError("provide --username when no existing JWT is supplied")

    if args.password_stdin:
        password = read_stdin_secret("VNTS password")
    elif args.password_env:
        password = read_env(args.password_env, "VNTS password")
    elif sys.stdin.isatty():
        password = getpass.getpass("VNTS password: ")
        if not password:
            raise ApiError("VNTS password is empty")
    else:
        raise ApiError("provide --password-stdin or --password-env for login")

    secrets: List[Optional[str]] = [password]
    login_body = json.dumps(
        {"username": args.username, "password": password},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    login_url = build_endpoint(base_url, "/api/login")
    raw, _headers, _status = exchange(
        login_url,
        "POST",
        None,
        login_body,
        args.timeout,
        args.ca_file,
        secrets,
    )
    payload = parse_envelope(raw, 200, "VNTS login", secrets)
    data = payload.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("token"), str):
        raise ApiError("VNTS login response has no token")
    token = data["token"]
    secrets.append(token)
    return token, secrets


def add_request_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("method", help="HTTP method, for example GET, POST, PUT, or DELETE")
    parser.add_argument("path", help="API path beginning with /, including an optional query")
    body = parser.add_mutually_exclusive_group()
    body.add_argument("--json", dest="json_body", help="inline JSON request body")
    body.add_argument("--json-file", help="UTF-8 file containing the JSON request body")
    parser.add_argument("--output", help="write raw response bytes to this file")
    parser.add_argument(
        "--force", action="store_true", help="allow --output to replace an existing file"
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="request timeout in seconds")
    parser.add_argument("--ca-file", help="custom PEM CA bundle for HTTPS verification")


def add_token_arguments(parser: argparse.ArgumentParser) -> None:
    token = parser.add_mutually_exclusive_group()
    token.add_argument("--token", help="Bearer token (stdin/environment is safer)")
    token.add_argument("--token-stdin", action="store_true", help="read Bearer token from stdin")
    token.add_argument(
        "--token-env",
        action="store_const",
        const="VNT_API_TOKEN",
        help="read Bearer token from VNT_API_TOKEN",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Call VNT client and VNTS server Web APIs without third-party packages."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    client = subparsers.add_parser("client", help="call a vnt2_web/desktop Web-access API")
    source = client.add_mutually_exclusive_group(required=True)
    source.add_argument("--access-url", help="full access URL, optionally containing ?token=")
    source.add_argument(
        "--access-url-stdin", action="store_true", help="read the full access URL from stdin"
    )
    source.add_argument(
        "--access-url-env",
        action="store_const",
        const="VNT_WEB_ACCESS_URL",
        help="read access URL from VNT_WEB_ACCESS_URL",
    )
    source.add_argument("--base-url", help="API base URL without a token query")
    add_token_arguments(client)
    add_request_arguments(client)

    server = subparsers.add_parser("server", help="call the VNTS administrative API")
    server.add_argument("--base-url", required=True, help="VNTS management base URL")
    add_token_arguments(server)
    server.add_argument("--username", help="management username used when no JWT is supplied")
    password = server.add_mutually_exclusive_group()
    password.add_argument(
        "--password-stdin", action="store_true", help="read management password from stdin"
    )
    password.add_argument(
        "--password-env",
        action="store_const",
        const="VNTS_PASSWORD",
        help="read password from VNTS_PASSWORD",
    )
    add_request_arguments(server)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.force and not args.output:
            raise ApiError("--force requires --output")
        if args.mode == "client":
            base_url, token, secrets = resolve_client(args)
            request_api(args, base_url, token, 0, "VNT client API", secrets)
        else:
            base_url = validate_base_url(args.base_url)
            token, secrets = server_login(args, base_url)
            request_api(args, base_url, token, 200, "VNTS API", secrets)
        return 0
    except ApiError as exc:
        fail(str(exc))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

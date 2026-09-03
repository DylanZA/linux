#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Dependency-free arithmetic REST service for the datafs OpenAPI provider."""

import argparse
import json
import math
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


OPENAPI_DOCUMENT = Path(__file__).with_name("datafs_rest_example.openapi.json").read_bytes()


def integer(query, name, default=0):
    """Return one integer query parameter or raise a client-facing error."""
    raw = query.get(name, [str(default)])[-1]
    try:
        return int(raw, 0)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error


def calculate(path, query):
    """Evaluate the operation selected by path and return its JSON object."""
    operation = path.removeprefix("/v1/").strip("/")
    a = integer(query, "a")
    b = integer(query, "b")
    if operation == "add":
        result = a + b
    elif operation == "subtract":
        result = a - b
    elif operation == "multiply":
        result = a * b
    elif operation == "divide":
        if b == 0:
            raise ValueError("b must not be zero")
        result = a / b
    elif operation == "modulo":
        if b == 0:
            raise ValueError("b must not be zero")
        result = a % b
    elif operation == "power":
        if b < 0 or b > 63:
            raise ValueError("b must be between 0 and 63")
        result = a**b
    elif operation == "gcd":
        result = math.gcd(a, b)
    else:
        raise LookupError("unknown arithmetic operation")
    return {"a": a, "b": b, "operation": operation, "result": result}


def encode_result(path, query_string):
    """Build the stable JSON representation used by both HEAD and GET."""
    query = parse_qs(query_string, keep_blank_values=True)
    return (json.dumps(calculate(path, query), sort_keys=True, separators=(",", ":")) + "\n").encode()


def select_range(body, value):
    """Apply one inclusive HTTP byte range and return status, body, and header."""
    if not value:
        return HTTPStatus.OK, body, None
    if not value.startswith("bytes=") or "," in value:
        raise ValueError("only one byte range is supported")
    bounds = value[6:].split("-", 1)
    if len(bounds) != 2 or not bounds[0]:
        raise ValueError("invalid byte range")
    start = int(bounds[0])
    end = int(bounds[1]) if bounds[1] else len(body) - 1
    if start < 0 or start >= len(body) or end < start:
        raise ValueError("byte range is outside the response")
    end = min(end, len(body) - 1)
    return HTTPStatus.PARTIAL_CONTENT, body[start : end + 1], f"bytes {start}-{end}/{len(body)}"


class ArithmeticHandler(BaseHTTPRequestHandler):
    """Serve arithmetic GET/HEAD operations with datafs-compatible ranges."""

    protocol_version = "HTTP/1.1"

    def send_arithmetic(self, include_body):
        """Evaluate a request and send identical metadata for HEAD and GET."""
        target = urlsplit(self.path)
        if target.path == "/openapi.json":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/vnd.oai.openapi+json;version=3.1")
            self.send_header("Content-Length", str(len(OPENAPI_DOCUMENT)))
            self.end_headers()
            if include_body:
                self.wfile.write(OPENAPI_DOCUMENT)
            return
        try:
            body = encode_result(target.path, target.query)
            status, selected, content_range = select_range(body, self.headers.get("Range"))
        except LookupError as error:
            self.send_error(HTTPStatus.NOT_FOUND, str(error))
            return
        except (ValueError, OverflowError) as error:
            self.send_error(HTTPStatus.BAD_REQUEST, str(error))
            return

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Accept-Ranges", "bytes")
        if content_range:
            self.send_header("Content-Range", content_range)
        self.send_header("Content-Length", str(len(selected)))
        self.end_headers()
        if include_body:
            self.wfile.write(selected)

    def do_GET(self):
        """Serve an arithmetic result, optionally restricted by Range."""
        self.send_arithmetic(True)

    def do_HEAD(self):
        """Return the exact length of the corresponding GET response."""
        self.send_arithmetic(False)

    def log_message(self, message, *args):
        """Use a compact service-specific access-log prefix."""
        print(f"arithmetic-rest: {self.address_string()} {message % args}")


def self_test():
    """Exercise calculation, validation, and byte-range behavior."""
    assert encode_result("/v1/add", "a=40&b=2").endswith(b'"result":42}\n')
    assert calculate("/v1/gcd", {"a": ["54"], "b": ["24"]})["result"] == 6
    status, body, content_range = select_range(b"abcdef", "bytes=2-4")
    assert status == HTTPStatus.PARTIAL_CONTENT
    assert body == b"cde"
    assert content_range == "bytes 2-4/6"


def main():
    """Parse service options and run until interrupted."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    server = ThreadingHTTPServer((args.host, args.port), ArithmeticHandler)
    print(f"arithmetic REST service listening on http://{args.host}:{args.port}/v1")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

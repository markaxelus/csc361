#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import socket
import ssl

def parse_url(url):
    if url.startswith("http://"):
        scheme = "http"
        url = url[7:]
    elif url.startswith("https://"):
        scheme = "https"
        url = url[8:]
    else:
        scheme = "http"
    if "/" in url:
        host, rest = url.split("/", 1)
        path = "/" + rest
    else:
        host = url
        path = "/"
    return scheme, host, path

def get_http_context():
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    return context

def create_socket(host, scheme):
    if scheme == "https":
        context = get_http_context()
        sock = socket.create_connection((host, 443), timeout=15)
        ssock = context.wrap_socket(sock, server_hostname=host)
        return ssock
    else:
        sock = socket.create_connection((host, 80), timeout=15)
        return sock

def send_request(sock, host, path):
    req = ("GET " + path + " HTTP/1.1\r\n" +
           "Host: " + host + "\r\n" +
           "User-Agent: WebTester/1.0\r\n" +
           "Connection: close\r\n\r\n")
    sock.sendall(req.encode())

def receive_response(sock):
    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        response += chunk
    return response.decode("latin1")

def parse_response(response):
    parts = response.split("\r\n\r\n", 1)
    header_text = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    header_lines = header_text.split("\r\n")
    status_line = header_lines[0]
    tokens = status_line.split()
    code = tokens[1] if len(tokens) >= 2 else "000"
    headers = {}
    for line in header_lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key in headers:
                if isinstance(headers[key], list):
                    headers[key].append(value)
                else:
                    headers[key] = [headers[key], value]
            else:
                headers[key] = value
    return status_line, code, headers, body

def extract_cookies(headers):
    cookies = []
    if "Set-Cookie" in headers:
        cookie_vals = headers["Set-Cookie"]
        if not isinstance(cookie_vals, list):
            cookie_vals = [cookie_vals]
        for cookie in cookie_vals:
            parts = cookie.split(";")
            first = parts[0].strip()
            if "=" in first:
                cookie_name, _ = first.split("=", 1)
            else:
                cookie_name = first
            expires = None
            domain = None
            for attr in parts[1:]:
                attr = attr.strip()
                if "=" in attr:
                    key, val = attr.split("=", 1)
                    key = key.lower().strip()
                    val = val.strip()
                    if key == "expires":
                        expires = val
                    elif key == "domain":
                        domain = val
            cookies.append((cookie_name, expires, domain))
    return cookies

def find_redirect(headers):
    if "Location" in headers:
        loc = headers["Location"]
        if isinstance(loc, list):
            return loc[0]
        return loc
    return None

def is_password_protected(code, headers):
    if code == "401":
        return True
    if "WWW-Authenticate" in headers:
        return True
    return False

def check_http2(sock, scheme):
    if scheme == "https":
        if sock.selected_alpn_protocol() == "h2":
            return True
    return False

def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python WebTester.py <URL>")
    input_url = sys.argv[1]
    scheme, host, path = parse_url(input_url)
    
    max_redirect = 5
    redirect_count = 0
    password_protected = False
    cookies = []
    http2_supported = False
    current_scheme = scheme
    current_host = host
    current_path = path

    while redirect_count < max_redirect:
        try:
            sock = create_socket(current_host, current_scheme)
        except Exception:
            sys.exit("Error connecting to " + current_host)
        send_request(sock, current_host, current_path)
        response_text = receive_response(sock)
        status_line, code, headers, body = parse_response(response_text)
        if is_password_protected(code, headers):
            password_protected = True
        cookies.extend(extract_cookies(headers))
        if current_scheme == "https":
            if check_http2(sock, current_scheme):
                http2_supported = True
            else:
                http2_supported = False
        sock.close()
        if code in ["301", "302"]:
            loc = find_redirect(headers)
            if loc:
                new_scheme, new_host, new_path = parse_url(loc)
                current_scheme = new_scheme
                current_host = new_host
                current_path = new_path
                redirect_count += 1
                continue
        break

    if current_scheme == "https" and not http2_supported:
        try:
            context = get_http_context()
            raw_sock = socket.create_connection((current_host, 443), timeout=15)
            ssock = context.wrap_socket(raw_sock, server_hostname=current_host)
            if ssock.selected_alpn_protocol() == "h2":
                http2_supported = True
            ssock.close()
        except Exception:
            http2_supported = False

    print("website: " + current_host)
    print("1. Supports http2: " + ("yes" if http2_supported else "no"))
    print("2. List of Cookies:")
    for (name, expires, domain) in cookies:
        line = "cookie name: " + name
        if expires:
            line += ", expires time: " + expires
        if domain:
            line += "; domain name: " + domain
        print(line)
    print("3. Password-protected: " + ("yes" if password_protected else "no"))

if __name__ == "__main__":
    main()

html_header_content = 'Content-type:text/html\r\n'
html_header_status = 'Status: 401 Unauthorized\r\n'
html_header_authenticate = 'WWW-Authenticate:Basic realm="Secure Area"\r\n\r\n'

html_body = '<html><head><title>401</title></head><body><h1>401 No way</h1>\
    </body></html>'


def get_html_header():
    str = html_header_content + html_header_status + html_header_authenticate
    return str


def get_html():
    return get_html_header() + html_body

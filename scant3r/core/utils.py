import binascii
import logging
import random
import re
import string
from typing import List
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunparse

from requests.models import Response

log = logging.getLogger("scant3r")

# Generate a random string. Arg int return str
def random_str(num: int) -> str:
    """
    >>> random_txt = random_str(5)
    geCr15
    """
    num = int(num)
    return "".join(random.choices(string.ascii_uppercase, k=num))


# Print the request in the console. Arg the request. Return a string. Empty string if no request
def dump_request(request: Response) -> str:
    """
    >>> import requests
    >>> req = requests.get('https://knassar702.github.io')
    >>> dump_request(req)
    GET / HTTP/1.1
    Host: knassar702.github.io
    User-aget: requests User agent
    Connection: Closed
    Content-Type: text/html
    """
    body = ""
    body += request.request.method
    body += " "
    body += request.request.url + " HTTP/1.1"
    body += "\n"

    for header, value in request.request.headers.items():
        body += header + ": " + value + "\n"

    if request.request.body != None:
        body += "\n" + str(request.request.body)
    return body


# Print the response in the console. Arg the request. Return a string. Empty string if no response
def dump_response(request: Response) -> str:
    """
    >>> import requests
    >>> req = requests.get('https://knassar702.github.io')
    >>> dump_response(req)
        HTTP/2 200
        server: GitHub.com
        content-type: text/html; charset=utf-8
        strict-transport-security: max-age=31556952
        last-modified: Wed, 21 Jul 2021 00:49:48 GMT
        date: Mon, 26 Jul 2021 13:16:36 GMT
        age: 0
        vary: Accept-Encoding
        content-length: 2915

    """
    body = "HTTP /1.1 "
    body += str(request.status_code)
    body += " "
    body += request.reason
    body += "\n"
    for header, value in request.headers.items():
        body += header + ": " + value + "\n"
    body += "\n\n"
    body += request.text
    return body


def URLENCODE(data):
    d = ""
    for word in data:
        d += "%" + binascii.b2a_hex(word.encode("utf-8")).decode("utf-8")
    return d


# from plain text to url encoding
def urlencoder(data, many=1):
    """
    >>> urlencoder('<')
    %3c
    >>> urlencoder('<',2)
    25%33%63
    >>> urlencoder('<',3)
    %25%32%35%25%33%33%25%36%33
    """
    for _ in range(many):
        data = URLENCODE(data)
    return data


# Remove duplicate element from a list. Arg List return a clean list
def remove_dups(l: list) -> list:
    """
    >>> remove_dups(["item","item2","item"])
    ["item","item2"]
    """
    v = list()
    [v.append(x) for x in l if x not in v]
    return v


# Remove duplicate url from a list. Arg list of url. Return a clean Url list
def remove_dups_urls(l: list) -> list:
    """
    >>> remove_dups_urls(['http://google.com/?test=1','http://php.net/?test=1','http://google.com/?test=1'])
    ['http://google.com/?test=1','http://php.net/?test=1']
    """
    v = list()
    [v.append(i) for i in l if i not in v and urlparse(i).netloc]
    return v


# Insert param
def insert_to_params_name(url: str, text: str) -> list:
    """
    >>> insert_to_params_name('http://google.com/?name=','PAYLOAD')
    http://google.com/?namePAYLOAD=
    """
    parse_url = urlparse(url)
    query = parse_url.query
    url_dict = dict(parse_qsl(query))
    for param, value in url_dict.copy().items():
        new_param = param + text
        url_dict.pop(param)
        url_dict[new_param] = value
    new_url = urlencode(url_dict)
    parse_url = parse_url._replace(query=new_url)
    return urlunparse(parse_url)


# Insert param to custom parameter name
def insert_to_custom_params(
    url: str, parameter: str, text: str, remove_content: bool = False
) -> str:
    """
    >>> insert_to_custom_params('http://google.com/?test=TEST&name=5',"test","YES")
    http://google.com/?test=TESTYES&name=5

    >>> insert_to_custom_params('http://google.com/?test=1&name=5',"test","YES",True)
    http://google.com/?test=YES&name=5
    """
    parse_url = urlparse(url)
    query = parse_url.query
    url_dict = dict(parse_qsl(query))
    if parameter not in url_dict:
        log.debug("cant find the parameter")
        return url
    for param, value in url_dict.copy().items():
        if remove_content:
            url_dict[param] = text
        url_dict[param] = value + text
    new_url = urlencode(url_dict)
    parse_url = parse_url._replace(query=new_url)
    return urlunparse(parse_url)


# Return the query from the url
def dump_params(url: str):
    """
    >>> dump_params('http://google.com/?test=1&name=5')
    test=1&name=5
    """
    return urlparse(url).query


# Add a path to an url
def add_path(url: str, path: str) -> str:
    """
    >>> add_path('http://google.com/','/admin/index.php')
    http://google.com/admin/index.php
    """
    return urljoin(url, path)


# Add a string to url parameters
def insert_to_params_urls(url: str, text: str, remove_content: bool = False) -> List[str]:
    """
    >>> insert_to_params_urls('http://php.net/?name=2','test')
    http://php.net/?name=2test
    >>> insert_to_params_urls('http://php.net/?name=2','test',True)
    http://php.net/?name=test

    """
    parse_url = urlparse(url)
    query = parse_url.query
    urls = []
    url_dict = dict(parse_qsl(query, keep_blank_values=True))
    for param, value in url_dict.copy().items():
        if remove_content:
            url_dict[param] = text
        else:
            url_dict[param] = value + text
        urls.append(urlunparse(parse_url._replace(query=urlencode(url_dict))))
    return urls


# insert text to url path
def insert_text_to_urlpath(url: str, text: str) -> list:
    """
    >>> insert_text_to_urlpath('http://php.net/search/text/','TEST')
    [
            'http://php.net/searchTEST/text/',
            'http://php.net/search/textTEST/'
    ]
    """
    new_urls = []
    path = urlparse(url).path
    for Path in path.split("/"):
        if Path:
            path_index = url.index(Path)
            u = list(url)
            u[path_index] = Path + text
            new_urls.append("".join(u))
    return new_urls


# Convert url parameters to dict (for cookies,request body parameters)
def post_data(url: str) -> dict:
    """
    >>> post_data('http://google.com/?test=1&name=khaled')
    {
            'test':'1',
            'name':'khaled'
    }
    >>> post_data('?test=1&name=khaled')
    {
            'test':'1',
            'name':'khaled'
    }

    """
    return dict(parse_qsl(urlsplit(url).query))


# Convert string headers to a dict Headers
def extract_headers(headers: str) -> dict:
    """
    >>> extract_headers('User-agent: YES')
    {'User-agent':'YES'}
    >>> extract_headers('User-agent: YES\nHacker: 3')
    {'User-agent':'YES','Hacker':'3'}
    """
    headers = headers.replace("\\n", "\n")
    sorted_headers = {}
    matches = re.findall(r"(.*):\s(.*)", headers)
    for match in matches:
        header = match[0]
        value = match[1]
        if value[-1] == ",":
            value = value[:-1]
        sorted_headers[header] = value
    return sorted_headers


# Convert cookie string to a dict
def extract_cookie(cookies: str) -> dict:
    """
    >>> extract_cookie('session=test')
    {'session':'test'}
    """
    dict_cookies = {}
    if cookies:
        cookies = cookies.strip()
        list_cookie = cookies.split(";")
        for cookie in list_cookie:
            cookie = cookie.strip()
            list_value_name_cookie = cookie.split("=")
            dict_cookies[list_value_name_cookie[0].strip()] = list_value_name_cookie[
                1
            ].strip()

    return dict_cookies


#  Insert some string into given string at given index
def insert_after(text: str, find_this: str, newText: str) -> str:
    """
    >>> insert_after('Hello World','W','M')
    Hello Morld
    """
    i = text.find(find_this)
    return text[: i + len(find_this)] + newText + text[i + len(find_this) :]


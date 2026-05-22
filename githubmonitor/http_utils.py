import ssl
from functools import lru_cache
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener, urlopen


@lru_cache(maxsize=1)
def insecure_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def open_external(request: Request, timeout: int = 10, proxy: str = ""):
    if proxy:
        opener = build_opener(
            ProxyHandler({"http": proxy, "https": proxy}),
            HTTPSHandler(context=insecure_ssl_context()),
        )
        return opener.open(request, timeout=timeout)
    return urlopen(request, timeout=timeout, context=insecure_ssl_context())

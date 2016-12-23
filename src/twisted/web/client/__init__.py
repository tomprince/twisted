# -*- test-case-name: twisted.web.client.test.test_webclient,twisted.web.client.test.test_agent -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
HTTP client.
"""

from __future__ import division, absolute_import

from twisted.python.deprecate import deprecatedModuleAttribute, deprecated
from incremental import Version

from twisted.python.deprecate import getDeprecationWarningString
from twisted.web import error

from ._uri import URI


class PartialDownloadError(error.Error):
    """
    Page was only partially downloaded, we got disconnected in middle.

    @ivar response: All of the response body which was downloaded.
    """


_GETPAGE_REPLACEMENT_TEXT = "https://pypi.org/project/treq/ or twisted.web.client.Agent"


from ._getpage import (
    HTTPClientFactory, HTTPDownloader,
    HTTPPageDownloader, HTTPPageGetter,
    _makeGetterFactory,
)

def _deprecateGetPageClasses():
    """
    Mark the protocols and factories associated with L{getPage} and
    L{downloadPage} as deprecated.
    """
    for klass in [
        HTTPPageGetter, HTTPPageDownloader,
        HTTPClientFactory, HTTPDownloader
    ]:
        deprecatedModuleAttribute(
            Version("Twisted", 16, 7, 0),
            getDeprecationWarningString(
                klass,
                Version("Twisted", 16, 7, 0),
                replacement=_GETPAGE_REPLACEMENT_TEXT)
            .split("; ")[1],
            __name__,
            klass.__name__)

_deprecateGetPageClasses()



@deprecated(Version("Twisted", 16, 7, 0),
            _GETPAGE_REPLACEMENT_TEXT)
def getPage(url, contextFactory=None, *args, **kwargs):
    """
    Download a web page as a string.

    Download a page. Return a deferred, which will callback with a
    page (as a string) or errback with a description of the error.

    See L{HTTPClientFactory} to see what extra arguments can be passed.
    """
    return _makeGetterFactory(
        url,
        HTTPClientFactory,
        contextFactory=contextFactory,
        *args, **kwargs).deferred



@deprecated(Version("Twisted", 16, 7, 0),
            _GETPAGE_REPLACEMENT_TEXT)
def downloadPage(url, file, contextFactory=None, *args, **kwargs):
    """
    Download a web page to a file.

    @param file: path to file on filesystem, or file-like object.

    See HTTPDownloader to see what extra args can be passed.
    """
    factoryFactory = lambda url, *a, **kw: HTTPDownloader(url, file, *a, **kw)
    return _makeGetterFactory(
        url,
        factoryFactory,
        contextFactory=contextFactory,
        *args, **kwargs).deferred


from ._http11 import Response
from ._agent import (
    ResponseDone, ResponseFailed, Agent, CookieAgent,
    ProxyAgent, ContentDecoderAgent, GzipDecoder, RedirectAgent,
    HTTPConnectionPool, readBody, BrowserLikeRedirectAgent,
    FileBodyProducer, BrowserLikePolicyForHTTPS,
)



__all__ = [
    'PartialDownloadError', 'HTTPPageGetter', 'HTTPPageDownloader',
    'HTTPClientFactory', 'HTTPDownloader', 'getPage', 'downloadPage',
    'ResponseDone', 'Response', 'ResponseFailed', 'Agent', 'CookieAgent',
    'ProxyAgent', 'ContentDecoderAgent', 'GzipDecoder', 'RedirectAgent',
    'HTTPConnectionPool', 'readBody', 'BrowserLikeRedirectAgent', 'URI',
    'FileBodyProducer', 'BrowserLikePolicyForHTTPS',
]

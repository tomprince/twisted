try:
    from urlparse import urlunparse
except ImportError:
    from urllib.parse import urlunparse as _urlunparse

    def urlunparse(parts):
        result = _urlunparse(tuple([p.decode("charmap") for p in parts]))
        return result.encode("charmap")


from twisted.web import http



class URI(object):
    """
    A URI object.

    @see: U{https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-21}
    """
    def __init__(self, scheme, netloc, host, port, path, params, query,
                 fragment):
        """
        @type scheme: L{bytes}
        @param scheme: URI scheme specifier.

        @type netloc: L{bytes}
        @param netloc: Network location component.

        @type host: L{bytes}
        @param host: Host name. For IPv6 address literals the brackets are
            stripped.

        @type port: L{int}
        @param port: Port number.

        @type path: L{bytes}
        @param path: Hierarchical path.

        @type params: L{bytes}
        @param params: Parameters for last path segment.

        @type query: L{bytes}
        @param query: Query string.

        @type fragment: L{bytes}
        @param fragment: Fragment identifier.
        """
        self.scheme = scheme
        self.netloc = netloc
        self.host = host.strip(b'[]')
        self.port = port
        self.path = path
        self.params = params
        self.query = query
        self.fragment = fragment


    @classmethod
    def fromBytes(cls, uri, defaultPort=None):
        """
        Parse the given URI into a L{URI}.

        @type uri: C{bytes}
        @param uri: URI to parse.

        @type defaultPort: C{int} or L{None}
        @param defaultPort: An alternate value to use as the port if the URI
            does not include one.

        @rtype: L{URI}
        @return: Parsed URI instance.
        """
        uri = uri.strip()
        scheme, netloc, path, params, query, fragment = http.urlparse(uri)

        if defaultPort is None:
            if scheme == b'https':
                defaultPort = 443
            else:
                defaultPort = 80

        if b':' in netloc:
            host, port = netloc.rsplit(b':', 1)
            try:
                port = int(port)
            except ValueError:
                host, port = netloc, defaultPort
        else:
            host, port = netloc, defaultPort
        return cls(scheme, netloc, host, port, path, params, query, fragment)


    def toBytes(self):
        """
        Assemble the individual parts of the I{URI} into a fully formed I{URI}.

        @rtype: C{bytes}
        @return: A fully formed I{URI}.
        """
        return urlunparse(
            (self.scheme, self.netloc, self.path, self.params, self.query,
             self.fragment))


    @property
    def originForm(self):
        """
        The absolute I{URI} path including I{URI} parameters, query string and
        fragment identifier.

        @see: U{https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-21#section-5.3}

        @return: The absolute path in original form.
        @rtype: L{bytes}
        """
        # The HTTP bis draft says the origin form should not include the
        # fragment.
        path = urlunparse(
            (b'', b'', self.path, self.params, self.query, b''))
        if path == b'':
            path = b'/'
        return path


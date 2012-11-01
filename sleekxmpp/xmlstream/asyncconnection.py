import asynchat
import logging
import ssl

log = logging.getLogger(__name__)

class AsyncConnection(asynchat.async_chat, object):

    def __init__(self, xmlstream=None, sock=None, map=None):
        super(AsyncConnection, self).__init__(sock, map)
        self.xmlstream = xmlstream
        self.set_terminator(None)
        self.handshaking = False
        self.want_read = False
        self.want_write = False

    def handle_connect(self):
        self.xmlstream.event("connected", direct=True)

    def collect_incoming_data(self, data):
        self.xmlstream.collect_incoming_data(data)

    def found_terminator(self):
        pass

    def handle_read_event(self):
        if self.handshaking:
            self.handshake()
        else:
            super(AsyncConnection, self).handle_read_event()

    def handle_write_event(self):
        if self.handshaking:
            self.handshake()
        else:
            super(AsyncConnection, self).handle_write_event()

    def readable(self):
        if self.handshaking:
            return self.want_read
        else:
            return super(AsyncConnection, self).readable()

    def writable(self):
        if self.handshaking:
            return self.want_write
        else:
            return super(AsyncConnection, self).writable()

    def handle_error(self):
        log.error("error", exc_info=True)
        self.handle_close()

    def send(self, data):
        try:
            return super(AsyncConnection, self).send(data)
        except ssl.SSLError as err:
            errtype = err.args[0]
            if errtype == ssl.SSL_ERROR_WANT_READ or errtype == ssl.SSL_ERROR_WANT_WRITE:
                return 0
            if errtype == ssl.SSL_ERROR_ZERO_RETURN:
                self.handle_close()
                return 0
            raise

    def recv(self, buffer_size):
        try:
            return super(AsyncConnection, self).recv(buffer_size)
        except ssl.SSLError as err:
            errtype = err.args[0]
            if errtype == ssl.SSL_ERROR_WANT_READ or errtype == ssl.SSL_ERROR_WANT_WRITE:
                return ''
            if errtype == ssl.SSL_ERROR_ZERO_RETURN:
                self.handle_close()
                return ''
            raise

    def handle_close(self):
        self.xmlstream.disconnect()
        super(AsyncConnection, self).handle_close()

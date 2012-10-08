import asynchat


class AsyncConnection(asynchat.async_chat, object):

    def __init__(self, xmlstream=None, sock=None, map=None):
        super(AsyncConnection, self).__init__(sock, map)
        self.xmlstream = xmlstream
        self.set_terminator(None)

    def handle_connect(self):
        self.xmlstream.event("connected", direct=True)

    def collect_incoming_data(self, data):
        self.xmlstream.collect_incoming_data(data)

    def found_terminator(self):
        pass

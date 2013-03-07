"""
    SleekXMPP: The Sleek XMPP Library
    Copyright (C) 2010  Nathanael C. Fritz
    This file is part of SleekXMPP.

    See the file LICENSE for copying permission.
"""
import greenlet

from sleekxmpp.stanza.rootstanza import RootStanza
from sleekxmpp.xmlstream import StanzaBase, ET
from sleekxmpp.xmlstream.handler import Callback
from sleekxmpp.xmlstream.matcher import MatcherId
from sleekxmpp.exceptions import IqTimeout, IqError


class Iq(RootStanza):
    """
    XMPP <iq> stanzas, or info/query stanzas, are XMPP's method of
    requesting and modifying information, similar to HTTP's GET and
    POST methods.

    Each <iq> stanza must have an 'id' value which associates the
    stanza with the response stanza. XMPP entities must always
    be given a response <iq> stanza with a type of 'result' after
    sending a stanza of type 'get' or 'set'.

    Most uses cases for <iq> stanzas will involve adding a <query>
    element whose namespace indicates the type of information
    desired. However, some custom XMPP applications use <iq> stanzas
    as a carrier stanza for an application-specific protocol instead.

    Example <iq> Stanzas:
        <iq to="user@example.com" type="get" id="314">
          <query xmlns="http://jabber.org/protocol/disco#items" />
        </iq>

        <iq to="user@localhost" type="result" id="17">
          <query xmlns='jabber:iq:roster'>
            <item jid='otheruser@example.net'
                  name='John Doe'
                  subscription='both'>
              <group>Friends</group>
            </item>
          </query>
        </iq>

    Stanza Interface:
        query -- The namespace of the <query> element if one exists.

    Attributes:
        types -- May be one of: get, set, result, or error.

    Methods:
        __init__    -- Overrides StanzaBase.__init__.
        unhandled   -- Send error if there are no handlers.
        set_payload -- Overrides StanzaBase.set_payload.
        set_query   -- Add or modify a <query> element.
        get_query   -- Return the namespace of the <query> element.
        del_query   -- Remove the <query> element.
        reply       -- Overrides StanzaBase.reply
        send        -- Overrides StanzaBase.send
    """

    namespace = 'jabber:client'
    name = 'iq'
    interfaces = set(('type', 'to', 'from', 'id', 'query'))
    types = set(('get', 'result', 'set', 'error'))
    plugin_attrib = name

    def __init__(self, *args, **kwargs):
        """
        Initialize a new <iq> stanza with an 'id' value.

        Overrides StanzaBase.__init__.
        """
        StanzaBase.__init__(self, *args, **kwargs)
        if self['id'] is None:
            if self.stream is not None:
                self['id'] = self.stream.new_id()
            else:
                self['id'] = '0'

    def unhandled(self):
        """
        Send a feature-not-implemented error if the stanza is not handled.

        Overrides StanzaBase.unhandled.
        """
        if self['type'] in ('get', 'set'):
            self.reply()
            self['error']['condition'] = 'feature-not-implemented'
            self['error']['text'] = 'No handlers registered for this request.'
            self.send()

    def set_payload(self, value):
        """
        Set the XML contents of the <iq> stanza.

        Arguments:
            value -- An XML object to use as the <iq> stanza's contents
        """
        self.clear()
        StanzaBase.set_payload(self, value)
        return self

    def set_query(self, value):
        """
        Add or modify a <query> element.

        Query elements are differentiated by their namespace.

        Arguments:
            value -- The namespace of the <query> element.
        """
        query = self.xml.find("{%s}query" % value)
        if query is None and value:
            plugin = self.plugin_tag_map.get('{%s}query' % value, None)
            if plugin:
                self.enable(plugin.plugin_attrib)
            else:
                self.clear()
                query = ET.Element("{%s}query" % value)
                self.xml.append(query)
        return self

    def get_query(self):
        """Return the namespace of the <query> element."""
        for child in self.xml:
            if child.tag.endswith('query'):
                ns = child.tag.split('}')[0]
                if '{' in ns:
                    ns = ns[1:]
                return ns
        return ''

    def del_query(self):
        """Remove the <query> element."""
        for child in self.xml:
            if child.tag.endswith('query'):
                self.xml.remove(child)
        return self

    def reply(self, clear=True):
        """
        Send a reply <iq> stanza.

        Overrides StanzaBase.reply

        Sets the 'type' to 'result' in addition to the default
        StanzaBase.reply behavior.

        Arguments:
            clear -- Indicates if existing content should be
                     removed before replying. Defaults to True.
        """
        self['type'] = 'result'
        StanzaBase.reply(self, clear)
        return self

    def __handler_name(self):
        return 'IqCallback_%s' % self['id']

    def __timeout_name(self):
        return 'IqTimeout_%s' % self['id']

    def send(self, block=True, timeout=None, callback=None, now=False, timeout_callback=None):
        """
        Send an <iq> stanza over the XML stream.

        The send call can optionally block until a response is received or
        a timeout occurs. Be aware that using blocking in non-threaded event
        handlers can drastically impact performance. Otherwise, a callback
        handler can be provided that will be executed when the Iq stanza's
        result reply is received. Be aware though that that the callback
        handler will not be executed in its own thread.

        Using both block and callback is not recommended, and only the
        callback argument will be used in that case.

        Overrides StanzaBase.send

        Arguments:
            block    -- Specify if the send call will block until a response
                        is received, or a timeout occurs. Defaults to True.
            timeout  -- The length of time (in seconds) to wait for a response
                        before exiting the send call if blocking is used.
                        Defaults to sleekxmpp.xmlstream.RESPONSE_TIMEOUT
            callback -- Optional reference to a stream handler function. Will
                        be executed when a reply stanza is received.
            now      -- Indicates if the send queue should be skipped and send
                        the stanza immediately. Used during stream
                        initialization. Defaults to False.
            timeout_callback -- Optional reference to a stream handler function.
                        Will be executed when the timeout expires before a
                        response has been received with the originally-sent IQ
                        stanza.  Only called if there is a callback parameter
                        (and therefore are in async mode).
        """
        if timeout is None:
            timeout = self.stream.response_timeout
        handler_name = self.__handler_name()
        timeout_name = self.__timeout_name()
        if callback is not None and self['type'] in ('get', 'set'):
            if timeout_callback:
                self.callback = callback
                self.timeout_callback = timeout_callback
                self.stream.schedule(timeout_name,
                                     timeout,
                                     self._fire_timeout,
                                     repeat=False)
                handler = Callback(handler_name,
                                   MatcherId(self['id']),
                                   self._handle_result,
                                   once=True)
            else:
                handler = Callback(handler_name,
                                   MatcherId(self['id']),
                                   callback,
                                   once=True)
            self.stream.register_handler(handler)
            StanzaBase.send(self, now=now)
            return handler_name
        elif block and self['type'] in ('get', 'set'):
            current = greenlet.getcurrent()
            handler = Callback(handler_name,
                               MatcherId(self['id']),
                               None,
                               once=True,
                               greenlet=current)

            def timeout_callback():
                self.stream.remove_handler(handler_name)
                if handler:
                    return handler.run(IqTimeout)

            # Fire the callback with the payload None to indicate a timeout.
            # Note that the callback in this case switches to our greenlet.
            self.stream.schedule(timeout_name,
                    timeout,
                    timeout_callback,
                    repeat=False)

            self.stream.register_handler(handler)
            StanzaBase.send(self, now=now)
            self.stream.waiting_greenlets.add(current)
            result = current.parent.switch()
            self.stream.waiting_greenlets.remove(current)
            self.stream.unschedule(timeout_name)
            handler = None

            if result is IqTimeout:
                # We hit the return value from the scheduled callback.
                # This means the normal handler has not fired yet.
                raise IqTimeout(self)
            # In this case, we got the Iq response. Remove the timeout.

            if result['type'] == 'error':
                raise IqError(result)
            return result
        else:
            return StanzaBase.send(self, now=now)

    def _handle_result(self, iq):
        # we got the IQ, so don't fire the timeout
        self.stream.unschedule(self.__timeout_name())
        self.callback(iq)

    def _fire_timeout(self):
        # don't fire the handler for the IQ, if it finally does come in
        self.stream.remove_handler(self.__handler_name())
        self.timeout_callback(self)

    def _set_stanza_values(self, values):
        """
        Set multiple stanza interface values using a dictionary.

        Stanza plugin values may be set usind nested dictionaries.

        If the interface 'query' is given, then it will be set
        last to avoid duplication of the <query /> element.

        Overrides ElementBase._set_stanza_values.

        Arguments:
            values -- A dictionary mapping stanza interface with values.
                      Plugin interfaces may accept a nested dictionary that
                      will be used recursively.
        """
        query = values.get('query', '')
        if query:
            del values['query']
            StanzaBase._set_stanza_values(self, values)
            self['query'] = query
        else:
            StanzaBase._set_stanza_values(self, values)
        return self


# To comply with PEP8, method names now use underscores.
# Deprecated method names are re-mapped for backwards compatibility.
Iq.setPayload = Iq.set_payload
Iq.getQuery = Iq.get_query
Iq.setQuery = Iq.set_query
Iq.delQuery = Iq.del_query

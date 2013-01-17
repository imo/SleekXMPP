# -*- coding: utf-8 -*-
"""
    sleekxmpp.xmlstream.handler.callback
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Part of SleekXMPP: The Sleek XMPP Library

    :copyright: (c) 2011 Nathanael C. Fritz
    :license: MIT, see LICENSE for more details
"""

import logging
import greenlet
from sleekxmpp.xmlstream.handler.base import BaseHandler

log = logging.getLogger(__name__)

class Callback(BaseHandler):

    """
    The Callback handler will execute a callback function with
    matched stanzas.

    The handler may execute the callback either during stream
    processing or during the main event loop.

    Callback functions are all executed in the same thread, so be aware if
    you are executing functions that will block for extended periods of
    time. Typically, you should signal your own events using the SleekXMPP
    object's :meth:`~sleekxmpp.xmlstream.xmlstream.XMLStream.event()`
    method to pass the stanza off to a threaded event handler for further
    processing.


    :param string name: The name of the handler.
    :param matcher: A :class:`~sleekxmpp.xmlstream.matcher.base.MatcherBase`
                    derived object for matching stanza objects.
    :param pointer: The function to execute during callback.
    :param bool thread: **DEPRECATED.** Remains only for
                        backwards compatibility.
    :param bool once: Indicates if the handler should be used only
                      once. Defaults to False.
    :param bool instream: Indicates if the callback should be executed
                          during stream processing instead of in the
                          main event loop.
    :param stream: The :class:`~sleekxmpp.xmlstream.xmlstream.XMLStream`
                   instance this handler should monitor.
    """

    def __init__(self, name, matcher, pointer, thread=False,
                 once=False, instream=False, stream=None, greenlet=None):
        BaseHandler.__init__(self, name, matcher, stream)
        self._pointer = pointer
        self._once = once
        self._greenlet = greenlet

    def prerun(self, payload):
        """Execute the callback during stream processing, if
        the callback was created with ``instream=True``.

        :param payload: The matched
            :class:`~sleekxmpp.xmlstream.stanzabase.ElementBase` object.
        """
        if self._once:
            self._destroy = True

    def run(self, payload, instream=False):
        """Execute the callback function with the matched stanza payload.

        :param payload: The matched
            :class:`~sleekxmpp.xmlstream.stanzabase.ElementBase` object.
        :param bool instream: Force the handler to execute during stream
                              processing. This should only be used by
                              :meth:`prerun()`. Defaults to ``False``.
        """
        if self._greenlet:
            res = payload
            # after returning, the current greenlet dies
            # and execution continues in the parent greenlet
            greenlet.getcurrent().parent = self._greenlet
        else:
            res = self._pointer(payload)
        if self._once:
            self._destroy = True
            del self._pointer
        return res

    def __str__(self):
        try:
            if self._pointer:
                return 'Callback: ' + str(self._pointer)
            elif self._greenlet:
                return 'Greenlet callback'
            else:
                return 'Unknown callback'
        except:
            return 'Used one-time callback'

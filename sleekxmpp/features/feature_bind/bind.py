"""
    SleekXMPP: The Sleek XMPP Library
    Copyright (C) 2011  Nathanael C. Fritz
    This file is part of SleekXMPP.

    See the file LICENSE for copying permission.
"""

import logging

from sleekxmpp.jid import JID
from sleekxmpp.stanza import Iq, StreamFeatures
from sleekxmpp.features.feature_bind import stanza
from sleekxmpp.xmlstream import register_stanza_plugin
from sleekxmpp.plugins import BasePlugin, register_plugin


log = logging.getLogger(__name__)


class FeatureBind(BasePlugin):

    name = 'feature_bind'
    description = 'RFC 6120: Stream Feature: Resource Binding'
    dependencies = set()
    stanza = stanza

    def plugin_init(self):
        self.xmpp.register_feature('bind',
                self._handle_bind_resource,
                restart=False,
                order=10000)

        register_stanza_plugin(Iq, stanza.Bind)
        register_stanza_plugin(StreamFeatures, stanza.Bind)

    def _handle_bind_resource(self, features):
        """
        Handle requesting a specific resource.

        Arguments:
            features -- The stream features stanza.
        """
        log.debug("Requesting resource: %s", self.xmpp.requested_jid.resource)
        iq = self.xmpp.Iq()
        iq['type'] = 'set'
        iq.enable('bind')
        if self.xmpp.requested_jid.resource:
            iq['bind']['resource'] = self.xmpp.requested_jid.resource
        response = iq.send(now=True)
        if response['bind']['jid']:
            # RFC 3921 specifies that servers MUST include a jid element.
            self.xmpp.boundjid = JID(response['bind']['jid'], cache_lock=True)
        elif response['bind']['resource']:
            # VKontakte sends a resource element instead of jid.
            self.xmpp.boundjid = JID(self.xmpp.requested_jid,
                    resource=response['bind']['resource'])
        else:
            log.error("Bind stanza missing JID: %s" % iq)
        self.xmpp.bound = True
        self.xmpp.event('session_bind', self.xmpp.boundjid, direct=True)
        self.xmpp.session_bind_event = True

        self.xmpp.features.add('bind')

        log.info("JID set to: %s", self.xmpp.boundjid.full)

        if 'session' not in features['features']:
            log.debug("Established Session")
            self.xmpp.sessionstarted = True
            self.xmpp.session_started_event = True
            self.xmpp.event("session_start")

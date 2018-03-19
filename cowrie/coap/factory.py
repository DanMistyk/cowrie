# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
Constrained Application Protocol for the Honeypot

@author: Dany YARAKOU< yarakou@gmail.com>
"""

from __future__ import division, absolute_import

import time

from twisted.internet import protocol

from twisted.internet import defer
from twisted.internet import reactor
from twisted.python import log

from cowrie.coap.server import CounterResource, BlockResource, CoreResource, SeparateLargeResource, TimeResource

import cowrie.coap.txthings.resource as resource
import cowrie.coap.txthings.coap as coap





class CowrieCoAPFactory(protocol.ServerFactory):
    """
    This factory creates HoneyPotSSHTransport instances
    They listen directly to the TCP port
    """

    starttime = None
    primes = None
    tac = None # gets set later

    def __init__(self, cfg):
        self.cfg = cfg


    def logDispatch(self, *msg, **args):
        """
        Special delivery to the loggers to avoid scope problems
        """
        args['sessionno'] = 'S'+str(args['sessionno'])
        for dblog in self.tac.dbloggers:
            dblog.logDispatch(*msg, **args)
        for output in self.tac.output_plugins:
            output.logDispatch(*msg, **args)


    def startFactory(self):
        """
        """
        # For use by the uptime command
        self.starttime = time.time()

        # root = resource.CoAPResource()

        # well_known = resource.CoAPResource()
        # root.putChild('.well-known', well_known)
        # core = CoreResource(root)
        # well_known.putChild('core', core)

        # counter = CounterResource(5000)
        # root.putChild('counter', counter)

        # timeNow = TimeResource()
        # root.putChild('time', timeNow)

        # other = resource.CoAPResource()
        # root.putChild('other', other)

        # block = BlockResource()
        # other.putChild('block', block)

        # separate = SeparateLargeResource()
        # other.putChild('separate', separate)


        protocol.ServerFactory.startFactory(self)
        log.msg("Ready to accept CoAP connections")


    def stopFactory(self):
        """
        """
        protocol.ServerFactory.stopFactory(self)


    # def buildProtocol(self, addr):
    #     """
    #     Create an instance of the server side of the SSH protocol.

    #     @type addr: L{twisted.internet.interfaces.IAddress} provider
    #     @param addr: The address at which the server will listen.

    #     @rtype: L{cowrie.ssh.transport.HoneyPotSSHTransport}
    #     @return: The built transport.
    #     """

    #     _modulis = '/etc/ssh/moduli', '/private/etc/moduli'

    #     t = transport.HoneyPotSSHTransport()

    #     try:
    #         t.ourVersionString = self.cfg.get('ssh', 'version')
    #     except:
    #         t.ourVersionString = "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"

    #     t.supportedPublicKeys = list(self.privateKeys.keys())

    #     for _moduli in _modulis:
    #         try:
    #             self.primes = primes.parseModuliFile(_moduli)
    #             break
    #         except IOError as err:
    #             pass

    #     if not self.primes:
    #         ske = t.supportedKeyExchanges[:]
    #         if 'diffie-hellman-group-exchange-sha1' in ske:
    #             ske.remove('diffie-hellman-group-exchange-sha1')
    #             log.msg("No moduli, no diffie-hellman-group-exchange-sha1")
    #         if 'diffie-hellman-group-exchange-sha256' in ske:
    #             ske.remove('diffie-hellman-group-exchange-sha256')
    #             log.msg("No moduli, no diffie-hellman-group-exchange-sha256")
    #         t.supportedKeyExchanges = ske

    #     # Reorder supported ciphers to resemble current openssh more
    #     t.supportedCiphers = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr',
    #         'aes128-cbc', '3des-cbc', 'blowfish-cbc', 'cast128-cbc',
    #         'aes192-cbc', 'aes256-cbc']
    #     t.supportedPublicKeys = ['ssh-rsa', 'ssh-dss']
    #     t.supportedMACs = ['hmac-md5', 'hmac-sha1']
    #     t.supportedCompressions = ['zlib@openssh.com', 'zlib', 'none']

    #     t.factory = self
    #     return t


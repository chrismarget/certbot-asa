"""ASA Authentication"""
import logging
import os
import subprocess

import zope.interface

from acme import challenges

from certbot import errors
from certbot import interfaces
from certbot import reverter

from certbot.plugins import common

from certbot_asa import dvsni
from certbot_asa import asa

logger = logging.getLogger(__name__)


class AsaConfigurator(common.Plugin):
    """ASA Configurator."""
    zope.interface.implements(interfaces.IAuthenticator, interfaces.IInstaller)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "DVSNI Authentication/Installation via Cisco ASA REST API"

    @classmethod
    def add_parser_arguments(cls, add):
        print "add_parser_arguments"									# delete me
        add("host", help="ASA host", action='append', default=[])
        add("chost", help="ASA challenge host, specify multiple times", action='append', default=[])
        add("credfile", help="ASA credentials file, defaults to <config-dir>/asa_creds.txt")
        add("creddelim", help="ASA credentials file delimiter", default=';')
        add("interface", help="Attach new certificate to interface, rather than domain")
        add("untrusted", help="Ignore SSL errors when making REST calls to managed ASA boxes", action='store_true')



    def __init__(self, *args, **kwargs):
        print "__init__"									# delete me
        """Initialize an ASA Authenticator."""
        super(AsaConfigurator, self).__init__(*args, **kwargs)

        # credfile lives in self.credfile rather than self.conf('credfile')
        # because I couldn't figure out how collect work_dir in
        # add_parser_arguments, presumably because of the @classmethod
        # decorator. Without work_dir, I couldn't set up the default value
        # correctly. So, I do it here.
        if self.conf('credfile'):
            self.credfile = self.conf('credfile')
        else:
            self.credfile = os.path.join(self.config.work_dir, 'asa_creds.txt')

        self.asa = {}
        self.asacreds = {}
        self.argprefix=''.join(["--",args[1],"-"])

        # Set up reverter
        self.reverter = reverter.Reverter(self.config)
        self.reverter.recovery_routine()

    # This is called in determine_authenticator and determine_installer
    def prepare(self):
        print "configurator.prepare"
        import os
        import stat
        """Prepare the authenticator/installer."""

        # Ensure that we've got at least one 'host' to work with. It's not
        # specified as 'required=True' for argparse because it's not reasonable
        # for this plugin to require arguments when the plugin might not be
        # in use.
        if not self.conf('host'):
             raise errors.PluginError("You haven't specified any ASAs for certificate installation. "
                                      "Use: %shost <host>" % (self.argprefix))
        # Each host and chost should appear once. No duplicates.
        allhosts = self.conf('host') + self.conf('chost')
        if set([x for x in allhosts if allhosts.count(x) > 1]):
             raise errors.PluginError("Don't specify a host more than once.")

        # Collect file permission bits from the asa credentials file
        try:
            st = os.stat(self.credfile)
        except IOError as e:
             raise errors.PluginError("I/O error({0}): {1}".format(e.errno, e.strerror))

        # bad_bits allow r/w/x to group or others
        bad_bits = (
            stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP |
            stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH)

        # We don't want bad_bits set on this file
        if (bad_bits & stat.S_IMODE(st.st_mode)) != 0:
            raise errors.PluginError(
                "REFUSING TO RUN: ASA Credentials file "+self.credfile+
                " must not permit group/other access.")

        # Read the credentials into a nested dictionary.
        # self.asacreds = {
        #    'host1': { 'user': 'user1', 'passwd': 'abc123' },
        #    'host2': { 'user': 'user2', 'passwd': 'cba321' }}
        try:
            f = open(self.credfile)
        except IOError as e:
            raise errors.PluginError(
                "I/O error({0}): {1}".format(e.errno, e.strerror))
        i = 0
        for credline in iter(f.readline, ''):
            i += 1
            try:
                host, user, passwd = credline.rstrip().split(self.conf('creddelim'),2)
            except:
                logger.error(self.credfile+" line "+str(i)+
                    ": Got less than 3 values when splitting with `"+
                    self.conf('creddelim')+"'")
                continue
            self.asacreds[host] = {'user': user, 'passwd': passwd}

        # Do we have credentials for all named hosts?
        for h in self.conf('host') + self.conf('chost'):
            if not h in self.asacreds.keys():
                raise errors.PluginError("Missing credentials for `"+h+"'")
            self.asa[h] = asa.RestAsa(h, self.asacreds[h]['user'], self.asacreds[h]['passwd'], self.conf('untrusted'))

        # Is each ASA responding on TCP/443? Hosts which don't respond will be
        # removed from the list on the assumption that if we can't hit 'em, then
        # the LE headend and users can't hit 'em either.
        #  - hosts:  Maybe the user has specified more than one target box? We
        #            want to install certificates on reachable units so delete
        #            the non-responders from the list and move on.
        #  - chosts: We're only talking about these boxes because a floating IP
        #            or DNS record *might* be pointing at them. Boxes that are
        #            down likely won't be challenged by LetsEncrypt, so ignore
        #            'em and move on.
        for h in self.conf('host'):
            if not self.asa[h].livetest():
                logger.error("ASA host `"+h+"' not responding.")
                self.conf('host').remove(h)
        for h in self.conf('chost'):
            if not self.asa[h].livetest():
                logger.error("ASA host `"+h+"' not responding.")
                self.conf('chost').remove(h)

        # Do we now have an empty list of hosts?
        if not self.conf('host'):
            raise errors.PluginError("None of the configured ASAs are responding.")

        # Test the credentials for each operational ASA. Any failure is a reason to bail.
        for h in self.conf('host') + self.conf('chost'):
            result = self.asa[h].authtest()
            if not result[0]:
                if "SSL: CERTIFICATE_VERIFY_FAILED" in str(result[1]):
                    raise errors.PluginError("SSL Certificate Validation failure "
                    "with "+h+". Consider using the `untrusted' CLI option "
                    "for this plugin.")
                else:
                    raise errors.PluginError(str(result[1]))
        pass

    def get_chall_pref(self, domain):
        """Return list of challenge preferences.

        :param str domain: Domain for which challenge preferences are sought.

        :returns: List of challenge types (subclasses of
            :class:`acme.challenges.Challenge`) with the most
            preferred challenges first. If a type is not specified, it means the
            Authenticator cannot perform the challenge.
        :rtype: list

        """
        return [challenges.TLSSNI01]

    def perform(self, achalls):
        print "begin configurator.perform"				# delete me
        """Perform the given challenge.

        :param list achalls: Non-empty (guaranteed) list of
            :class:`~certbot.achallenges.AnnotatedChallenge`
            instances, such that it contains types found within
            :func:`get_chall_pref` only.

        :returns: List of ACME
            :class:`~acme.challenges.ChallengeResponse` instances
            or if the :class:`~acme.challenges.Challenge` cannot
            be fulfilled then:

            ``None``
              Authenticator can perform challenge, but not at this time.
            ``False``
              Authenticator will never be able to perform (error).

        :rtype: :class:`list` of
            :class:`acme.challenges.ChallengeResponse`

        :raises .PluginError: If challenges cannot be performed

        """
        asa_dvsni = dvsni.AsaDvsni(self)

        responses = []

        for i, achall in enumerate(achalls):
            responses.append(None)
            asa_dvsni.add_chall(achall, i)

        sni_response = asa_dvsni.perform(list(self.asa.values()))

        # Go through all of the challenges and assign them to the proper place
        # in the responses return value. All responses must be in the same order
        # as the original challenges.
        for i, resp in enumerate(sni_response):
            responses[asa_dvsni.indices[i]] = resp

        print "done configurator.perform"				# delete me
        return responses

    def cleanup(self, achalls):
        """Revert changes and shutdown after challenges complete.

        :param list achalls: Non-empty (guaranteed) list of
            :class:`~certbot.achallenges.AnnotatedChallenge`
            instances, a subset of those previously passed to :func:`perform`.

        :raises PluginError: if original configuration cannot be restored

        """
        print "begin configurator.cleanup"				# delete me
        asa_dvsni = dvsni.AsaDvsni(self)
        for i, achall in enumerate(achalls):
            asa_dvsni.add_chall(achall, i)
        cleanup_response = asa_dvsni.cleanup(list(self.asa.values()))
        print "end configurator.cleanup"				# delete me

    def more_info(self):
        print "more_info"									# delete me
        """Human-readable string to help understand the module"""
        return (
            "Plugin responds to DVSNI01 challenges with, and installs "
            "certificates to Cisco ASA via REST API."
        )

    def get_all_names(self):
        """Returns all names that may be authenticated."""
        print "get_all_names()"
        return []

    @staticmethod
    def view_config_changes():
        """No ability to preview configs"""
        raise errors.NotSupportedError(
            'No ability to preview configs')

    def deploy_cert(self, domain, cert_path, key_path, chain_path=None, fullchain_path=None):
        """Initialize deploy certificate in ASA via REST API."""
        print ("begin configurator.deploy_cert()")
        print (domain)
        print (cert_path)
        print (key_path)
        print (chain_path)
        print (fullchain_path)
        print ("done configurator.deploy_cert()")

    @staticmethod
    def supported_enhancements():
        """Returns a list of supported enhancements."""
        print ("begin configurator.staticmethod()")
        print ("done configurator.staticmethod()")
        return []

    @staticmethod
    def config_test():
        """Assume configuration is always valid."""
        print ("begin configurator.config_test()")
        print ("done configurator.config_test()")
        pass  # pragma: no cover

    def recovery_routine(self):
        """Revert deployer changes."""
        print ("begin configurator.recovery_routine()")
        print ("done configurator.recovery_routine()")
        pass  # pragma: no cover

    @staticmethod
    def enhance(unused_domain, unused_enhancement, unused_options=None):
        """No enhancements are supported now."""
        print ("begin configurator.enhance()")
        print ("done configurator.enhance()")
        raise errors.NotSupportedError('No enhancements are supported now.')

    def save(self, unused_title=None, temporary=False):
        """Push Plesk to deploy certificate."""
        print ("begin configurator.save()")
        # todo: save the config here
        print ("done configurator.save()")
        pass  # pragma: no cover

    @staticmethod
    def rollback_checkpoints(unused_rollback=1):
        """Revert deployer state to the previous."""
        print ("begin configurator.rollback_checkpoints()")
        print ("done configurator.rollback_checkpoints()")
        raise errors.NotSupportedError()

    @staticmethod
    def get_all_certs_keys():
        """No interest in retrieving certificate data from ASA."""
        print ("begin configurator.get_all_certs_keys()")
        print ("done configurator.get_all_certs_keys()")
        return []

    def restart(self):
        """Nothing to restart. ASA configuration is live when applied."""
        print ("begin configurator.restart()")
        print ("done configurator.restart()")
        pass

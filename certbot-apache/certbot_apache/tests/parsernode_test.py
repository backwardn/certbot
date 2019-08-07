""" Tests for ParserNode interface """

import unittest

import mock

from acme.magic_typing import Dict, Tuple  # pylint: disable=unused-import, no-name-in-module

from certbot_apache import augeasparser
from certbot_apache import interfaces

from certbot_apache.tests import util



class DummyCommentNode(interfaces.CommentNode):
    """ A dummy class implementing CommentNode interface """
    ancestor = None
    comment = ""
    dirty = False

    def save(self, msg):  # pragma: no cover
        pass


class DummyDirectiveNode(interfaces.DirectiveNode):
    """ A dummy class implementing DirectiveNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    dirty = False
    enabled = True
    name = ""

    def save(self, msg):  # pragma: no cover
        pass

    def set_parameters(self, parameters):  # pragma: no cover
        pass


class DummyBlockNode(interfaces.BlockNode):
    """ A dummy class implementing BlockNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    children = tuple()  # type: Tuple[interfaces.ParserNode, ...]
    dirty = False
    enabled = True
    name = ""

    def save(self, msg):  # pragma: no cover
        pass

    def add_child_block(self, name, parameters=None, position=None):  # pragma: no cover
        pass

    def add_child_directive(self, name, parameters=None, position=None):  # pragma: no cover
        pass

    def add_child_comment(self, comment="", position=None):  # pragma: no cover
        pass

    def find_blocks(self, name, exclude=True):  # pragma: no cover
        pass

    def find_directives(self, name, exclude=True):  # pragma: no cover
        pass

    def find_comments(self, comment, exact=False):  # pragma: no cover
        pass

    def delete_child(self, child):  # pragma: no cover
        pass

    def set_parameters(self, parameters):  # pragma: no cover
        pass

    def unsaved_files(self):  # pragma: no cover
        pass


class ParserNodeTest(util.ApacheTest):
    """Test cases for ParserNode interface"""

    def __init__(self, *args, **kwargs):
        super(ParserNodeTest, self).__init__(*args, **kwargs)
        self.mock_nodes = dict()  # type: Dict[str, interfaces.ParserNode]

    def setUp(self):  # pylint: disable=arguments-differ
        super(ParserNodeTest, self).setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir)
        self.config = self.mock_deploy_cert(self.config)
        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multiple_vhosts")

    def mock_deploy_cert(self, config):
        """A test for a mock deploy cert"""
        config.real_deploy_cert = self.config.deploy_cert

        def mocked_deploy_cert(*args, **kwargs):
            """a helper to mock a deployed cert"""
            g_mod = "certbot_apache.configurator.ApacheConfigurator.enable_mod"
            with mock.patch(g_mod):
                config.real_deploy_cert(*args, **kwargs)
        self.config.deploy_cert = mocked_deploy_cert
        return self.config

    def test_dummy(self):
        dummyblock = DummyBlockNode()
        dummydirective = DummyDirectiveNode()
        dummycomment = DummyCommentNode()

    def _create_mock_vhost_nodes(self, servername, serveraliases, addrs):
        """Create a mock VirtualHost nodes"""

        nodes = {
            "VirtualHost": augeasparser.AugeasBlockNode("VirtualHost", tuple(addrs)),
            "ServerName": augeasparser.AugeasDirectiveNode("ServerName",
                                                           (servername,)),
            "ServerAlias": augeasparser.AugeasDirectiveNode("ServerAlias",
                                                            tuple(serveraliases)),
            "Macro": augeasparser.AugeasDirectiveNode("Macro", ("variable", "value",)),
            "SSLEngine": augeasparser.AugeasDirectiveNode("SSLEngine", ("on",))
        }
        return nodes

    def mock_find_directives(self, name, exclude=True):  # pylint: disable=unused-argument
        """
        Mocks BlockNode.find_directives() and returns values defined in class
        variable self.mock_nodes, set by the test case
        """
        try:
            return self.mock_nodes[name]
        except KeyError:
            return []

    def test_create_vhost_v2_nonssl(self):
        nodes = self._create_mock_vhost_nodes("example.com",
                                              ["a1.example.com", "a2.example.com"],
                                              ["*:80"])

        nodes["VirtualHost"].find_directives = self.mock_find_directives
        self.mock_nodes = {"ServerName": [nodes["ServerName"]],
                           "ServerAlias": [nodes["ServerAlias"]]}
        vhost = self.config._create_vhost_v2(nodes["VirtualHost"])  # pylint: disable=protected-access
        self.assertEqual(vhost.name, "example.com")
        self.assertTrue("a1.example.com" in vhost.aliases)
        self.assertTrue("a2.example.com" in vhost.aliases)
        self.assertEqual(len(vhost.aliases), 2)
        self.assertEqual(len(vhost.addrs), 1)
        self.assertFalse(vhost.ssl)
        self.assertFalse(vhost.modmacro)

    def test_create_vhost_v2_macro(self):
        nodes = self._create_mock_vhost_nodes("example.com",
                                              ["a1.example.com", "a2.example.com"],
                                              ["*:80"])

        nodes["VirtualHost"].find_directives = self.mock_find_directives
        self.mock_nodes = {"ServerName": [nodes["ServerName"]],
                           "ServerAlias": [nodes["ServerAlias"]],
                           "Macro": [nodes["Macro"]]}
        vhost = self.config._create_vhost_v2(nodes["VirtualHost"])  # pylint: disable=protected-access
        self.assertEqual(vhost.name, None)
        self.assertEqual(vhost.aliases, set())
        self.assertFalse(vhost.ssl)
        self.assertTrue(vhost.modmacro)

    def test_create_vhost_v2_ssl_port(self):
        nodes = self._create_mock_vhost_nodes("example.com",
                                              ["a1.example.com", "a2.example.com"],
                                              ["*:443"])

        nodes["VirtualHost"].find_directives = self.mock_find_directives
        self.mock_nodes = {"ServerName": [nodes["ServerName"]],
                           "ServerAlias": [nodes["ServerAlias"]]}
        vhost = self.config._create_vhost_v2(nodes["VirtualHost"])  # pylint: disable=protected-access
        self.assertTrue(vhost.ssl)
        self.assertFalse(vhost.modmacro)

    def test_create_vhost_v2_sslengine(self):
        nodes = self._create_mock_vhost_nodes("example.com",
                                              ["a1.example.com", "a2.example.com"],
                                              ["*:80"])

        nodes["VirtualHost"].find_directives = self.mock_find_directives
        self.mock_nodes = {"ServerName": [nodes["ServerName"]],
                           "ServerAlias": [nodes["ServerAlias"]],
                           "SSLEngine": [nodes["SSLEngine"]]}
        vhost = self.config._create_vhost_v2(nodes["VirtualHost"])  # pylint: disable=protected-access
        self.assertTrue(vhost.ssl)
        self.assertFalse(vhost.modmacro)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover

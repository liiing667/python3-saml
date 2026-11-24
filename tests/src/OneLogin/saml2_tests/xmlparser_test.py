# -*- coding: utf-8 -*-

import base64
import io
import unittest

from os.path import dirname, join

from lxml.etree import XMLSyntaxError
from onelogin.saml2 import xmlparser


class TestOneLoginSaml2XmlParser(unittest.TestCase):
    data_path = join(dirname(__file__), "..", "..", "..", "data")

    def test_valid_xml_is_parsed(self):
        element = xmlparser.fromstring(b'<root><child name="value">text</child></root>')
        self.assertEqual("root", element.tag)
        self.assertEqual("value", element[0].get("name"))

        tree = xmlparser.parse(io.BytesIO(b"<root/>"))
        self.assertEqual("root", tree.getroot().tag)

    def test_signed_response_is_parsed(self):
        with open(join(self.data_path, "responses", "signed_message_response.xml.base64"), "rb") as stream:
            response = base64.b64decode(stream.read())
        element = xmlparser.fromstring(response)
        self.assertEqual("Response", element.tag.rsplit("}", 1)[-1])

    def test_dtd_is_forbidden_before_dom_construction(self):
        with self.assertRaises(xmlparser.DTDForbidden):
            xmlparser.fromstring(b'<!DOCTYPE root [<!ENTITY value "expanded">]><root>&value;</root>')
        with self.assertRaises(xmlparser.DTDForbidden):
            xmlparser.parse(io.BytesIO(b"<!DOCTYPE root><root/>"))

    def test_entities_are_forbidden_when_dtd_is_allowed(self):
        with self.assertRaises(xmlparser.EntitiesForbidden):
            xmlparser.fromstring(b'<!DOCTYPE root [<!ENTITY value "expanded">]><root>&value;</root>', forbid_dtd=False)

    def test_deep_nesting_exceeds_budget(self):
        depth = xmlparser.MAX_XML_DEPTH + 1
        document = b"<a>" * depth + b"</a>" * depth
        with self.assertRaises(xmlparser.ResourceLimitError):
            xmlparser.fromstring(document)

    def test_large_attribute_exceeds_budget(self):
        document = b'<root value="' + b"A" * (xmlparser.MAX_XML_ATTRIBUTE_LENGTH + 1) + b'"/>'
        with self.assertRaises(xmlparser.ResourceLimitError):
            xmlparser.fromstring(document)

    def test_malformed_xml_keeps_lxml_error(self):
        with self.assertRaises(XMLSyntaxError):
            xmlparser.fromstring(b"<root>")

    def test_rejection_does_not_pollute_default_parser(self):
        parser = xmlparser.getDefaultParser()
        errors_before = len(parser.error_log)
        with self.assertRaises(xmlparser.DTDForbidden):
            xmlparser.fromstring(b"<!DOCTYPE root><root/>")
        self.assertIs(parser, xmlparser.getDefaultParser())
        self.assertEqual(errors_before, len(parser.error_log))
        self.assertEqual("root", xmlparser.fromstring(b"<root/>", parser=parser).tag)

    def test_malformed_input_does_not_pollute_default_parser(self):
        parser = xmlparser.getDefaultParser()
        errors_before = len(parser.error_log)
        with self.assertRaises(XMLSyntaxError):
            xmlparser.fromstring(b"<root>")
        self.assertIs(parser, xmlparser.getDefaultParser())
        self.assertEqual(errors_before, len(parser.error_log))
        self.assertEqual("root", xmlparser.fromstring(b"<root/>").tag)

    def test_stream_position_is_restored_on_rejection(self):
        stream = io.BytesIO(b"<!DOCTYPE root><root/>")
        with self.assertRaises(xmlparser.DTDForbidden):
            xmlparser.parse(stream)
        self.assertEqual(0, stream.tell())


if __name__ == "__main__":
    unittest.main()

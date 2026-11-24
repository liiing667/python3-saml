# -*- coding: utf-8 -*-

# Based on the lxml example from defusedxml
# DTDForbidden, EntitiesForbidden, NotSupportedError are clones of the classes defined at defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""lxml.etree protection"""

from __future__ import print_function, absolute_import

import io
import os
import threading

from lxml import etree as _etree

try:
    from xml.parsers import expat as _expat
except ImportError:  # pragma: no cover - expat is part of the standard library
    _expat = None

LXML3 = _etree.LXML_VERSION[0] >= 3

__origin__ = "lxml.etree"

tostring = _etree.tostring


# Shared resource budget applied before lxml is allowed to build a DOM.  The
# limits are deliberately generous (real SAML messages are much smaller) but
# they prevent a single document from making the parser allocate an unbounded
# amount of memory or recurse without limit.
MAX_XML_SIZE = 16 * 1024 * 1024
MAX_XML_DEPTH = 64
MAX_XML_ELEMENTS = 100000
MAX_XML_ATTRIBUTE_LENGTH = 8 * 1024
MAX_XML_ATTRIBUTES = 64
MAX_XML_ENTITY_LENGTH = 8 * 1024
MAX_XML_TEXT_LENGTH = 16 * 1024 * 1024

# Backwards/forwards friendly aliases for callers that want to refer to the
# policy values without knowing the exact spelling used by this module.
MAX_DOCUMENT_SIZE = MAX_XML_SIZE
MAX_DEPTH = MAX_XML_DEPTH
MAX_ELEMENTS = MAX_XML_ELEMENTS
MAX_ATTRIBUTE_SIZE = MAX_XML_ATTRIBUTE_LENGTH
MAX_ENTITY_SIZE = MAX_XML_ENTITY_LENGTH


class DTDForbidden(ValueError):
    """Document type definition is forbidden"""

    def __init__(self, name, sysid, pubid):
        super(DTDForbidden, self).__init__()
        self.name = name
        self.sysid = sysid
        self.pubid = pubid

    def __str__(self):
        tpl = "DTDForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class EntitiesForbidden(ValueError):
    """Entity definition is forbidden"""

    def __init__(self, name, value, base, sysid, pubid, notation_name):
        super(EntitiesForbidden, self).__init__()
        self.name = name
        self.value = value
        self.base = base
        self.sysid = sysid
        self.pubid = pubid
        self.notation_name = notation_name

    def __str__(self):
        tpl = "EntitiesForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class NotSupportedError(ValueError):
    """The operation is not supported"""


class ResourceLimitError(NotSupportedError):
    """The XML document exceeds one of the pre-parse resource budgets"""

    def __init__(self, resource, limit, actual=None, message=None):
        self.resource = resource
        self.limit = limit
        self.actual = actual
        if message is None:
            if actual is None:
                message = "XML %s limit exceeded (limit=%s)" % (resource, limit)
            else:
                message = "XML %s limit exceeded (limit=%s, actual=%s)" % (resource, limit, actual)
        super(ResourceLimitError, self).__init__(message)


# Common names used by applications when handling parser resource limits.
ResourceLimitExceeded = ResourceLimitError
XMLResourceLimitError = ResourceLimitError
BudgetExceeded = ResourceLimitError


class RestrictedElement(_etree.ElementBase):
    """A restricted Element class that filters out instances of some classes"""

    __slots__ = ()
    blacklist = (_etree._Entity, _etree._ProcessingInstruction, _etree._Comment)

    def _filter(self, iterator):
        blacklist = self.blacklist
        for child in iterator:
            if isinstance(child, blacklist):
                continue
            yield child

    def __iter__(self):
        iterator = super(RestrictedElement, self).__iter__()
        return self._filter(iterator)

    def iterchildren(self, tag=None, reversed=False):
        iterator = super(RestrictedElement, self).iterchildren(tag=tag, reversed=reversed)
        return self._filter(iterator)

    def iter(self, tag=None, *tags):
        iterator = super(RestrictedElement, self).iter(tag=tag, *tags)
        return self._filter(iterator)

    def iterdescendants(self, tag=None, *tags):
        iterator = super(RestrictedElement, self).iterdescendants(tag=tag, *tags)
        return self._filter(iterator)

    def itersiblings(self, tag=None, preceding=False):
        iterator = super(RestrictedElement, self).itersiblings(tag=tag, preceding=preceding)
        return self._filter(iterator)

    def getchildren(self):
        iterator = super(RestrictedElement, self).__iter__()
        return list(self._filter(iterator))

    def getiterator(self, tag=None):
        iterator = super(RestrictedElement, self).getiterator(tag)
        return self._filter(iterator)


class GlobalParserTLS(threading.local):
    """Thread local context for custom parser instances"""

    parser_config = {"resolve_entities": False, "remove_comments": True, "no_network": True, "remove_pis": True, "huge_tree": False}

    element_class = RestrictedElement

    def createDefaultParser(self):
        parser = _etree.XMLParser(**self.parser_config)
        element_class = self.element_class
        if self.element_class is not None:
            lookup = _etree.ElementDefaultClassLookup(element=element_class)
            parser.set_element_class_lookup(lookup)
        return parser

    def setDefaultParser(self, parser):
        self._default_parser = parser

    def getDefaultParser(self):
        parser = getattr(self, "_default_parser", None)
        if parser is None:
            parser = self.createDefaultParser()
            self.setDefaultParser(parser)
        return parser


_parser_tls = GlobalParserTLS()
getDefaultParser = _parser_tls.getDefaultParser


def _parser_for_call(parser):
    """Return the parser to use for a single parse call.

    The thread-local default parser is a configuration template.  Parsing with
    a private copy means that a failing document (including a malformed one
    that gets past the preflight checks) cannot leave error state or partial
    input on the parser that the next caller will receive.
    """
    if parser is not None:
        return parser
    default_parser = getDefaultParser()
    try:
        return default_parser.copy()
    except (AttributeError, TypeError):  # pragma: no cover - lxml always has copy()
        return default_parser


def _preflight_text(text, forbid_dtd, forbid_entities):
    """Apply the shared prohibition and resource policy before an XML DOM is built.

    This deliberately uses Expat as a streaming, non-DOM parser.  It gives us a
    chance to reject DTDs, entity declarations, excessive nesting and oversized
    attributes before lxml performs any tree construction.  Expat's own
    well-formedness errors are ignored here: lxml remains the authority for
    malformed documents and must keep raising its normal XMLSyntaxError.
    """
    if not isinstance(text, (str, bytes, bytearray, memoryview)):
        # Let lxml raise its usual TypeError for unsupported input types.
        return

    if isinstance(text, memoryview):
        text = text.tobytes()
    elif isinstance(text, bytearray):
        text = bytes(text)

    if _expat is None:  # pragma: no cover - Python always ships expat
        if len(text) > MAX_XML_SIZE:
            raise ResourceLimitError("document size", MAX_XML_SIZE, len(text))
        _preflight_text_fallback(text, forbid_dtd, forbid_entities)
        return

    parser = _expat.ParserCreate()
    state = {"depth": 0, "elements": 0, "text": 0}

    def reject_dtd(name, sysid, pubid, has_internal_subset):
        if forbid_dtd:
            raise DTDForbidden(name, sysid, pubid)
        if forbid_entities and (sysid or pubid):
            # An external subset may declare entities we cannot inspect
            # without fetching it.  Reject it while entities are forbidden.
            raise EntitiesForbidden(None, None, None, sysid, pubid, None)

    def handle_entity(name, is_parameter_entity, value, base, sysid, pubid, notation_name):
        if forbid_entities:
            raise EntitiesForbidden(name, value, base, sysid, pubid, notation_name)
        if value is not None and len(value) > MAX_XML_ENTITY_LENGTH:
            raise ResourceLimitError("entity length", MAX_XML_ENTITY_LENGTH, len(value))

    def handle_external_entity(context, base, sysid, pubid):
        if forbid_entities:
            raise EntitiesForbidden(None, None, base, sysid, pubid, None)
        # External entities are never resolved by the preflight parser.  Let
        # lxml apply its own no_network/resolve_entities policy afterwards.
        return 1

    def handle_unparsed_entity(name, base, sysid, pubid, notation_name):
        if forbid_entities:
            raise EntitiesForbidden(name, None, base, sysid, pubid, notation_name)

    def start_element(name, attributes):
        state["depth"] += 1
        state["elements"] += 1
        if state["depth"] > MAX_XML_DEPTH:
            raise ResourceLimitError("depth", MAX_XML_DEPTH, state["depth"])
        if state["elements"] > MAX_XML_ELEMENTS:
            raise ResourceLimitError("element count", MAX_XML_ELEMENTS, state["elements"])
        if len(attributes) > MAX_XML_ATTRIBUTES:
            raise ResourceLimitError("attribute count", MAX_XML_ATTRIBUTES, len(attributes))
        for value in attributes.values():
            if len(value) > MAX_XML_ATTRIBUTE_LENGTH:
                raise ResourceLimitError("attribute length", MAX_XML_ATTRIBUTE_LENGTH, len(value))

    def end_element(name):
        if state["depth"]:
            state["depth"] -= 1

    def character_data(data):
        state["text"] += len(data)
        if state["text"] > MAX_XML_TEXT_LENGTH:
            raise ResourceLimitError("text length", MAX_XML_TEXT_LENGTH, state["text"])

    parser.StartDoctypeDeclHandler = reject_dtd
    parser.EntityDeclHandler = handle_entity
    parser.UnparsedEntityDeclHandler = handle_unparsed_entity
    parser.ExternalEntityRefHandler = handle_external_entity
    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    parser.CharacterDataHandler = character_data

    total = 0
    chunk_size = 64 * 1024
    try:
        # Feed the document in bounded chunks.  Prohibited declarations and
        # budget violations are raised as soon as they are encountered, even
        # when the document as a whole is larger than MAX_XML_SIZE.
        for start in range(0, len(text), chunk_size):
            chunk = text[start : start + chunk_size]
            total += len(chunk)
            if total > MAX_XML_SIZE:
                raise ResourceLimitError("document size", MAX_XML_SIZE, total)
            parser.Parse(chunk, False)
        parser.Parse(text[:0], True)
    except (DTDForbidden, EntitiesForbidden, ResourceLimitError):
        raise
    except (_expat.ExpatError, LookupError, UnicodeError):
        # The document is malformed.  Falling through preserves lxml's
        # XMLSyntaxError behaviour and error messages.
        return


def _preflight_text_fallback(text, forbid_dtd, forbid_entities):  # pragma: no cover
    """Conservative fallback for the unusual case where expat is unavailable."""
    if isinstance(text, str):
        data = text.encode("utf-8", "surrogatepass")
    else:
        data = bytes(text)
    lowered = data.lower()
    if forbid_dtd and b"<!doctype" in lowered:
        raise DTDForbidden(None, None, None)
    if forbid_entities and b"<!entity" in lowered:
        raise EntitiesForbidden(None, None, None, None, None, None)


def _read_source_bounded(source):
    """Read at most MAX_XML_SIZE + 1 units from a file-like object."""
    chunk = source.read(MAX_XML_SIZE + 1)
    return chunk


def _looks_like_xml(source):
    if isinstance(source, str):
        return source.lstrip("\ufeff \t\r\n").startswith("<")
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
        if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
            return True
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        return data.lstrip(b" \t\r\n").startswith(b"<")
    return False


def _preflight_source(source, forbid_dtd, forbid_entities):
    """Preflight a source accepted by :func:`parse` without disturbing it.

    File-like objects are restored to their original position when possible so
    that lxml sees exactly the input the caller supplied.
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        # lxml normally treats bytes passed to parse() as a filename.  If the
        # value is actually XML (a common mistake, and the way the public
        # entry point is often used in tests), keep it safe as well.
        try:
            is_file = os.path.exists(source)
        except (OSError, ValueError, TypeError):
            is_file = False
        if is_file:
            try:
                with open(source, "rb") as stream:
                    data = stream.read(MAX_XML_SIZE + 1)
            except OSError:
                return source
            _preflight_text(data, forbid_dtd, forbid_entities)
            return source
        if _looks_like_xml(source):
            _preflight_text(source, forbid_dtd, forbid_entities)
            return io.BytesIO(bytes(source))
        return source

    if isinstance(source, os.PathLike):
        try:
            with open(source, "rb") as stream:
                data = stream.read(MAX_XML_SIZE + 1)
        except OSError:
            return source
        _preflight_text(data, forbid_dtd, forbid_entities)
        return source

    if isinstance(source, str):
        try:
            is_file = os.path.isfile(source)
        except OSError:
            is_file = False
        if is_file:
            with open(source, "rb") as stream:
                data = stream.read(MAX_XML_SIZE + 1)
            _preflight_text(data, forbid_dtd, forbid_entities)
        elif _looks_like_xml(source):
            _preflight_text(source, forbid_dtd, forbid_entities)
            return io.StringIO(source)
        return source

    if hasattr(source, "read"):
        seekable = False
        position = None
        try:
            seekable = source.seekable()
            if seekable:
                position = source.tell()
        except (AttributeError, IOError, OSError, ValueError):
            seekable = False

        data = _read_source_bounded(source)
        if seekable:
            try:
                source.seek(position)
            except (IOError, OSError, ValueError):
                seekable = False

        if seekable:
            _preflight_text(data, forbid_dtd, forbid_entities)
            return source

        # Non-seekable streams cannot be read twice.  Buffer the (bounded)
        # content and hand the buffer to lxml instead.
        if isinstance(data, str):
            return io.StringIO(data)
        return io.BytesIO(data)

    return source


def check_docinfo(elementtree, forbid_dtd=False, forbid_entities=True):
    """Check docinfo of an element tree for DTD and entity declarations
    The check for entity declarations needs lxml 3 or newer. lxml 2.x does
    not support dtd.iterentities().
    """
    docinfo = elementtree.docinfo
    if docinfo.doctype:
        if forbid_dtd:
            raise DTDForbidden(docinfo.doctype, docinfo.system_url, docinfo.public_id)
        if forbid_entities and not LXML3:
            # lxml < 3 has no iterentities()
            raise NotSupportedError("Unable to check for entity declarations " "in lxml 2.x")

    if forbid_entities:
        for dtd in docinfo.internalDTD, docinfo.externalDTD:
            if dtd is None:
                continue
            for entity in dtd.iterentities():
                raise EntitiesForbidden(entity.name, entity.content, None, None, None, None)


def parse(source, parser=None, base_url=None, forbid_dtd=True, forbid_entities=True):
    # Apply the prohibition and resource budget before the thread-local parser
    # is used, let alone before lxml builds a DOM.  In particular, a rejected
    # document must leave the default parser untouched for the next caller.
    source = _preflight_source(source, forbid_dtd, forbid_entities)
    parser = _parser_for_call(parser)
    elementtree = _etree.parse(source, parser, base_url=base_url)
    check_docinfo(elementtree, forbid_dtd, forbid_entities)
    return elementtree


def fromstring(text, parser=None, base_url=None, forbid_dtd=True, forbid_entities=True):
    # See parse(): this check happens before the parser is selected or fed.
    _preflight_text(text, forbid_dtd, forbid_entities)
    parser = _parser_for_call(parser)
    rootelement = _etree.fromstring(text, parser, base_url=base_url)
    elementtree = rootelement.getroottree()
    check_docinfo(elementtree, forbid_dtd, forbid_entities)
    return rootelement


XML = fromstring


def iterparse(*args, **kwargs):
    raise NotSupportedError("iterparse not available")

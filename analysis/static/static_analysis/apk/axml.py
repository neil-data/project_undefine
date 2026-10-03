"""Minimal, defensive reader for Android binary XML manifests."""

import struct
import xml.etree.ElementTree as element_tree
from dataclasses import dataclass

_RES_XML_TYPE = 0x0003
_RES_STRING_POOL_TYPE = 0x0001
_RES_XML_START_ELEMENT_TYPE = 0x0102
_RES_XML_END_ELEMENT_TYPE = 0x0103
_UTF8_FLAG = 0x00000100


class ManifestParseError(ValueError):
    """Raised when a manifest cannot be read as plain or Android binary XML."""


@dataclass(frozen=True, slots=True)
class XmlNode:
    name: str
    attributes: dict[str, str]
    children: tuple["XmlNode", ...] = ()


def parse_manifest(payload: bytes) -> XmlNode:
    """Parse plain XML or compiled Android XML into a small namespace-aware tree."""
    if payload.lstrip().startswith(b"<"):
        return _parse_plain_xml(payload)
    return _parse_binary_xml(payload)


def _parse_plain_xml(payload: bytes) -> XmlNode:
    try:
        root = element_tree.fromstring(payload)
    except element_tree.ParseError as error:
        raise ManifestParseError("Invalid plain XML manifest") from error

    def convert(element: element_tree.Element) -> XmlNode:
        return XmlNode(
            name=_local_name(element.tag),
            attributes={_attribute_name(key): value for key, value in element.attrib.items()},
            children=tuple(convert(child) for child in element),
        )

    return convert(root)


def _parse_binary_xml(payload: bytes) -> XmlNode:
    if len(payload) < 8:
        raise ManifestParseError("Truncated binary XML manifest")
    chunk_type, header_size, total_size = struct.unpack_from("<HHI", payload, 0)
    if chunk_type != _RES_XML_TYPE or header_size < 8 or total_size > len(payload):
        raise ManifestParseError("Invalid binary XML header")
    strings: list[str] = []
    stack: list[tuple[str, dict[str, str], list[XmlNode]]] = []
    root: XmlNode | None = None
    offset = header_size
    while offset + 8 <= total_size:
        chunk_type, chunk_header_size, chunk_size = struct.unpack_from("<HHI", payload, offset)
        if chunk_header_size < 8 or chunk_size < chunk_header_size or offset + chunk_size > total_size:
            raise ManifestParseError("Invalid binary XML chunk")
        if chunk_type == _RES_STRING_POOL_TYPE:
            strings = _read_string_pool(payload, offset, chunk_header_size, chunk_size)
        elif chunk_type == _RES_XML_START_ELEMENT_TYPE:
            node = _read_start_element(payload, offset, chunk_header_size, chunk_size, strings)
            stack.append((node.name, node.attributes, []))
        elif chunk_type == _RES_XML_END_ELEMENT_TYPE:
            if not stack:
                raise ManifestParseError("Unbalanced binary XML element")
            name, attributes, children = stack.pop()
            node = XmlNode(name=name, attributes=attributes, children=tuple(children))
            if stack:
                stack[-1][2].append(node)
            else:
                root = node
        offset += chunk_size
    if root is None or stack:
        raise ManifestParseError("Incomplete binary XML manifest")
    return root


def _read_string_pool(payload: bytes, offset: int, header_size: int, chunk_size: int) -> list[str]:
    if header_size < 28 or offset + 28 > len(payload):
        raise ManifestParseError("Invalid string pool")
    count, _, flags, strings_start, _ = struct.unpack_from("<IIIII", payload, offset + 8)
    offsets_start = offset + header_size
    if offsets_start + count * 4 > offset + chunk_size:
        raise ManifestParseError("Truncated string offsets")
    result: list[str] = []
    for index in range(count):
        relative_offset = struct.unpack_from("<I", payload, offsets_start + index * 4)[0]
        start = offset + strings_start + relative_offset
        if start >= offset + chunk_size:
            raise ManifestParseError("Invalid string offset")
        result.append(_decode_pool_string(payload, start, bool(flags & _UTF8_FLAG)))
    return result


def _decode_pool_string(payload: bytes, start: int, is_utf8: bool) -> str:
    try:
        if is_utf8:
            _, position = _read_length8(payload, start)
            byte_length, position = _read_length8(payload, position)
            return payload[position : position + byte_length].decode("utf-8")
        length, position = _read_length16(payload, start)
        return payload[position : position + length * 2].decode("utf-16le")
    except (IndexError, UnicodeDecodeError) as error:
        raise ManifestParseError("Invalid string pool value") from error


def _read_length8(payload: bytes, position: int) -> tuple[int, int]:
    first = payload[position]
    if first & 0x80:
        return ((first & 0x7F) << 8) | payload[position + 1], position + 2
    return first, position + 1


def _read_length16(payload: bytes, position: int) -> tuple[int, int]:
    first = struct.unpack_from("<H", payload, position)[0]
    if first & 0x8000:
        second = struct.unpack_from("<H", payload, position + 2)[0]
        return ((first & 0x7FFF) << 16) | second, position + 4
    return first, position + 2


def _read_start_element(payload: bytes, offset: int, header_size: int, chunk_size: int, strings: list[str]) -> XmlNode:
    if header_size < 36 or not strings:
        raise ManifestParseError("Invalid start element")
    name_index = struct.unpack_from("<I", payload, offset + 20)[0]
    attribute_start, attribute_size, attribute_count = struct.unpack_from("<HHH", payload, offset + 24)
    attributes: dict[str, str] = {}
    for index in range(attribute_count):
        attribute_offset = offset + attribute_start + index * attribute_size
        if attribute_size < 20 or attribute_offset + 20 > offset + chunk_size:
            raise ManifestParseError("Invalid element attribute")
        _, attribute_name_index, raw_value_index = struct.unpack_from("<III", payload, attribute_offset)
        data_type = payload[attribute_offset + 15]
        data = struct.unpack_from("<I", payload, attribute_offset + 16)[0]
        name = _string_at(strings, attribute_name_index)
        value = _string_at(strings, raw_value_index) if raw_value_index != 0xFFFFFFFF else _typed_value(strings, data_type, data)
        attributes[name] = value
    return XmlNode(name=_string_at(strings, name_index), attributes=attributes)


def _typed_value(strings: list[str], data_type: int, data: int) -> str:
    if data_type == 0x03:
        return _string_at(strings, data)
    if data_type == 0x12:
        return "true" if data else "false"
    return str(data)


def _string_at(strings: list[str], index: int) -> str:
    if index >= len(strings):
        raise ManifestParseError("Invalid string index")
    return strings[index]


def _local_name(name: str) -> str:
    return name.rsplit("}", 1)[-1]


def _attribute_name(name: str) -> str:
    return f"android:{_local_name(name)}" if name.startswith("{http://schemas.android.com/apk/res/android}") else _local_name(name)

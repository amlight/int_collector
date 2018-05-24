# -*- coding: utf-8 -*-
"""Define the line_protocol handler."""
from __future__ import unicode_literals

from datetime import datetime

from pytz import UTC
from six import iteritems, PY2

from influxdb.line_protocol import _convert_timestamp, _escape_tag, _escape_value, _get_unicode

EPOCH = UTC.localize(datetime.utcfromtimestamp(0))

def _escape_tag_value(value):
    ret = _escape_tag(value)
    if ret.endswith('\\'):
        ret += ' '
    return ret

def make_line(measurement, key_val_list, point=None, time=None, tags=None, static_tags=None, precision=None):
    """
    Make one line string for a point data, used directly for line protocol. 

    Ref: make_lines function from influxdb.line_protocol
    """

    elements = []

    # add measurement name
    _measurement = _escape_tag(_get_unicode(measurement))
    key_values = [_measurement]

    # tags should be sorted client-side to take load off server
    if tags:
        for tag_key, tag_value in sorted(iteritems(tags)):
            key = _escape_tag(tag_key)
            value = _escape_tag_value(tag_value)

            if key != '' and value != '':
                key_values.append(key + "=" + value)

    elements.append(','.join(key_values))

    # add fields
    field_values = []
    for (field_key, field_value) in sorted(key_val_list):
        key = _escape_tag(field_key)
        value = _escape_value(field_value)

        if key != '' and value != '':
            field_values.append(key + "=" + value)

    elements.append(','.join(field_values))

    # add timestamp
    if time:
        timestamp = _get_unicode(str(int(
            _convert_timestamp(time, precision))))
        elements.append(timestamp)

    line = ' '.join(elements)
    return line

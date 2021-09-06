/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2020 The noVNC Authors
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 */

exports.toUnsigned32bit = (toConvert) => {
    return toConvert >>> 0;
}

exports.toSigned32bit = (toConvert) => {
    return toConvert | 0;
}

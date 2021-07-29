/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2019 The noVNC Authors
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 *
 */

class CopyRectDecoder {
    decodeRect(x, y, width, height, sock, client, depth) {
        if (sock.rQwait("COPYRECT", 4)) {
            return false;
        }

        let deltaX = sock.rQshift16();
        let deltaY = sock.rQshift16();

        if ((width === 0) || (height === 0)) {
            return true;
        }

        client.emit("fbu_copy_image", deltaX, deltaY, x, y, width, height);

        return true;
    }
}

module.exports = {
    CopyRectDecoder
}
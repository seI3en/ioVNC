class RFB {

    constructor(target) {
        this.target = target;
        const _sQbufferSize = 256;
        this._sQ = new Uint8Array(_sQbufferSize);
    }

    _handleMessage(msg) {
        if (msg["event"] == "key") {
            this.keyEvent(msg["keysym"], msg["down"]);
        } else if (msg["event"] == "extkey") {
            this.QEMUExtendedKeyEvent(msg["keysym"], msg["down"], msg["scancode"]);
        } else {
            this.target.write(msg);
        }

// formerly Class Methods, now instance methods
    keyEvent(keysym, down) {
        const buff = this._sQ.slice(0,8);
        const offset = 0;

        buff[offset] = 4;  // msg-type
        buff[offset + 1] = down;

        buff[offset + 2] = 0;
        buff[offset + 3] = 0;

        buff[offset + 4] = (keysym >> 24);
        buff[offset + 5] = (keysym >> 16);
        buff[offset + 6] = (keysym >> 8);
        buff[offset + 7] = keysym;

        this.target.write(buff);
    }

    QEMUExtendedKeyEvent(keysym, down, keycode) {
        function getRFBkeycode(xtScanCode) {
            const upperByte = (keycode >> 8);
            const lowerByte = (keycode & 0x00ff);
            if (upperByte === 0xe0 && lowerByte < 0x7f) {
                return lowerByte | 0x80;
            }
            return xtScanCode;
        }

        const buff = this._sQ.slice(0,12);
        const offset = 0;

        buff[offset] = 255; // msg-type
        buff[offset + 1] = 0; // sub msg-type

        buff[offset + 2] = (down >> 8);
        buff[offset + 3] = down;

        buff[offset + 4] = (keysym >> 24);
        buff[offset + 5] = (keysym >> 16);
        buff[offset + 6] = (keysym >> 8);
        buff[offset + 7] = keysym;

        const RFBkeycode = getRFBkeycode(keycode);

        buff[offset + 8] = (RFBkeycode >> 24);
        buff[offset + 9] = (RFBkeycode >> 16);
        buff[offset + 10] = (RFBkeycode >> 8);
        buff[offset + 11] = RFBkeycode;

        this.target.write(buff);
    }

    pointerEvent(x, y, mask) {
        const buff = this._sQ.slice(0,6);
        const offset = 0;

        buff[offset] = 5; // msg-type

        buff[offset + 1] = mask;

        buff[offset + 2] = x >> 8;
        buff[offset + 3] = x;

        buff[offset + 4] = y >> 8;
        buff[offset + 5] = y;

        this.target.write(buff);
    }

    // Used to build Notify and Request data.
    _buildExtendedClipboardFlags(actions, formats) {
        let data = new Uint8Array(4);
        let formatFlag = 0x00000000;
        let actionFlag = 0x00000000;

        for (let i = 0; i < actions.length; i++) {
            actionFlag |= actions[i];
        }

        for (let i = 0; i < formats.length; i++) {
            formatFlag |= formats[i];
        }

        data[0] = actionFlag >> 24; // Actions
        data[1] = 0x00;             // Reserved
        data[2] = 0x00;             // Reserved
        data[3] = formatFlag;       // Formats

        return data;
    }

    extendedClipboardProvide(formats, inData) {
        // Deflate incomming data and their sizes
        let deflator = new Deflator();
        let dataToDeflate = [];

        for (let i = 0; i < formats.length; i++) {
            // We only support the format Text at this time
            if (formats[i] != extendedClipboardFormatText) {
                throw new Error("Unsupported extended clipboard format for Provide message.");
            }

            // Change lone \r or \n into \r\n as defined in rfbproto
            inData[i] = inData[i].replace(/\r\n|\r|\n/gm, "\r\n");

            // Check if it already has \0
            let text = encodeUTF8(inData[i] + "\0");

            dataToDeflate.push( (text.length >> 24) & 0xFF,
                                (text.length >> 16) & 0xFF,
                                (text.length >>  8) & 0xFF,
                                (text.length & 0xFF));

            for (let j = 0; j < text.length; j++) {
                dataToDeflate.push(text.charCodeAt(j));
            }
        }

        let deflatedData = deflator.deflate(new Uint8Array(dataToDeflate));

        // Build data  to send
        let data = new Uint8Array(4 + deflatedData.length);
        data.set(this._buildExtendedClipboardFlags([extendedClipboardActionProvide],
                                                           formats));
        data.set(deflatedData, 4);

        this.clientCutText(data, true);
    }

    extendedClipboardNotify(formats) {
        let flags = this._buildExtendedClipboardFlags([extendedClipboardActionNotify],
                                                              formats);
        this.clientCutText(flags, true);
    }

    extendedClipboardRequest(formats) {
        let flags = this._buildExtendedClipboardFlags([extendedClipboardActionRequest],
                                                              formats);
        this.clientCutText(flags, true);
    }

    extendedClipboardCaps(actions, formats) {
        let formatKeys = Object.keys(formats);
        let data  = new Uint8Array(4 + (4 * formatKeys.length));

        formatKeys.map(x => parseInt(x));
        formatKeys.sort((a, b) =>  a - b);

        data.set(this._buildExtendedClipboardFlags(actions, []));

        let loopOffset = 4;
        for (let i = 0; i < formatKeys.length; i++) {
            data[loopOffset]     = formats[formatKeys[i]] >> 24;
            data[loopOffset + 1] = formats[formatKeys[i]] >> 16;
            data[loopOffset + 2] = formats[formatKeys[i]] >> 8;
            data[loopOffset + 3] = formats[formatKeys[i]] >> 0;

            loopOffset += 4;
            data[3] |= (1 << formatKeys[i]); // Update our format flags
        }

        this.clientCutText(data, true);
    }

    clientCutText(data, extended = false) {
        const buff = this._sQ;
        var offset = 0;

        buff[offset] = 6; // msg-type

        buff[offset + 1] = 0; // padding
        buff[offset + 2] = 0; // padding
        buff[offset + 3] = 0; // padding

        let length;
        if (extended) {
            length = toUnsigned32bit(-data.length);
        } else {
            length = data.length;
        }

        buff[offset + 4] = length >> 24;
        buff[offset + 5] = length >> 16;
        buff[offset + 6] = length >> 8;
        buff[offset + 7] = length;

        offset = 8;

        // We have to keep track of from where in the data we begin creating the
        // buffer for the flush in the next iteration.
        let dataOffset = 0;

        let remaining = data.length;
        while (remaining > 0) {

            let flushSize = Math.min(remaining, (buff.length - offset));
            for (let i = 0; i < flushSize; i++) {
                buff[offset + i] = data[dataOffset + i];
            }

            this.target.write(buff.slice(0,flushSize + offset));

            remaining -= flushSize;
            dataOffset += flushSize;
            offset = 0;
        }

    }

    setDesktopSize(width, height, id, flags) {
        const buff = this._sQ.slice(0,24);
        const offset = 0;

        buff[offset] = 251;              // msg-type
        buff[offset + 1] = 0;            // padding
        buff[offset + 2] = width >> 8;   // width
        buff[offset + 3] = width;
        buff[offset + 4] = height >> 8;  // height
        buff[offset + 5] = height;

        buff[offset + 6] = 1;            // number-of-screens
        buff[offset + 7] = 0;            // padding

        // screen array
        buff[offset + 8] = id >> 24;     // id
        buff[offset + 9] = id >> 16;
        buff[offset + 10] = id >> 8;
        buff[offset + 11] = id;
        buff[offset + 12] = 0;           // x-position
        buff[offset + 13] = 0;
        buff[offset + 14] = 0;           // y-position
        buff[offset + 15] = 0;
        buff[offset + 16] = width >> 8;  // width
        buff[offset + 17] = width;
        buff[offset + 18] = height >> 8; // height
        buff[offset + 19] = height;
        buff[offset + 20] = flags >> 24; // flags
        buff[offset + 21] = flags >> 16;
        buff[offset + 22] = flags >> 8;
        buff[offset + 23] = flags;

        this.target.write(buff);
    }

    clientFence(flags, payload) {
        const buff = this._sQ;
        const offset = 0;

        buff[offset] = 248; // msg-type

        buff[offset + 1] = 0; // padding
        buff[offset + 2] = 0; // padding
        buff[offset + 3] = 0; // padding

        buff[offset + 4] = flags >> 24; // flags
        buff[offset + 5] = flags >> 16;
        buff[offset + 6] = flags >> 8;
        buff[offset + 7] = flags;

        const n = payload.length;

        buff[offset + 8] = n; // length

        for (let i = 0; i < n; i++) {
            buff[offset + 9 + i] = payload.charCodeAt(i);
        }

        this.target.write(buff.slice(0,9 + n));
    }

    enableContinuousUpdates(enable, x, y, width, height) {
        const buff = this._sQ.slice(0,10);
        const offset = 0;

        buff[offset] = 150;             // msg-type
        buff[offset + 1] = enable;      // enable-flag

        buff[offset + 2] = x >> 8;      // x
        buff[offset + 3] = x;
        buff[offset + 4] = y >> 8;      // y
        buff[offset + 5] = y;
        buff[offset + 6] = width >> 8;  // width
        buff[offset + 7] = width;
        buff[offset + 8] = height >> 8; // height
        buff[offset + 9] = height;

        this.target.write(buff);
    }

    pixelFormat(depth, trueColor) {
        const buff = this._sQ.slice(0,20);
        const offset = 0;

        let bpp;

        if (depth > 16) {
            bpp = 32;
        } else if (depth > 8) {
            bpp = 16;
        } else {
            bpp = 8;
        }

        const bits = Math.floor(depth/3);

        buff[offset] = 0;  // msg-type

        buff[offset + 1] = 0; // padding
        buff[offset + 2] = 0; // padding
        buff[offset + 3] = 0; // padding

        buff[offset + 4] = bpp;                 // bits-per-pixel
        buff[offset + 5] = depth;               // depth
        buff[offset + 6] = 0;                   // little-endian
        buff[offset + 7] = trueColor ? 1 : 0;  // true-color

        buff[offset + 8] = 0;    // red-max
        buff[offset + 9] = (1 << bits) - 1;  // red-max

        buff[offset + 10] = 0;   // green-max
        buff[offset + 11] = (1 << bits) - 1; // green-max

        buff[offset + 12] = 0;   // blue-max
        buff[offset + 13] = (1 << bits) - 1; // blue-max

        buff[offset + 14] = bits * 0; // red-shift
        buff[offset + 15] = bits * 1; // green-shift
        buff[offset + 16] = bits * 2; // blue-shift

        buff[offset + 17] = 0;   // padding
        buff[offset + 18] = 0;   // padding
        buff[offset + 19] = 0;   // padding

        this.target.write(buff);
    }

    clientEncodings(encodings) {
        const buff = this._sQ;
        const offset = 0;

        buff[offset] = 2; // msg-type
        buff[offset + 1] = 0; // padding

        buff[offset + 2] = encodings.length >> 8;
        buff[offset + 3] = encodings.length;

        let j = offset + 4;
        for (let i = 0; i < encodings.length; i++) {
            const enc = encodings[i];
            buff[j] = enc >> 24;
            buff[j + 1] = enc >> 16;
            buff[j + 2] = enc >> 8;
            buff[j + 3] = enc;

            j += 4;
        }

        this.target.write(buff.slice(0,j - offset));
    }

    fbUpdateRequest(incremental, x, y, w, h) {
        const buff = this._sQ.slice(0,10);
        const offset = 0;

        if (typeof(x) === "undefined") { x = 0; }
        if (typeof(y) === "undefined") { y = 0; }

        buff[offset] = 3;  // msg-type
        buff[offset + 1] = incremental ? 1 : 0;

        buff[offset + 2] = (x >> 8) & 0xFF;
        buff[offset + 3] = x & 0xFF;

        buff[offset + 4] = (y >> 8) & 0xFF;
        buff[offset + 5] = y & 0xFF;

        buff[offset + 6] = (w >> 8) & 0xFF;
        buff[offset + 7] = w & 0xFF;

        buff[offset + 8] = (h >> 8) & 0xFF;
        buff[offset + 9] = h & 0xFF;

        this.target.write(buff);
    }

    xvpOp(ver, op) {
        const buff = this._sQ.slice(0,4);
        const offset = 0;

        buff[offset] = 250; // msg-type
        buff[offset + 1] = 0; // padding

        buff[offset + 2] = ver;
        buff[offset + 3] = op;

        this.target.write(buff);
    }

} // end of 'RFB' class

module.exports = {
    RFB
}

var { toUnsigned32bit, toSigned32bit } = require('./util/int_s.js');
var Log = require('./util/logging_s.js');
var DES = require('./des_s.js').DES;
var encodings = require('./encodings_s.js').encodings;
var RawDecoder = require('./decoders/raw_s.js').RawDecoder;
var CopyRectDecoder = require('./decoders/copyrect_s.js').CopyRectDecoder;
var TightDecoder = require('./decoders/tight_s.js').TightDecoder;
var Inflator = require("./inflator_s.js").Inflate;

class RFB {

    constructor(client,target,_sock) {
		
        this.client = client;
        this.target = target;
		this._sock = _sock;

        this._rfbConnectionState = 'connecting';
        this._rfbInitState = '';
		this._rfbAuthScheme = -1;
        // Server capabilities
        this._rfbVersion = 0;
        this._rfbMaxVersion = 3.8;
        this._rfbTightVNC = false;
        this._rfbVeNCryptState = 0;
        this._rfbXvpVer = 0;

        const _sQbufferSize = 256;
        this._sQ = new Uint8Array(_sQbufferSize);
        const _rQbufferSize = 1024 * 1024 * 4; // Receive queue buffer size (4 MiB)
        //this._rQ = new Uint8Array(_rQbufferSize);
		this._rQ = null;

        this._disconnTimer = null;      // disconnection timer
		
        this._securityContext = '';
        this._securityStatus = 0;
        this._rfbCredentials = { password : '' }
		this._shared = false;
		
		this._viewOnly = false;
        this._clipViewport = false;
        this._scaleViewport = false;
		this._fbDepth = 0;
		this._fbWidth = 0;
        this._fbHeight = 0;
		this._fbName = "";
		this._qualityLevel = 6;
        this._compressionLevel = 2;
		
		this._FBU = {
            rects: 0,
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            encoding: null,
        };
		
		this._enabledContinuousUpdates = false;
		this._cursorImage = RFB.cursors.none;
		this._showDotCursor = false;
		
		this._supportsSetDesktopSize = false;
		this._qemuExtKeyEventSupported = false;
		
		this._decoders = {};
        // populate decoder array with objects
		this._decoders[encodings.encodingRaw] = new RawDecoder();
        this._decoders[encodings.encodingCopyRect] = new CopyRectDecoder();
		this._decoders[encodings.encodingTight] = new TightDecoder();
		
		this.unfinished_rect = false;
		
		this._sock.on('message', this._handleData.bind(this));
		//client.on('message', this._handleMessage.bind(this));
		
    }

    _handleMessage(msg) {
        if (msg["event"] == "key") {
			RFB.messages.keyEvent(this._sock, msg["keysym"], msg["down"]);
        } else if (msg["event"] == "extkey") {
			RFB.messages.QEMUExtendedKeyEvent(this._sock, msg["keysym"], msg["down"], msg["keycode"]);
        } else if (msg["event"] == "pointer") {
			RFB.messages.pointerEvent(this._sock, msg["x"], msg["y"], msg["mask"]);
        } else if (msg["event"] == "clientCutText") {
			RFB.messages.clientCutText(this._sock, msg["data"], msg["extended"]);
        } else if (msg["event"] == "setDesktopSize") {
			RFB.messages.setDesktopSize(this._sock, msg["width"], msg["height"], msg["id"], msg["flags"]);
        } else if (msg["event"] == "clientFence") {
			RFB.messages.clientFence(this._sock, msg["flags"], msg["payload"]);
        } else if (msg["event"] == "enableContinuousUpdates") {
			RFB.messages.enableContinuousUpdates(this._sock, msg["enable"], msg["x"], msg["y"], msg["width"], msg["height"]);
        } else if (msg["event"] == "pixelFormat") {
			RFB.messages.pixelFormat(this._sock, msg["depth"], msg["trueColor"]);
        } else if (msg["event"] == "clientEncodings") {
			RFB.messages.clientEncodings(this._sock, msg["encodings"]);
        } else if (msg["event"] == "fbUpdateRequest") {
			RFB.messages.fbUpdateRequest(this._sock, msg["incremental"], msg["x"], msg["y"], msg["w"], msg["h"]);
        } else if (msg["event"] == "xvpOp") {
			RFB.messages.xvpOp(this._sock, msg["ver"], msg["op"]);
        } else {
            this._sock.send(msg);
        }
    }

    _socketOpen() {
        if ((this._rfbConnectionState === 'connecting') &&
            (this._rfbInitState === '')) {
            this._rfbInitState = 'ProtocolVersion';
            Log.Debug("Starting VNC handshake");
        } else {
            this._fail("Unexpected server connection while " +
                       this._rfbConnectionState);
        }
    }

    _socketClose(e) {
        Log.Debug("WebSocket on-close event");
        /*let msg = "";
        if (e.code) {
            msg = "(code: " + e.code;
            if (e.reason) {
                msg += ", reason: " + e.reason;
            }
            msg += ")";
        }*/

		this._rfbConnectionState = 'disconnected';
		
        /*switch (this._rfbConnectionState) {
            case 'connecting':
                this._fail("Connection closed " + msg);
                break;
            case 'connected':
                // Handle disconnects that were initiated server-side
                this._updateConnectionState('disconnecting');
                this._updateConnectionState('disconnected');
                break;
            case 'disconnecting':
                // Normal disconnection path
                this._updateConnectionState('disconnected');
                break;
            case 'disconnected':
                this._fail("Unexpected server disconnect " +
                           "when already disconnected " + msg);
                break;
            default:
                this._fail("Unexpected server disconnect before connecting " +
                           msg);
                break;
        }*/
        //this._sock.off('close');
		this._sock.close();
        // Delete reference to raw channel to allow cleanup.
        // this._rawChannel = null;
    }

    _handleData() {
        if (this._sock.rQlen === 0) {
            Log.Warn("handleMessage called on an empty receive queue");
            return;
        }

        switch (this._rfbConnectionState) {
            case 'disconnected':
                Log.Error("Got data while disconnected");
                break;
            case 'connected':
                while (true) {
                    if (this._flushing) {
                        break;
                    }
                    if (!this._normalMsg()) {
                        break;
                    }
                    if (this._sock.rQlen === 0) {
                        break;
                    }
                }
                break;
            default:
                this._initMsg();
                break;
        }

    }


    // Message Handlers

    _negotiateProtocolVersion() {
        if (this._sock.rQwait("version", 12)) {
            return false;
        }

        const sversion = this._sock.rQshiftStr(12).substr(4, 7);
        Log.Info("Server ProtocolVersion: " + sversion);
        let isRepeater = 0;
        switch (sversion) {
            case "000.000":  // UltraVNC repeater
                isRepeater = 1;
                break;
            case "003.003":
            case "003.006":  // UltraVNC
            case "003.889":  // Apple Remote Desktop
                this._rfbVersion = 3.3;
                break;
            case "003.007":
                this._rfbVersion = 3.7;
                break;
            case "003.008":
            case "004.000":  // Intel AMT KVM
            case "004.001":  // RealVNC 4.6
            case "005.000":  // RealVNC 5.3
                this._rfbVersion = 3.8;
                break;
            default:
                return this._fail("Invalid server version " + sversion);
        }

        if (isRepeater) {
            let repeaterID = "ID:" + this._repeaterID;
            while (repeaterID.length < 250) {
                repeaterID += "\0";
            }
            this._sock.sendString(repeaterID);
            return true;
        }

        if (this._rfbVersion > this._rfbMaxVersion) {
            this._rfbVersion = this._rfbMaxVersion;
        }

        const cversion = "00" + parseInt(this._rfbVersion, 10) +
                       ".00" + ((this._rfbVersion * 10) % 10);
        this._sock.sendString("RFB " + cversion + "\n");
        Log.Debug('Sent ProtocolVersion: ' + cversion);

        this._rfbInitState = 'Security';
    }

    _negotiateSecurity() {
        if (this._rfbVersion >= 3.7) {
            // Server sends supported list, client decides
            const numTypes = this._sock.rQshift8();
            if (this._sock.rQwait("security type", numTypes, 1)) { return false; }

            if (numTypes === 0) {
                this._rfbInitState = "SecurityReason";
                this._securityContext = "no security types";
                this._securityStatus = 1;
                return this._initMsg();
            }

            const types = this._sock.rQshiftBytes(numTypes);
            Log.Debug("Server security types: " + types);

            // Look for each auth in preferred order
            if (types.includes(1)) {
                this._rfbAuthScheme = 1; // None
            } else if (types.includes(22)) {
                this._rfbAuthScheme = 22; // XVP
            } else if (types.includes(16)) {
                this._rfbAuthScheme = 16; // Tight
            } else if (types.includes(2)) {
                this._rfbAuthScheme = 2; // VNC Auth
            } else if (types.includes(19)) {
                this._rfbAuthScheme = 19; // VeNCrypt Auth
            } else {
                return this._fail("Unsupported security types (types: " + types + ")");
            }

            this._sock.send([this._rfbAuthScheme]);
        } else {
            // Server decides
            if (this._sock.rQwait("security scheme", 4)) { return false; }
            this._rfbAuthScheme = this._sock.rQshift32();

            if (this._rfbAuthScheme == 0) {
                this._rfbInitState = "SecurityReason";
                this._securityContext = "authentication scheme";
                this._securityStatus = 1;
                return this._initMsg();
            }
        }

        this._rfbInitState = 'Authentication';
        Log.Debug('Authenticating using scheme: ' + this._rfbAuthScheme);

        return this._initMsg(); // jump to authentication
    }

    _handleSecurityReason() {
        if (this._sock.rQwait("reason length", 4)) {
            return false;
        }
        const strlen = this._sock.rQshift32();
        let reason = "";

        if (strlen > 0) {
            if (this._sock.rQwait("reason", strlen, 4)) { return false; }
            reason = this._sock.rQshiftStr(strlen);
        }

        if (reason !== "") {
            this.dispatchEvent(new CustomEvent(
                "securityfailure",
                { detail: { status: this._securityStatus,
                            reason: reason } }));

            return this._fail("Security negotiation failed on " +
                              this._securityContext +
                              " (reason: " + reason + ")");
        } else {
            this.dispatchEvent(new CustomEvent(
                "securityfailure",
                { detail: { status: this._securityStatus } }));

            return this._fail("Security negotiation failed on " +
                              this._securityContext);
        }
    }

    // authentication
    _negotiateXvpAuth() {
        if (this._rfbCredentials.username === undefined ||
            this._rfbCredentials.password === undefined ||
            this._rfbCredentials.target === undefined) {
            this.dispatchEvent(new CustomEvent(
                "credentialsrequired",
                { detail: { types: ["username", "password", "target"] } }));
            return false;
        }

        const xvpAuthStr = String.fromCharCode(this._rfbCredentials.username.length) +
                           String.fromCharCode(this._rfbCredentials.target.length) +
                           this._rfbCredentials.username +
                           this._rfbCredentials.target;
        this._sock.sendString(xvpAuthStr);
        this._rfbAuthScheme = 2;
        return this._negotiateAuthentication();
    }

    // VeNCrypt authentication, currently only supports version 0.2 and only Plain subtype
    _negotiateVeNCryptAuth() {

        // waiting for VeNCrypt version
        if (this._rfbVeNCryptState == 0) {
            if (this._sock.rQwait("vencrypt version", 2)) { return false; }

            const major = this._sock.rQshift8();
            const minor = this._sock.rQshift8();

            if (!(major == 0 && minor == 2)) {
                return this._fail("Unsupported VeNCrypt version " + major + "." + minor);
            }

            this._sock.send([0, 2]);
            this._rfbVeNCryptState = 1;
        }

        // waiting for ACK
        if (this._rfbVeNCryptState == 1) {
            if (this._sock.rQwait("vencrypt ack", 1)) { return false; }

            const res = this._sock.rQshift8();

            if (res != 0) {
                return this._fail("VeNCrypt failure " + res);
            }

            this._rfbVeNCryptState = 2;
        }
        // must fall through here (i.e. no "else if"), beacause we may have already received
        // the subtypes length and won't be called again

        if (this._rfbVeNCryptState == 2) { // waiting for subtypes length
            if (this._sock.rQwait("vencrypt subtypes length", 1)) { return false; }

            const subtypesLength = this._sock.rQshift8();
            if (subtypesLength < 1) {
                return this._fail("VeNCrypt subtypes empty");
            }

            this._rfbVeNCryptSubtypesLength = subtypesLength;
            this._rfbVeNCryptState = 3;
        }

        // waiting for subtypes list
        if (this._rfbVeNCryptState == 3) {
            if (this._sock.rQwait("vencrypt subtypes", 4 * this._rfbVeNCryptSubtypesLength)) { return false; }

            const subtypes = [];
            for (let i = 0; i < this._rfbVeNCryptSubtypesLength; i++) {
                subtypes.push(this._sock.rQshift32());
            }

            // 256 = Plain subtype
            if (subtypes.indexOf(256) != -1) {
                // 0x100 = 256
                this._sock.send([0, 0, 1, 0]);
                this._rfbVeNCryptState = 4;
            } else {
                return this._fail("VeNCrypt Plain subtype not offered by server");
            }
        }

        // negotiated Plain subtype, server waits for password
        if (this._rfbVeNCryptState == 4) {
            if (this._rfbCredentials.username === undefined ||
                this._rfbCredentials.password === undefined) {
                this.dispatchEvent(new CustomEvent(
                    "credentialsrequired",
                    { detail: { types: ["username", "password"] } }));
                return false;
            }

            const user = encodeUTF8(this._rfbCredentials.username);
            const pass = encodeUTF8(this._rfbCredentials.password);

            this._sock.send([
                (user.length >> 24) & 0xFF,
                (user.length >> 16) & 0xFF,
                (user.length >> 8) & 0xFF,
                user.length & 0xFF
            ]);
            this._sock.send([
                (pass.length >> 24) & 0xFF,
                (pass.length >> 16) & 0xFF,
                (pass.length >> 8) & 0xFF,
                pass.length & 0xFF
            ]);
            this._sock.sendString(user);
            this._sock.sendString(pass);

            this._rfbInitState = "SecurityResult";
            return true;
        }
    }

    _negotiateStdVNCAuth() {
        if (this._sock.rQwait("auth challenge", 16)) { return false; }

        if (this._rfbCredentials.password === undefined) {
            this.dispatchEvent(new CustomEvent(
                "credentialsrequired",
                { detail: { types: ["password"] } }));
            return false;
        }

        // TODO(directxman12): make genDES not require an Array
        const challenge = Array.prototype.slice.call(this._sock.rQshiftBytes(16));
        const response = RFB.genDES(this._rfbCredentials.password, challenge);
        this._sock.send(response);
        this._rfbInitState = "SecurityResult";
        return true;
    }

    _negotiateTightUnixAuth() {
        if (this._rfbCredentials.username === undefined ||
            this._rfbCredentials.password === undefined) {
            this.dispatchEvent(new CustomEvent(
                "credentialsrequired",
                { detail: { types: ["username", "password"] } }));
            return false;
        }

        this._sock.send([0, 0, 0, this._rfbCredentials.username.length]);
        this._sock.send([0, 0, 0, this._rfbCredentials.password.length]);
        this._sock.sendString(this._rfbCredentials.username);
        this._sock.sendString(this._rfbCredentials.password);
        this._rfbInitState = "SecurityResult";
        return true;
    }

    _negotiateTightTunnels(numTunnels) {
        const clientSupportedTunnelTypes = {
            0: { vendor: 'TGHT', signature: 'NOTUNNEL' }
        };
        const serverSupportedTunnelTypes = {};
        // receive tunnel capabilities
        for (let i = 0; i < numTunnels; i++) {
            const capCode = this._sock.rQshift32();
            const capVendor = this._sock.rQshiftStr(4);
            const capSignature = this._sock.rQshiftStr(8);
            serverSupportedTunnelTypes[capCode] = { vendor: capVendor, signature: capSignature };
        }

        Log.Debug("Server Tight tunnel types: " + serverSupportedTunnelTypes);

        // Siemens touch panels have a VNC server that supports NOTUNNEL,
        // but forgets to advertise it. Try to detect such servers by
        // looking for their custom tunnel type.
        if (serverSupportedTunnelTypes[1] &&
            (serverSupportedTunnelTypes[1].vendor === "SICR") &&
            (serverSupportedTunnelTypes[1].signature === "SCHANNEL")) {
            Log.Debug("Detected Siemens server. Assuming NOTUNNEL support.");
            serverSupportedTunnelTypes[0] = { vendor: 'TGHT', signature: 'NOTUNNEL' };
        }

        // choose the notunnel type
        if (serverSupportedTunnelTypes[0]) {
            if (serverSupportedTunnelTypes[0].vendor != clientSupportedTunnelTypes[0].vendor ||
                serverSupportedTunnelTypes[0].signature != clientSupportedTunnelTypes[0].signature) {
                return this._fail("Client's tunnel type had the incorrect " +
                                  "vendor or signature");
            }
            Log.Debug("Selected tunnel type: " + clientSupportedTunnelTypes[0]);
            this._sock.send([0, 0, 0, 0]);  // use NOTUNNEL
            return false; // wait until we receive the sub auth count to continue
        } else {
            return this._fail("Server wanted tunnels, but doesn't support " +
                              "the notunnel type");
        }
    }

    _negotiateTightAuth() {
        if (!this._rfbTightVNC) {  // first pass, do the tunnel negotiation
            if (this._sock.rQwait("num tunnels", 4)) { return false; }
            const numTunnels = this._sock.rQshift32();
            if (numTunnels > 0 && this._sock.rQwait("tunnel capabilities", 16 * numTunnels, 4)) { return false; }

            this._rfbTightVNC = true;

            if (numTunnels > 0) {
                this._negotiateTightTunnels(numTunnels);
                return false;  // wait until we receive the sub auth to continue
            }
        }

        // second pass, do the sub-auth negotiation
        if (this._sock.rQwait("sub auth count", 4)) { return false; }
        const subAuthCount = this._sock.rQshift32();
        if (subAuthCount === 0) {  // empty sub-auth list received means 'no auth' subtype selected
            this._rfbInitState = 'SecurityResult';
            return true;
        }

        if (this._sock.rQwait("sub auth capabilities", 16 * subAuthCount, 4)) { return false; }

        const clientSupportedTypes = {
            'STDVNOAUTH__': 1,
            'STDVVNCAUTH_': 2,
            'TGHTULGNAUTH': 129
        };

        const serverSupportedTypes = [];

        for (let i = 0; i < subAuthCount; i++) {
            this._sock.rQshift32(); // capNum
            const capabilities = this._sock.rQshiftStr(12);
            serverSupportedTypes.push(capabilities);
        }

        Log.Debug("Server Tight authentication types: " + serverSupportedTypes);

        for (let authType in clientSupportedTypes) {
            if (serverSupportedTypes.indexOf(authType) != -1) {
                this._sock.send([0, 0, 0, clientSupportedTypes[authType]]);
                Log.Debug("Selected authentication type: " + authType);

                switch (authType) {
                    case 'STDVNOAUTH__':  // no auth
                        this._rfbInitState = 'SecurityResult';
                        return true;
                    case 'STDVVNCAUTH_': // VNC auth
                        this._rfbAuthScheme = 2;
                        return this._initMsg();
                    case 'TGHTULGNAUTH': // UNIX auth
                        this._rfbAuthScheme = 129;
                        return this._initMsg();
                    default:
                        return this._fail("Unsupported tiny auth scheme " +
                                          "(scheme: " + authType + ")");
                }
            }
        }

        return this._fail("No supported sub-auth types!");
    }

    _negotiateAuthentication() {
        switch (this._rfbAuthScheme) {
            case 1:  // no auth
                if (this._rfbVersion >= 3.8) {
                    this._rfbInitState = 'SecurityResult';
                    return true;
                }
                this._rfbInitState = 'ClientInitialisation';
                return this._initMsg();

            case 22:  // XVP auth
                return this._negotiateXvpAuth();

            case 2:  // VNC authentication
                return this._negotiateStdVNCAuth();

            case 16:  // TightVNC Security Type
                return this._negotiateTightAuth();

            case 19:  // VeNCrypt Security Type
                return this._negotiateVeNCryptAuth();

            case 129:  // TightVNC UNIX Security Type
                return this._negotiateTightUnixAuth();

            default:
                return this._fail("Unsupported auth scheme (scheme: " +
                                  this._rfbAuthScheme + ")");
        }
    }



    _handleSecurityResult() {
        if (this._sock.rQwait('VNC auth response ', 4)) { return false; }

        const status = this._sock.rQshift32();

        if (status === 0) { // OK
            this._rfbInitState = 'ClientInitialisation';
            Log.Debug('Authentication OK');
            return this._initMsg();
        } else {
            if (this._rfbVersion >= 3.8) {
                this._rfbInitState = "SecurityReason";
                this._securityContext = "security result";
                this._securityStatus = status;
                return this._initMsg();
            } else {
                this.dispatchEvent(new CustomEvent(
                    "securityfailure",
                    { detail: { status: status } }));

                return this._fail("Security handshake failed");
            }
        }
    }

    _negotiateServerInit() {
        if (this._sock.rQwait("server initialization", 24)) { return false; }

        /* Screen size */
        const width = this._sock.rQshift16();
        const height = this._sock.rQshift16();

        /* PIXEL_FORMAT */
        const bpp         = this._sock.rQshift8();
        const depth       = this._sock.rQshift8();
        const bigEndian  = this._sock.rQshift8();
        const trueColor  = this._sock.rQshift8();

        const redMax     = this._sock.rQshift16();
        const greenMax   = this._sock.rQshift16();
        const blueMax    = this._sock.rQshift16();
        const redShift   = this._sock.rQshift8();
        const greenShift = this._sock.rQshift8();
        const blueShift  = this._sock.rQshift8();
        this._sock.rQskipBytes(3);  // padding

        // NB(directxman12): we don't want to call any callbacks or print messages until
        //                   *after* we're past the point where we could backtrack

        /* Connection name/title */
        const nameLength = this._sock.rQshift32();
        if (this._sock.rQwait('server init name', nameLength, 24)) { return false; }
        let name = this._sock.rQshiftStr(nameLength);
        //name = decodeUTF8(name, true);
		name = name.toString('utf8');

        if (this._rfbTightVNC) {
            if (this._sock.rQwait('TightVNC extended server init header', 8, 24 + nameLength)) { return false; }
            // In TightVNC mode, ServerInit message is extended
            const numServerMessages = this._sock.rQshift16();
            const numClientMessages = this._sock.rQshift16();
            const numEncodings = this._sock.rQshift16();
            this._sock.rQskipBytes(2);  // padding

            const totalMessagesLength = (numServerMessages + numClientMessages + numEncodings) * 16;
            if (this._sock.rQwait('TightVNC extended server init header', totalMessagesLength, 32 + nameLength)) { return false; }

            // we don't actually do anything with the capability information that TIGHT sends,
            // so we just skip the all of this.

            // TIGHT server message capabilities
            this._sock.rQskipBytes(16 * numServerMessages);

            // TIGHT client message capabilities
            this._sock.rQskipBytes(16 * numClientMessages);

            // TIGHT encoding capabilities
            this._sock.rQskipBytes(16 * numEncodings);
        }

        // NB(directxman12): these are down here so that we don't run them multiple times
        //                   if we backtrack
        Log.Info("Screen: " + width + "x" + height +
                  ", bpp: " + bpp + ", depth: " + depth +
                  ", bigEndian: " + bigEndian +
                  ", trueColor: " + trueColor +
                  ", redMax: " + redMax +
                  ", greenMax: " + greenMax +
                  ", blueMax: " + blueMax +
                  ", redShift: " + redShift +
                  ", greenShift: " + greenShift +
                  ", blueShift: " + blueShift);

        // we're past the point where we could backtrack, so it's safe to call this
        this._setDesktopName(name);
        this._resize(width, height);

        //if (!this._viewOnly) { this._keyboard.grab(); }
		if (!this._viewOnly) { this.client.emit("_keyboard.grab"); }

        this._fbDepth = 24;

        if (this._fbName === "Intel(r) AMT KVM") {
            Log.Warn("Intel AMT KVM only supports 8/16 bit depths. Using low color mode.");
            this._fbDepth = 8;
        }

        RFB.messages.pixelFormat(this._sock, this._fbDepth, true);
        this._sendEncodings();
        RFB.messages.fbUpdateRequest(this._sock, false, 0, 0, this._fbWidth, this._fbHeight);

        //this._updateConnectionState('connected');
		this._rfbConnectionState = 'connected';
		this.client.emit("_updateConnectionState", 'connected');
        return true;
    }

    _setDesktopName(name) {
        this._fbName = name;
        //this.dispatchEvent(new CustomEvent(
        //    "desktopname",
        //    { detail: { name: this._fbName } }));
		this.client.emit("_setDesktopName", name);
    }

    _resize(width, height) {
        this._fbWidth = width;
        this._fbHeight = height;
		this.client.emit("_resize", this._fbWidth, this._fbHeight);

        //this._display.resize(this._fbWidth, this._fbHeight);

        // Adjust the visible viewport based on the new dimensions
        //this._updateClip();
        //this._updateScale();

        this._updateContinuousUpdates();
    }

    _updateContinuousUpdates() {
        if (!this._enabledContinuousUpdates) { return; }

        RFB.messages.enableContinuousUpdates(this._sock, true, 0, 0,
                                             this._fbWidth, this._fbHeight);
    }

    _sendEncodings() {
        const encs = [];

        // In preference order
        encs.push(encodings.encodingCopyRect);
        // Only supported with full depth support
        if (this._fbDepth == 24) {
            encs.push(encodings.encodingTight);
            //encs.push(encodings.encodingTightPNG);
            //encs.push(encodings.encodingHextile);
            //encs.push(encodings.encodingRRE);
        }
        encs.push(encodings.encodingRaw);

        // Psuedo-encoding settings
        encs.push(encodings.pseudoEncodingQualityLevel0 + this._qualityLevel);
        encs.push(encodings.pseudoEncodingCompressLevel0 + this._compressionLevel);

        encs.push(encodings.pseudoEncodingDesktopSize);
        encs.push(encodings.pseudoEncodingLastRect);
        encs.push(encodings.pseudoEncodingQEMUExtendedKeyEvent);
        //encs.push(encodings.pseudoEncodingExtendedDesktopSize);
        encs.push(encodings.pseudoEncodingXvp);
        encs.push(encodings.pseudoEncodingFence);
        encs.push(encodings.pseudoEncodingContinuousUpdates);
        encs.push(encodings.pseudoEncodingDesktopName);
        encs.push(encodings.pseudoEncodingExtendedClipboard);

        if (this._fbDepth == 24) {
            encs.push(encodings.pseudoEncodingVMwareCursor);
            encs.push(encodings.pseudoEncodingCursor);
        }

        RFB.messages.clientEncodings(this._sock, encs);
    }

    /* RFB protocol initialization states:
     *   ProtocolVersion
     *   Security
     *   Authentication
     *   SecurityResult
     *   ClientInitialization - not triggered by server message
     *   ServerInitialization
     */
    _initMsg() {
        switch (this._rfbInitState) {
            case 'ProtocolVersion':
                return this._negotiateProtocolVersion();

            case 'Security':
                return this._negotiateSecurity();

            case 'Authentication':
                return this._negotiateAuthentication();

            case 'SecurityResult':
                return this._handleSecurityResult();

            case 'SecurityReason':
                return this._handleSecurityReason();

            case 'ClientInitialisation':
                this._sock.send([this._shared ? 1 : 0]); // ClientInitialisation
                this._rfbInitState = 'ServerInitialisation';
                return true;

            case 'ServerInitialisation':
                return this._negotiateServerInit();

            default:
                return this._fail("Unknown init state (state: " +
                                  this._rfbInitState + ")");
        }
    }

    _normalMsg() {
        let msgType;
        if (this._FBU.rects > 0) {
            msgType = 0;
        } else {
            msgType = this._sock.rQshift8();
        }

        let first, ret;
        switch (msgType) {
            case 0:  // FramebufferUpdate
                ret = this._framebufferUpdate();
                if (ret && !this._enabledContinuousUpdates) {
                    RFB.messages.fbUpdateRequest(this._sock, true, 0, 0,
                                                 this._fbWidth, this._fbHeight);
                }
                return ret;

            case 1:  // SetColorMapEntries
                return this._handleSetColourMapMsg();

            case 2:  // Bell
                Log.Debug("Bell");
                //this.dispatchEvent(new CustomEvent(
                //    "bell",
                //    { detail: {} }));
				client.emit("bell");
                return true;

            case 3:  // ServerCutText
                return this._handleServerCutText();

            case 150: // EndOfContinuousUpdates
                first = !this._supportsContinuousUpdates;
                this._supportsContinuousUpdates = true;
                this._enabledContinuousUpdates = false;
                if (first) {
                    this._enabledContinuousUpdates = true;
                    this._updateContinuousUpdates();
                    Log.Info("Enabling continuous updates.");
                } else {
                    // FIXME: We need to send a framebufferupdaterequest here
                    // if we add support for turning off continuous updates
                }
                return true;

            case 248: // ServerFence
                return this._handleServerFenceMsg();

            case 250:  // XVP
                return this._handleXvpMsg();

            default:
                this._fail("Unexpected server message (type " + msgType + ")");
                Log.Debug("sock.rQslice(0, 30): " + this._sock.rQslice(0, 30));
                return true;
        }
    }

    _framebufferUpdate() {
        if (this._FBU.rects === 0) {
            if (this._sock.rQwait("FBU header", 3, 1)) { return false; }
            this._sock.rQskipBytes(1);  // Padding
            this._FBU.rects = this._sock.rQshift16();

            // Make sure the previous frame is fully rendered first
            // to avoid building up an excessive queue
            /*if (this._display.pending()) {
                this._flushing = true;
                this._display.flush();
                return false;
            }*/
        }

        while (this._FBU.rects > 0) {
            if (this._FBU.encoding === null) {
                if (this._sock.rQwait("rect header", 12)) { return false; }
                /* New FramebufferUpdate */

                const hdr = this._sock.rQshiftBytes(12);
                this._FBU.x        = (hdr[0] << 8) + hdr[1];
                this._FBU.y        = (hdr[2] << 8) + hdr[3];
                this._FBU.width    = (hdr[4] << 8) + hdr[5];
                this._FBU.height   = (hdr[6] << 8) + hdr[7];
                this._FBU.encoding = parseInt((hdr[8] << 24) + (hdr[9] << 16) +
                                              (hdr[10] << 8) + hdr[11], 10);
				//Log.Debug("FBU encoding: " + this._FBU.encoding);
            }

            if (!this._handleRect()) {
                return false;
            }

            this._FBU.rects--;
            this._FBU.encoding = null;
        }

        //this._display.flip();

        return true;  // We finished this FBU
    }

    _handleRect() {
        switch (this._FBU.encoding) {
            case encodings.pseudoEncodingLastRect:
                this._FBU.rects = 1; // Will be decreased when we return
				this.client.emit("fbu_pseudoEncodingLastRect");
                return true;

            case encodings.pseudoEncodingVMwareCursor:
                return this._handleVMwareCursor();

            case encodings.pseudoEncodingCursor:
                return this._handleCursor();

            case encodings.pseudoEncodingQEMUExtendedKeyEvent:
                this._qemuExtKeyEventSupported = true;
				this.client.emit("fbu_qemuExtKeyEventSupported");
                return true;

            case encodings.pseudoEncodingDesktopName:
                return this._handleDesktopName();

            case encodings.pseudoEncodingDesktopSize:
				this._resize(this._FBU.width, this._FBU.height);
				this.client.emit("fbu_display_flip");
                return true;

            case encodings.pseudoEncodingExtendedDesktopSize:
                return this._handleExtendedDesktopSize();

            default:
                return this._handleDataRect();
        }
    }

    _handleVMwareCursor() {
        const hotx = this._FBU.x;  // hotspot-x
        const hoty = this._FBU.y;  // hotspot-y
        const w = this._FBU.width;
        const h = this._FBU.height;
        if (this._sock.rQwait("VMware cursor encoding", 1)) {
            return false;
        }

        const cursorType = this._sock.rQshift8();

        this._sock.rQshift8(); //Padding

        let rgba;
        const bytesPerPixel = 4;

        //Classic cursor
        if (cursorType == 0) {
            //Used to filter away unimportant bits.
            //OR is used for correct conversion in js.
            const PIXEL_MASK = 0xffffff00 | 0;
            rgba = new Array(w * h * bytesPerPixel);

            if (this._sock.rQwait("VMware cursor classic encoding",
                                  (w * h * bytesPerPixel) * 2, 2)) {
                return false;
            }

            let andMask = new Array(w * h);
            for (let pixel = 0; pixel < (w * h); pixel++) {
                andMask[pixel] = this._sock.rQshift32();
            }

            let xorMask = new Array(w * h);
            for (let pixel = 0; pixel < (w * h); pixel++) {
                xorMask[pixel] = this._sock.rQshift32();
            }

            for (let pixel = 0; pixel < (w * h); pixel++) {
                if (andMask[pixel] == 0) {
                    //Fully opaque pixel
                    let bgr = xorMask[pixel];
                    let r   = bgr >> 8  & 0xff;
                    let g   = bgr >> 16 & 0xff;
                    let b   = bgr >> 24 & 0xff;

                    rgba[(pixel * bytesPerPixel)     ] = r;    //r
                    rgba[(pixel * bytesPerPixel) + 1 ] = g;    //g
                    rgba[(pixel * bytesPerPixel) + 2 ] = b;    //b
                    rgba[(pixel * bytesPerPixel) + 3 ] = 0xff; //a

                } else if ((andMask[pixel] & PIXEL_MASK) ==
                           PIXEL_MASK) {
                    //Only screen value matters, no mouse colouring
                    if (xorMask[pixel] == 0) {
                        //Transparent pixel
                        rgba[(pixel * bytesPerPixel)     ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 1 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 2 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 3 ] = 0x00;

                    } else if ((xorMask[pixel] & PIXEL_MASK) ==
                               PIXEL_MASK) {
                        //Inverted pixel, not supported in browsers.
                        //Fully opaque instead.
                        rgba[(pixel * bytesPerPixel)     ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 1 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 2 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 3 ] = 0xff;

                    } else {
                        //Unhandled xorMask
                        rgba[(pixel * bytesPerPixel)     ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 1 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 2 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 3 ] = 0xff;
                    }

                } else {
                    //Unhandled andMask
                    rgba[(pixel * bytesPerPixel)     ] = 0x00;
                    rgba[(pixel * bytesPerPixel) + 1 ] = 0x00;
                    rgba[(pixel * bytesPerPixel) + 2 ] = 0x00;
                    rgba[(pixel * bytesPerPixel) + 3 ] = 0xff;
                }
            }

        //Alpha cursor.
        } else if (cursorType == 1) {
            if (this._sock.rQwait("VMware cursor alpha encoding",
                                  (w * h * 4), 2)) {
                return false;
            }

            rgba = new Array(w * h * bytesPerPixel);

            for (let pixel = 0; pixel < (w * h); pixel++) {
                let data = this._sock.rQshift32();

                rgba[(pixel * 4)     ] = data >> 24 & 0xff; //r
                rgba[(pixel * 4) + 1 ] = data >> 16 & 0xff; //g
                rgba[(pixel * 4) + 2 ] = data >> 8 & 0xff;  //b
                rgba[(pixel * 4) + 3 ] = data & 0xff;       //a
            }

        } else {
            Log.Warn("The given cursor type is not supported: "
                      + cursorType + " given.");
            return false;
        }

        this._updateCursor(rgba, hotx, hoty, w, h);

        return true;
    }

    _handleCursor() {
        const hotx = this._FBU.x;  // hotspot-x
        const hoty = this._FBU.y;  // hotspot-y
        const w = this._FBU.width;
        const h = this._FBU.height;

        const pixelslength = w * h * 4;
        const masklength = Math.ceil(w / 8) * h;

        let bytes = pixelslength + masklength;
        if (this._sock.rQwait("cursor encoding", bytes)) {
            return false;
        }

        // Decode from BGRX pixels + bit mask to RGBA
        const pixels = this._sock.rQshiftBytes(pixelslength);
        const mask = this._sock.rQshiftBytes(masklength);
        let rgba = new Uint8Array(w * h * 4);

        let pixIdx = 0;
        for (let y = 0; y < h; y++) {
            for (let x = 0; x < w; x++) {
                let maskIdx = y * Math.ceil(w / 8) + Math.floor(x / 8);
                let alpha = (mask[maskIdx] << (x % 8)) & 0x80 ? 255 : 0;
                rgba[pixIdx    ] = pixels[pixIdx + 2];
                rgba[pixIdx + 1] = pixels[pixIdx + 1];
                rgba[pixIdx + 2] = pixels[pixIdx];
                rgba[pixIdx + 3] = alpha;
                pixIdx += 4;
            }
        }

        this._updateCursor(rgba, hotx, hoty, w, h);

        return true;
    }

    _updateCursor(rgba, hotx, hoty, w, h) {
        this._cursorImage = {
            rgbaPixels: rgba,
            hotx: hotx, hoty: hoty, w: w, h: h,
        };
        this._refreshCursor();
    }

    _shouldShowDotCursor() {
        // Called when this._cursorImage is updated
        if (!this._showDotCursor) {
            // User does not want to see the dot, so...
            return false;
        }

        // The dot should not be shown if the cursor is already visible,
        // i.e. contains at least one not-fully-transparent pixel.
        // So iterate through all alpha bytes in rgba and stop at the
        // first non-zero.
        for (let i = 3; i < this._cursorImage.rgbaPixels.length; i += 4) {
            if (this._cursorImage.rgbaPixels[i]) {
                return false;
            }
        }

        // At this point, we know that the cursor is fully transparent, and
        // the user wants to see the dot instead of this.
        return true;
    }

    _refreshCursor() {
        if (this._rfbConnectionState !== "connecting" &&
            this._rfbConnectionState !== "connected") {
            return;
        }
        const image = this._shouldShowDotCursor() ? RFB.cursors.dot : this._cursorImage;
        /*this._cursor.change(image.rgbaPixels,
                            image.hotx, image.hoty,
                            image.w, image.h
        );*/
		this.client.emit("fbu_cursor_change", image.rgbaPixels, image.hotx, image.hoty, image.w, image.h);
    }

    _handleDesktopName() {
        if (this._sock.rQwait("DesktopName", 4)) {
            return false;
        }

        let length = this._sock.rQshift32();

        if (this._sock.rQwait("DesktopName", length, 4)) {
            return false;
        }

        let name = this._sock.rQshiftStr(length);
        //name = decodeUTF8(name, true);
		name = name.toString('utf8');

        this._setDesktopName(name);
        this.client.emit("fbu_display_flip");
		
        return true;
    }

    _handleExtendedDesktopSize() {
        if (this._sock.rQwait("ExtendedDesktopSize", 4)) {
            return false;
        }

        const numberOfScreens = this._sock.rQpeek8();

        let bytes = 4 + (numberOfScreens * 16);
        if (this._sock.rQwait("ExtendedDesktopSize", bytes)) {
            return false;
        }

        const firstUpdate = !this._supportsSetDesktopSize;
        this._supportsSetDesktopSize = true;

        // Normally we only apply the current resize mode after a
        // window resize event. However there is no such trigger on the
        // initial connect. And we don't know if the server supports
        // resizing until we've gotten here.
        if (firstUpdate) {
            //this._requestRemoteResize(); _requestRemoteResize() calls _screenSize(), _screenSize() calls this._screen.getBoundingClientRect(), this._screen is a DIV element in the showing page
	                                    // so this function will fail on the webserver		
        }

        this._sock.rQskipBytes(1);  // number-of-screens
        this._sock.rQskipBytes(3);  // padding

        for (let i = 0; i < numberOfScreens; i += 1) {
            // Save the id and flags of the first screen
            if (i === 0) {
                this._screenID = this._sock.rQshiftBytes(4);    // id
                this._sock.rQskipBytes(2);                       // x-position
                this._sock.rQskipBytes(2);                       // y-position
                this._sock.rQskipBytes(2);                       // width
                this._sock.rQskipBytes(2);                       // height
                this._screenFlags = this._sock.rQshiftBytes(4); // flags
            } else {
                this._sock.rQskipBytes(16);
            }
        }

        /*
         * The x-position indicates the reason for the change:
         *
         *  0 - server resized on its own
         *  1 - this client requested the resize
         *  2 - another client requested the resize
         */

        // We need to handle errors when we requested the resize.
        if (this._FBU.x === 1 && this._FBU.y !== 0) {
            let msg = "";
            // The y-position indicates the status code from the server
            switch (this._FBU.y) {
                case 1:
                    msg = "Resize is administratively prohibited";
                    break;
                case 2:
                    msg = "Out of resources";
                    break;
                case 3:
                    msg = "Invalid screen layout";
                    break;
                default:
                    msg = "Unknown reason";
                    break;
            }
            Log.Warn("Server did not accept the resize request: "
                     + msg);
        } else {
            this._resize(this._FBU.width, this._FBU.height);
			this.client.emit("fbu_display_flip");
        }

        return true;
    }

    _handleDataRect() {
        let decoder = this._decoders[this._FBU.encoding];
        if (!decoder) {
            this._fail("Unsupported encoding (encoding: " +
                       this._FBU.encoding + ")");
            return false;
        }

        try {
            return decoder.decodeRect(this._FBU.x, this._FBU.y,
                                      this._FBU.width, this._FBU.height,
                                      this._sock, this.client,
                                      this._fbDepth);
        } catch (err) {
            this._fail("Error decoding rect: " + err);
            return false;
        }
    }

    _handleSetColourMapMsg() {
        Log.Debug("SetColorMapEntries");

        return this._fail("Unexpected SetColorMapEntries message");
    }

    _handleServerCutText() {
        Log.Debug("ServerCutText");

        if (this._sock.rQwait("ServerCutText header", 7, 1)) { return false; }

        this._sock.rQskipBytes(3);  // Padding

        let length = this._sock.rQshift32();
        length = toSigned32bit(length);

        if (this._sock.rQwait("ServerCutText content", Math.abs(length), 8)) { return false; }

        if (length >= 0) {
            //Standard msg
            const text = this._sock.rQshiftStr(length);
            if (this._viewOnly) {
                return true;
            }

            //this.dispatchEvent(new CustomEvent(
            //    "clipboard",
            //    { detail: { text: text } }));
			this.client.emit("clipboard", text);

        } else {
            //Extended msg.
            length = Math.abs(length);
            const flags = this._sock.rQshift32();
            let formats = flags & 0x0000FFFF;
            let actions = flags & 0xFF000000;

            let isCaps = (!!(actions & extendedClipboardActionCaps));
            if (isCaps) {
                this._clipboardServerCapabilitiesFormats = {};
                this._clipboardServerCapabilitiesActions = {};

                // Update our server capabilities for Formats
                for (let i = 0; i <= 15; i++) {
                    let index = 1 << i;

                    // Check if format flag is set.
                    if ((formats & index)) {
                        this._clipboardServerCapabilitiesFormats[index] = true;
                        // We don't send unsolicited clipboard, so we
                        // ignore the size
                        this._sock.rQshift32();
                    }
                }

                // Update our server capabilities for Actions
                for (let i = 24; i <= 31; i++) {
                    let index = 1 << i;
                    this._clipboardServerCapabilitiesActions[index] = !!(actions & index);
                }

                /*  Caps handling done, send caps with the clients
                    capabilities set as a response */
                let clientActions = [
                    extendedClipboardActionCaps,
                    extendedClipboardActionRequest,
                    extendedClipboardActionPeek,
                    extendedClipboardActionNotify,
                    extendedClipboardActionProvide
                ];
                RFB.messages.extendedClipboardCaps(this._sock, clientActions, {extendedClipboardFormatText: 0});

            } else if (actions === extendedClipboardActionRequest) {
                if (this._viewOnly) {
                    return true;
                }

                // Check if server has told us it can handle Provide and there is clipboard data to send.
                if (this._clipboardText != null &&
                    this._clipboardServerCapabilitiesActions[extendedClipboardActionProvide]) {

                    if (formats & extendedClipboardFormatText) {
                        RFB.messages.extendedClipboardProvide(this._sock, [extendedClipboardFormatText], [this._clipboardText]);
                    }
                }

            } else if (actions === extendedClipboardActionPeek) {
                if (this._viewOnly) {
                    return true;
                }

                if (this._clipboardServerCapabilitiesActions[extendedClipboardActionNotify]) {

                    if (this._clipboardText != null) {
                        RFB.messages.extendedClipboardNotify(this._sock, [extendedClipboardFormatText]);
                    } else {
                        RFB.messages.extendedClipboardNotify(this._sock, []);
                    }
                }

            } else if (actions === extendedClipboardActionNotify) {
                if (this._viewOnly) {
                    return true;
                }

                if (this._clipboardServerCapabilitiesActions[extendedClipboardActionRequest]) {

                    if (formats & extendedClipboardFormatText) {
                        RFB.messages.extendedClipboardRequest(this._sock, [extendedClipboardFormatText]);
                    }
                }

            } else if (actions === extendedClipboardActionProvide) {
                if (this._viewOnly) {
                    return true;
                }

                if (!(formats & extendedClipboardFormatText)) {
                    return true;
                }
                // Ignore what we had in our clipboard client side.
                this._clipboardText = null;

                // FIXME: Should probably verify that this data was actually requested
                let zlibStream = this._sock.rQshiftBytes(length - 4);
                let streamInflator = new Inflator();
                let textData = null;

                streamInflator.setInput(zlibStream);
                for (let i = 0; i <= 15; i++) {
                    let format = 1 << i;

                    if (formats & format) {

                        let size = 0x00;
                        let sizeArray = streamInflator.inflate(4);

                        size |= (sizeArray[0] << 24);
                        size |= (sizeArray[1] << 16);
                        size |= (sizeArray[2] << 8);
                        size |= (sizeArray[3]);
                        let chunk = streamInflator.inflate(size);

                        if (format === extendedClipboardFormatText) {
                            textData = chunk;
                        }
                    }
                }
                streamInflator.setInput(null);

                if (textData !== null) {
                    let tmpText = "";
                    for (let i = 0; i < textData.length; i++) {
                        tmpText += String.fromCharCode(textData[i]);
                    }
                    textData = tmpText;

                    //textData = decodeUTF8(textData);
					textData = textData.toString('utf8');
                    if ((textData.length > 0) && "\0" === textData.charAt(textData.length - 1)) {
                        textData = textData.slice(0, -1);
                    }

                    textData = textData.replace("\r\n", "\n");

                    //this.dispatchEvent(new CustomEvent(
                    //    "clipboard",
                    //    { detail: { text: textData } }));
					this.client.emit("clipboard", textData);
                }
            } else {
                return this._fail("Unexpected action in extended clipboard message: " + actions);
            }
        }
        return true;
    }

    _handleServerFenceMsg() {
        if (this._sock.rQwait("ServerFence header", 8, 1)) { return false; }
        this._sock.rQskipBytes(3); // Padding
        let flags = this._sock.rQshift32();
        let length = this._sock.rQshift8();

        if (this._sock.rQwait("ServerFence payload", length, 9)) { return false; }

        if (length > 64) {
            Log.Warn("Bad payload length (" + length + ") in fence response");
            length = 64;
        }

        const payload = this._sock.rQshiftStr(length);

        this._supportsFence = true;

        /*
         * Fence flags
         *
         *  (1<<0)  - BlockBefore
         *  (1<<1)  - BlockAfter
         *  (1<<2)  - SyncNext
         *  (1<<31) - Request
         */

        if (!(flags & (1<<31))) {
            return this._fail("Unexpected fence response");
        }

        // Filter out unsupported flags
        // FIXME: support syncNext
        flags &= (1<<0) | (1<<1);

        // BlockBefore and BlockAfter are automatically handled by
        // the fact that we process each incoming message
        // synchronuosly.
        RFB.messages.clientFence(this._sock, flags, payload);

        return true;
    }

    _handleXvpMsg() {
        if (this._sock.rQwait("XVP version and message", 3, 1)) { return false; }
        this._sock.rQskipBytes(1);  // Padding
        const xvpVer = this._sock.rQshift8();
        const xvpMsg = this._sock.rQshift8();

        switch (xvpMsg) {
            case 0:  // XVP_FAIL
                Log.Error("XVP Operation Failed");
                break;
            case 1:  // XVP_INIT
                this._rfbXvpVer = xvpVer;
                Log.Info("XVP extensions enabled (version " + this._rfbXvpVer + ")");
                this._setCapability("power", true);
                break;
            default:
                this._fail("Illegal server XVP message (msg: " + xvpMsg + ")");
                break;
        }

        return true;
    }


    /* Print errors and disconnect
     *
     * The parameter 'details' is used for information that
     * should be logged but not sent to the user interface.
     */
    _fail(details) {
        switch (this._rfbConnectionState) {
            case 'disconnecting':
                Log.Error("Failed when disconnecting: " + details);
                break;
            case 'connected':
                Log.Error("Failed while connected: " + details);
                break;
            case 'connecting':
                Log.Error("Failed when connecting: " + details);
                break;
            default:
                Log.Error("RFB failure: " + details);
                break;
        }
        this._rfbCleanDisconnect = false; //This is sent to the UI

        // Transition to disconnected without waiting for socket to close
        //this._updateConnectionState('disconnecting');
        //this._updateConnectionState('disconnected');
		this._rfbConnectionState = 'disconnected';

        return false;
    }

    static genDES(password, challenge) {
        const passwordChars = password.split('').map(c => c.charCodeAt(0));
        return (new DES(passwordChars)).encrypt(challenge);
    }

} // end of 'RFB' class

// Class Methods
RFB.messages = {
    keyEvent(sock, keysym, down) {
        const buff = sock._sQ;
        const offset = sock._sQlen;

        buff[offset] = 4;  // msg-type
        buff[offset + 1] = down;

        buff[offset + 2] = 0;
        buff[offset + 3] = 0;

        buff[offset + 4] = (keysym >> 24);
        buff[offset + 5] = (keysym >> 16);
        buff[offset + 6] = (keysym >> 8);
        buff[offset + 7] = keysym;

        sock._sQlen += 8;
        sock.flush();
    },

    QEMUExtendedKeyEvent(sock, keysym, down, keycode) {
        function getRFBkeycode(xtScanCode) {
            const upperByte = (keycode >> 8);
            const lowerByte = (keycode & 0x00ff);
            if (upperByte === 0xe0 && lowerByte < 0x7f) {
                return lowerByte | 0x80;
            }
            return xtScanCode;
        }

        const buff = sock._sQ;
        const offset = sock._sQlen;

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

        sock._sQlen += 12;
        sock.flush();
    },

    pointerEvent(sock, x, y, mask) {
        const buff = sock._sQ;
        const offset = sock._sQlen;

        buff[offset] = 5; // msg-type

        buff[offset + 1] = mask;

        buff[offset + 2] = x >> 8;
        buff[offset + 3] = x;

        buff[offset + 4] = y >> 8;
        buff[offset + 5] = y;

        sock._sQlen += 6;
        sock.flush();
    },

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
    },

    extendedClipboardProvide(sock, formats, inData) {
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
        data.set(RFB.messages._buildExtendedClipboardFlags([extendedClipboardActionProvide],
                                                           formats));
        data.set(deflatedData, 4);

        RFB.messages.clientCutText(sock, data, true);
    },

    extendedClipboardNotify(sock, formats) {
        let flags = RFB.messages._buildExtendedClipboardFlags([extendedClipboardActionNotify],
                                                              formats);
        RFB.messages.clientCutText(sock, flags, true);
    },

    extendedClipboardRequest(sock, formats) {
        let flags = RFB.messages._buildExtendedClipboardFlags([extendedClipboardActionRequest],
                                                              formats);
        RFB.messages.clientCutText(sock, flags, true);
    },

    extendedClipboardCaps(sock, actions, formats) {
        let formatKeys = Object.keys(formats);
        let data  = new Uint8Array(4 + (4 * formatKeys.length));

        formatKeys.map(x => parseInt(x));
        formatKeys.sort((a, b) =>  a - b);

        data.set(RFB.messages._buildExtendedClipboardFlags(actions, []));

        let loopOffset = 4;
        for (let i = 0; i < formatKeys.length; i++) {
            data[loopOffset]     = formats[formatKeys[i]] >> 24;
            data[loopOffset + 1] = formats[formatKeys[i]] >> 16;
            data[loopOffset + 2] = formats[formatKeys[i]] >> 8;
            data[loopOffset + 3] = formats[formatKeys[i]] >> 0;

            loopOffset += 4;
            data[3] |= (1 << formatKeys[i]); // Update our format flags
        }

        RFB.messages.clientCutText(sock, data, true);
    },

    clientCutText(sock, data, extended = false) {
        const buff = sock._sQ;
        const offset = sock._sQlen;

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

        sock._sQlen += 8;

        // We have to keep track of from where in the data we begin creating the
        // buffer for the flush in the next iteration.
        let dataOffset = 0;

        let remaining = data.length;
        while (remaining > 0) {

            let flushSize = Math.min(remaining, (sock._sQbufferSize - sock._sQlen));
            for (let i = 0; i < flushSize; i++) {
                buff[sock._sQlen + i] = data[dataOffset + i];
            }

            sock._sQlen += flushSize;
            sock.flush();

            remaining -= flushSize;
            dataOffset += flushSize;
        }

    },

    setDesktopSize(sock, width, height, id, flags) {
        const buff = sock._sQ;
        const offset = sock._sQlen;

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

        sock._sQlen += 24;
        sock.flush();
    },

    clientFence(sock, flags, payload) {
        const buff = sock._sQ;
        const offset = sock._sQlen;

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

        sock._sQlen += 9 + n;
        sock.flush();
    },

    enableContinuousUpdates(sock, enable, x, y, width, height) {
        const buff = sock._sQ;
        const offset = sock._sQlen;

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

        sock._sQlen += 10;
        sock.flush();
    },

    pixelFormat(sock, depth, trueColor) {
        const buff = sock._sQ;
        const offset = sock._sQlen;

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

        sock._sQlen += 20;
        sock.flush();
    },

    clientEncodings(sock, encodings) {
        const buff = sock._sQ;
        const offset = sock._sQlen;

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

        sock._sQlen += j - offset;
        sock.flush();
    },

    fbUpdateRequest(sock, incremental, x, y, w, h) {
        const buff = sock._sQ;
        const offset = sock._sQlen;

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

        sock._sQlen += 10;
        sock.flush();
    },

    xvpOp(sock, ver, op) {
        const buff = sock._sQ;
        const offset = sock._sQlen;

        buff[offset] = 250; // msg-type
        buff[offset + 1] = 0; // padding

        buff[offset + 2] = ver;
        buff[offset + 3] = op;

        sock._sQlen += 4;
        sock.flush();
    }
};

RFB.cursors = {
    none: {
        rgbaPixels: new Uint8Array(),
        w: 0, h: 0,
        hotx: 0, hoty: 0,
    },

    dot: {
        /* eslint-disable indent */
        rgbaPixels: new Uint8Array([
            255, 255, 255, 255,   0,   0,   0, 255, 255, 255, 255, 255,
              0,   0,   0, 255,   0,   0,   0,   0,   0,   0,  0,  255,
            255, 255, 255, 255,   0,   0,   0, 255, 255, 255, 255, 255,
        ]),
        /* eslint-enable indent */
        w: 3, h: 3,
        hotx: 1, hoty: 1,
    }
};

module.exports = {
    RFB
}

/**
 * SSL/TLS traffic capture — based on r0capture
 *
 * Hooks SSL_read/SSL_write at native layer + Java socket layer.
 * Captures decrypted traffic with connection info and stack traces.
 *
 * Supported:
 *   - Native: libssl (OpenSSL/BoringSSL/conscrypt)
 *   - Java: SocketOutputStream/SocketInputStream (plaintext HTTP)
 *   - Java: ConscryptFileDescriptorSocket SSLOutputStream/SSLInputStream
 *
 * Messages sent via send() with payload:
 *   {function, src_addr, src_port, dst_addr, dst_port, ssl_session_id, stack}
 *   + binary data as second argument
 */

"use strict";

rpc.exports = {
    setssllib: function(name) {
        libname = name;
        initNativeHooks();
    }
};

var libname = "*libssl*";
var addresses = {};
var SSL_get_fd, SSL_get_session, SSL_SESSION_get_id;
var ntohs, ntohl;
var SSLstackwrite = "";
var SSLstackread = "";

function initNativeHooks() {
    var resolver = new ApiResolver("module");
    var libs = [
        [Process.platform === "darwin" ? "*libboringssl*" : libname,
         ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id"]],
        [Process.platform === "darwin" ? "*libsystem*" : "*libc*",
         ["getpeername", "getsockname", "ntohs", "ntohl"]]
    ];

    for (var i = 0; i < libs.length; i++) {
        var lib = libs[i][0], names = libs[i][1];
        for (var j = 0; j < names.length; j++) {
            var name = names[j];
            var matches = resolver.enumerateMatches("exports:" + lib + "!" + name);
            if (matches.length === 0) {
                if (name === "SSL_get_fd") { addresses[name] = 0; continue; }
                continue;
            }
            // Prefer conscrypt
            var sel = null;
            for (var k = 0; k < matches.length; k++) {
                if (matches[k].name.indexOf("conscrypt") !== -1) { sel = matches[k]; break; }
            }
            addresses[name] = (sel || matches[0]).address;
        }
    }

    SSL_get_fd = addresses["SSL_get_fd"]
        ? new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"])
        : function() { return 0; };
    SSL_get_session = addresses["SSL_get_session"]
        ? new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"]) : null;
    SSL_SESSION_get_id = addresses["SSL_SESSION_get_id"]
        ? new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]) : null;
    ntohs = new NativeFunction(addresses["ntohs"], "uint16", ["uint16"]);
    ntohl = new NativeFunction(addresses["ntohl"], "uint32", ["uint32"]);

    // Hook SSL_read
    if (addresses["SSL_read"]) {
        Interceptor.attach(addresses["SSL_read"], {
            onEnter: function(args) {
                var fd = SSL_get_fd(args[0]);
                this.msg = getConnInfo(fd);
                this.msg.function = "SSL_read";
                this.msg.ssl_session_id = getSslSessionId(args[0]);
                this.msg.stack = SSLstackread;
                this.buf = args[1];
            },
            onLeave: function(retval) {
                var len = retval.toInt32();
                if (len <= 0) return;
                this.msg.length = len;
                send(this.msg, this.buf.readByteArray(Math.min(len, 16384)));
            }
        });
    }

    // Hook SSL_write
    if (addresses["SSL_write"]) {
        Interceptor.attach(addresses["SSL_write"], {
            onEnter: function(args) {
                var fd = SSL_get_fd(args[0]);
                var len = args[2].toInt32();
                var msg = getConnInfo(fd);
                msg.function = "SSL_write";
                msg.ssl_session_id = getSslSessionId(args[0]);
                msg.stack = SSLstackwrite;
                msg.length = len;
                send(msg, args[1].readByteArray(Math.min(len, 16384)));
            }
        });
    }

    send({type: "native_ssl_hooked", functions: Object.keys(addresses)});
}

function ipToNumber(ip) {
    if (!ip) return 0;
    var parts = ip.split(".");
    if (parts.length !== 4) return 0;
    return ((parseInt(parts[0]) << 0) + (parseInt(parts[1]) << 8) +
            (parseInt(parts[2]) << 16) + (parseInt(parts[3]) << 24)) >>> 0;
}

function getConnInfo(fd) {
    var info = {src_addr: 0, src_port: 0, dst_addr: 0, dst_port: 0};
    try {
        var peer = Socket.peerAddress(fd);
        var local = Socket.localAddress(fd);
        if (peer) {
            info.dst_addr = peer.ip || "?";
            info.dst_port = peer.port || 0;
        }
        if (local) {
            info.src_addr = local.ip || "?";
            info.src_port = local.port || 0;
        }
    } catch(e) {}
    return info;
}

function getSslSessionId(ssl) {
    if (!SSL_get_session || !SSL_SESSION_get_id) return "";
    try {
        var session = SSL_get_session(ssl);
        if (session.isNull()) return "";
        var lenPtr = Memory.alloc(4);
        var p = SSL_SESSION_get_id(session, lenPtr);
        var len = lenPtr.readU32();
        var id = "";
        for (var i = 0; i < Math.min(len, 32); i++) {
            var b = p.add(i).readU8().toString(16).toUpperCase();
            id += (b.length < 2 ? "0" : "") + b;
        }
        return id;
    } catch(e) { return ""; }
}

// Initialize native hooks
initNativeHooks();

// ── Java layer hooks ──────────────────────────────────

if (typeof Java !== "undefined" && Java.available) {
    Java.perform(function() {
        var Log = Java.use("android.util.Log");
        var Throwable = Java.use("java.lang.Throwable");

        function getStack() {
            return Log.getStackTraceString(Throwable.$new()).substring(0, 800);
        }

        // Plaintext HTTP: SocketOutputStream.socketWrite0
        try {
            Java.use("java.net.SocketOutputStream").socketWrite0
                .overload("java.io.FileDescriptor", "[B", "int", "int")
                .implementation = function(fd, bytes, offset, count) {
                    var result = this.socketWrite0(fd, bytes, offset, count);
                    var msg = {};
                    msg.function = "HTTP_send";
                    msg.ssl_session_id = "";
                    try {
                        var sock = this.socket.value;
                        msg.src_addr = sock.getLocalAddress().toString().split("/").pop().split(":")[0];
                        msg.src_port = parseInt(sock.getLocalPort());
                        msg.dst_addr = sock.getRemoteSocketAddress().toString().split("/").pop().split(":")[0];
                        msg.dst_port = parseInt(sock.getRemoteSocketAddress().toString().split(":").pop());
                    } catch(e) {}
                    msg.stack = getStack();
                    msg.length = count;
                    var ptr = Memory.alloc(count);
                    for (var i = 0; i < count; i++) ptr.add(i).writeU8(bytes[offset + i] & 0xff);
                    send(msg, ptr.readByteArray(count));
                    return result;
                };
            send({type: "java_http_send_hooked"});
        } catch(e) {}

        // Plaintext HTTP: SocketInputStream.socketRead0
        try {
            Java.use("java.net.SocketInputStream").socketRead0
                .overload("java.io.FileDescriptor", "[B", "int", "int", "int")
                .implementation = function(fd, bytes, offset, count, timeout) {
                    var result = this.socketRead0(fd, bytes, offset, count, timeout);
                    if (result > 0) {
                        var msg = {};
                        msg.function = "HTTP_recv";
                        msg.ssl_session_id = "";
                        try {
                            var sock = this.socket.value;
                            msg.dst_addr = sock.getLocalAddress().toString().split("/").pop().split(":")[0];
                            msg.dst_port = parseInt(sock.getLocalPort());
                            msg.src_addr = sock.getRemoteSocketAddress().toString().split("/").pop().split(":")[0];
                            msg.src_port = parseInt(sock.getRemoteSocketAddress().toString().split(":").pop());
                        } catch(e) {}
                        msg.stack = getStack();
                        msg.length = result;
                        var ptr = Memory.alloc(result);
                        for (var i = 0; i < result; i++) ptr.add(i).writeU8(bytes[offset + i] & 0xff);
                        send(msg, ptr.readByteArray(result));
                    }
                    return result;
                };
            send({type: "java_http_recv_hooked"});
        } catch(e) {}

        // Conscrypt SSL stack trace capture (Android 9+)
        try {
            if (parseFloat(Java.androidVersion) > 8) {
                Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream")
                    .write.overload("[B", "int", "int").implementation = function(b, off, len) {
                        var r = this.write(b, off, len);
                        SSLstackwrite = getStack();
                        return r;
                    };
                Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream")
                    .read.overload("[B", "int", "int").implementation = function(b, off, len) {
                        var r = this.read(b, off, len);
                        SSLstackread = getStack();
                        return r;
                    };
                send({type: "conscrypt_stack_hooked"});
            } else {
                Java.use("com.android.org.conscrypt.OpenSSLSocketImpl$SSLOutputStream")
                    .write.overload("[B", "int", "int").implementation = function(b, off, len) {
                        var r = this.write(b, off, len);
                        SSLstackwrite = getStack();
                        return r;
                    };
                Java.use("com.android.org.conscrypt.OpenSSLSocketImpl$SSLInputStream")
                    .read.overload("[B", "int", "int").implementation = function(b, off, len) {
                        var r = this.read(b, off, len);
                        SSLstackread = getStack();
                        return r;
                    };
                send({type: "openssl_stack_hooked"});
            }
        } catch(e) {}
    });
}

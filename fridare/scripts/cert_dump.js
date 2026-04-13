/**
 * Client certificate dump + SSL pinning locator
 * Based on r0capture cert dump functionality
 *
 * Features:
 * 1. Hooks KeyStore.PrivateKeyEntry to dump client certs as P12
 * 2. Detects SSL pinning check locations
 * 3. Dumps all trusted CAs from TrustManager
 */

"use strict";

Java.perform(function() {
    var Log = Java.use("android.util.Log");
    var Throwable = Java.use("java.lang.Throwable");

    function getStack() {
        return Log.getStackTraceString(Throwable.$new()).substring(0, 1200);
    }

    function uuid(len) {
        var chars = "0123456789abcdef";
        var result = "";
        for (var i = 0; i < (len || 16); i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    var pkgName = "";
    try {
        pkgName = Java.use("android.app.ActivityThread")
            .currentApplication().getApplicationContext().getPackageName();
    } catch(e) { pkgName = "unknown"; }

    // ── 1. Client certificate dump ────────────────────

    function storeP12(privateKey, cert, path, password) {
        try {
            var X509Cert = Java.use("java.security.cert.X509Certificate");
            var chain = Java.array("java.security.cert.X509Certificate",
                [Java.cast(cert, X509Cert)]);
            var ks = Java.use("java.security.KeyStore").getInstance("PKCS12", "BC");
            ks.load(null, null);
            ks.setKeyEntry("client", privateKey,
                Java.use("java.lang.String").$new(password).toCharArray(), chain);
            var out = Java.use("java.io.FileOutputStream").$new(path);
            ks.store(out, Java.use("java.lang.String").$new(password).toCharArray());
            out.close();
            return true;
        } catch(e) {
            send({type: "cert_dump_error", error: e.message});
            return false;
        }
    }

    try {
        var PKEntry = Java.use("java.security.KeyStore$PrivateKeyEntry");

        PKEntry.getPrivateKey.implementation = function() {
            var result = this.getPrivateKey();
            var p12Path = "/sdcard/Download/" + pkgName + "_" + uuid(8) + ".p12";
            var password = "frida-mcp";
            storeP12(result, this.getCertificate(), p12Path, password);
            send({
                type: "client_cert_dumped",
                path: p12Path,
                password: password,
                algorithm: result.getAlgorithm(),
                stack: getStack()
            });
            return result;
        };

        PKEntry.getCertificateChain.implementation = function() {
            var result = this.getCertificateChain();
            var p12Path = "/sdcard/Download/" + pkgName + "_chain_" + uuid(8) + ".p12";
            var password = "frida-mcp";
            storeP12(this.getPrivateKey(), this.getCertificate(), p12Path, password);
            send({
                type: "client_cert_chain_dumped",
                path: p12Path,
                password: password,
                chain_length: result.length,
                stack: getStack()
            });
            return result;
        };

        send({type: "cert_dump_hooked"});
    } catch(e) {
        send({type: "cert_dump_hook_failed", error: e.message});
    }

    // ── 2. SSL pinning locator ────────────────────────

    try {
        Java.use("java.io.File").$init
            .overload("java.io.File", "java.lang.String")
            .implementation = function(dir, name) {
                var result = this.$init(dir, name);
                var stack = getStack();
                if (dir.getPath().indexOf("cacert") >= 0 &&
                    stack.indexOf("checkServerTrusted") >= 0) {
                    send({
                        type: "ssl_pinning_detected",
                        path: dir.getPath() + "/" + name,
                        stack: stack
                    });
                }
                return result;
            };
        send({type: "pinning_locator_hooked"});
    } catch(e) {}

    // ── 3. TrustManager info dump ─────────────────────

    try {
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        TrustManagerFactory.getTrustManagers.implementation = function() {
            var result = this.getTrustManagers();
            var info = [];
            for (var i = 0; i < result.length; i++) {
                var tm = result[i];
                info.push({
                    index: i,
                    class: tm.getClass().getName(),
                });
            }
            send({
                type: "trust_managers",
                count: result.length,
                managers: info,
                stack: getStack()
            });
            return result;
        };
        send({type: "trustmanager_hooked"});
    } catch(e) {}

    // ── 4. Keystore load monitor ──────────────────────

    try {
        Java.use("java.security.KeyStore").load
            .overload("java.io.InputStream", "[C")
            .implementation = function(stream, password) {
                var result = this.load(stream, password);
                var pwd = password ? Java.use("java.lang.String").$new(password) : "null";
                var ksType = this.getType();
                send({
                    type: "keystore_loaded",
                    keystore_type: ksType,
                    has_password: password !== null,
                    password_hint: pwd.toString().substring(0, 20),
                    stack: getStack()
                });
                return result;
            };
        send({type: "keystore_load_hooked"});
    } catch(e) {}

    send({type: "cert_dump_ready", package: pkgName});
});

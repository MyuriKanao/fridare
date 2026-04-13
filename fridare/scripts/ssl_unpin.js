/**
 * SSL Pinning bypass — universal unpinner
 *
 * Bypasses:
 * 1. TrustManagerFactory → inject permissive TrustManager
 * 2. OkHttp CertificatePinner
 * 3. Conscrypt TrustManagerImpl
 * 4. WebView SSL errors
 * 5. Apache HttpClient
 * 6. Custom X509TrustManager implementations
 */

"use strict";

Java.perform(function() {
    var Log = Java.use("android.util.Log");

    // ── 1. Custom TrustManager that accepts everything ──

    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var X509Certificate = Java.use("java.security.cert.X509Certificate");

    var PassTrustManager = Java.registerClass({
        name: "com.frida.PassTrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() {
                return Java.array("java.security.cert.X509Certificate", []);
            }
        }
    });

    // ── 2. SSLContext.init — inject our TrustManager ──

    try {
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom")
            .implementation = function(km, tm, sr) {
                var ptm = Java.array("javax.net.ssl.TrustManager", [PassTrustManager.$new()]);
                this.init(km, ptm, sr);
                send({type: "ssl_unpin", target: "SSLContext.init"});
            };
    } catch(e) {}

    // ── 3. OkHttp CertificatePinner ──

    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function(hostname, peerCerts) {
                send({type: "ssl_unpin", target: "OkHttp3.CertificatePinner", hostname: hostname});
            };
    } catch(e) {}

    try {
        var CertPinner2 = Java.use("com.squareup.okhttp.CertificatePinner");
        CertPinner2.check.overload("java.lang.String", "java.util.List")
            .implementation = function(hostname, peerCerts) {
                send({type: "ssl_unpin", target: "OkHttp2.CertificatePinner", hostname: hostname});
            };
    } catch(e) {}

    // ── 4. Conscrypt TrustManagerImpl ──

    try {
        var TMImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TMImpl.verifyChain.implementation = function() {
            send({type: "ssl_unpin", target: "Conscrypt.verifyChain"});
            return arguments[0]; // return the untrusted chain as-is
        };
    } catch(e) {}

    // ── 5. WebViewClient SSL errors ──

    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
            send({type: "ssl_unpin", target: "WebViewClient.onReceivedSslError"});
        };
    } catch(e) {}

    // ── 6. HttpsURLConnection default ──

    try {
        var HttpsConn = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsConn.setDefaultHostnameVerifier.implementation = function(verifier) {
            // ignore custom verifier
            send({type: "ssl_unpin", target: "HttpsURLConnection.setDefaultHostnameVerifier"});
        };
    } catch(e) {}

    // ── 7. All X509TrustManager implementations ──

    try {
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        TrustManagerFactory.getTrustManagers.implementation = function() {
            var ptm = Java.array("javax.net.ssl.TrustManager", [PassTrustManager.$new()]);
            send({type: "ssl_unpin", target: "TrustManagerFactory.getTrustManagers"});
            return ptm;
        };
    } catch(e) {}

    send({type: "ssl_unpin_ready"});
});

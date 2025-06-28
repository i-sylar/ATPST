Java.perform(function () {
    console.log("[*] Starting protection detection and bypass script...");

    // --- Root Detection Bypass ---
    var RootPackages = [
        "com.noshufou.android.su",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.topjohnwu.magisk"
    ];

    var StringClass = Java.use("java.lang.String");
    var contains = StringClass.contains.overload("java.lang.CharSequence");

    contains.implementation = function (str) {
        for (var i = 0; i < RootPackages.length; i++) {
            if (str.toString().includes(RootPackages[i])) {
                console.log("[!] Root detection attempt detected! Bypassed: " + str);
                return false;
            }
        }
        return contains.call(this, str);
    };

    // --- Emulator Detection Bypass ---
    var Build = Java.use("android.os.Build");

    var emulatorProps = {
        FINGERPRINT: "generic",
        MODEL: "Pixel 5",
        MANUFACTURER: "Google",
        BRAND: "google",
        DEVICE: "pixel_5",
        PRODUCT: "pixel_5"
    };

    Object.keys(emulatorProps).forEach(function (prop) {
        try {
            Build[prop].value = emulatorProps[prop];
            console.log("[!] Emulator detection bypassed via Build." + prop);
        } catch (err) {
            console.log("[!] Failed to override Build." + prop);
        }
    });

    // --- SSL Pinning Bypass ---
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        var TrustManager = Java.registerClass({
            name: "com.sensepost.test.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {
                    console.log("[!] SSL pinning check detected and bypassed!");
                },
                getAcceptedIssuers: function () {
                    return [];
                }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        var TLSContext = SSLContext.getInstance("TLS");
        TLSContext.init(null, TrustManagers, null);
        SSLContext.setDefault(TLSContext);

        console.log("[*] SSL Pinning bypass in place.");
    } catch (e) {
        console.log("[!] SSL Pinning bypass setup failed: " + e.message);
    }

    // --- Debugger Detection ---
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
        console.log("[!] Debugger check detected. Returning false.");
        return false;
    };

    Debug.waitingForDebugger.implementation = function () {
        console.log("[!] Debugger wait check detected. Skipping.");
        return false;
    };

    // --- Frida Detection ---
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
        if (cmd.indexOf("frida") !== -1) {
            console.log("[!] Frida detection attempt detected. Command: " + cmd);
            return null;
        }
        return this.exec(cmd);
    };

    var SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload("java.lang.String").implementation = function (key) {
        if (key.toLowerCase().includes("frida")) {
            console.log("[!] SystemProperties check for Frida detected. Key: " + key);
            return "";
        }
        return this.get(key);
    };

    console.log("[*] Protection hooks installed.");
});

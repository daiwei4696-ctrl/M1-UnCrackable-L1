import Java from "frida-java-bridge";

Java.perform(function () {
    var c = Java.use("sg.vantagepoint.a.c");
    c.a.implementation = function () { console.log("[bypass] root check c.a() -> false"); return false; };
    c.b.implementation = function () { console.log("[bypass] root check c.b() -> false"); return false; };
    c.c.implementation = function () { console.log("[bypass] root check c.c() -> false"); return false; };

    var b = Java.use("sg.vantagepoint.a.b");
    b.a.overload("android.content.Context").implementation = function (ctx) {
        console.log("[bypass] debuggable check b.a(ctx) -> false");
        return false;
    };

    var aes = Java.use("sg.vantagepoint.a.a");
    aes.a.overload("[B", "[B").implementation = function (k, d) {
        var o = this.a(k, d);
        console.log("[*] AES decrypted secret => \"" + Java.use("java.lang.String").$new(o) + "\"");
        return o;
    };
    console.log("[+] hooks installed (root/debug bypass + AES trace)");
});

setTimeout(function () {
    Java.perform(function () {
        var Ck = Java.use("sg.vantagepoint.uncrackable1.a");
        console.log("[VERIFY] input 'I want to believe' -> " + Ck.a("I want to believe"));
        console.log("[VERIFY] input 'wrong guess'      -> " + Ck.a("wrong guess"));
        console.log("[DONE]");
    });
}, 3500);
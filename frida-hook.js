// Frida 17 标准写法：ESM import（不要再用全局 Java，也不要用 require('...') 拿 default）
import Java from "frida-java-bridge";

// 用法（在本目录，已 npm install frida-java-bridge）：
//   frida -U -f owasp.mstg.uncrackable1 -l frida-hook.js
Java.perform(function () {
    // 绕过 root 检测：sg.vantagepoint.a.c 的 a()/b()/c() 全部返回 false
    var c = Java.use("sg.vantagepoint.a.c");
    c.a.implementation = function () { console.log("[bypass] root c.a() -> false"); return false; };
    c.b.implementation = function () { console.log("[bypass] root c.b() -> false"); return false; };
    c.c.implementation = function () { console.log("[bypass] root c.c() -> false"); return false; };

    // 绕过 debuggable 检测：sg.vantagepoint.a.b.a(Context)
    var b = Java.use("sg.vantagepoint.a.b");
    b.a.overload("android.content.Context").implementation = function (ctx) {
        console.log("[bypass] debuggable b.a(ctx) -> false");
        return false;
    };

    // Hook AES 解密，直接打印明文
    var aes = Java.use("sg.vantagepoint.a.a");
    aes.a.overload("[B", "[B").implementation = function (key, data) {
        var out = this.a(key, data);
        console.log("[*] AES decrypted secret => \"" + Java.use("java.lang.String").$new(out) + "\"");
        return out;
    };

    // 可选：强制校验通过（点 verify 必 Success）
    var Check = Java.use("sg.vantagepoint.uncrackable1.a");
    Check.a.overload("java.lang.String").implementation = function (input) {
        console.log("[*] verify(" + input + ") -> force true");
        return true;
    };

    console.log("[+] UnCrackable L1 hooks installed.");
});
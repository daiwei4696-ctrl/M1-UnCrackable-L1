const crypto = require("crypto");
const key = Buffer.from("8d127684cbc37c17616d806cf50473cc", "hex");
const ct  = Buffer.from("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", "base64");
const d = crypto.createDecipheriv("aes-128-ecb", key, null);
d.setAutoPadding(true);
const pt = Buffer.concat([d.update(ct), d.final()]).toString();
console.log("key bytes (hex) :", key.toString("hex"), "len", key.length);
console.log("cipher bytes    :", ct.length, "len (blocks of 16)");
console.log(">>> secret plaintext:", pt);
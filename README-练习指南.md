# M1 实战 · OWASP UnCrackable Level 1

> Android 逆向入门靶场（OWASP MASTG 官方 Crackme）。
- 隐藏字符串：**`I want to believe`**（X 档案梗；输入它即 Success，root 检测需先绕过）。

## 目标信息
- APK：`UnCrackable-Level1.apk`（package `owasp.mstg.uncrackable1`）
- 主 Activity：`sg.vantagepoint.uncrackable1.MainActivity`
- jadx 反编译输出：`jadx-out/`（读 Java）
- apktool 解包输出：`apktool-out/`（smali + 资源 + Manifest）
- 静态验证脚本：`solve-static.js`（node solve-static.js）
- Frida 脚本（动态阶段）：`frida-hook.js`

## 已知结构（先读这些类）
- `sg/vantagepoint/uncrackable1/MainActivity.java`：入口。`onCreate` 里 `c.a()||c.b()||c.c()` 判 root → 弹框退出；`b.a(ctx)` 判可调试。
- `sg/vantagepoint/a/c.java`：root 检测三件套（su 路径 / Build 标签 / superuser APK）。
- `sg/vantagepoint/a/b.java`：debuggable 检测。
- `sg/vantagepoint/uncrackable1/a.java`：校验逻辑 `a.a(输入)`——用密钥 `8d127684cbc37c17616d806cf50473cc`（hex→16 字节）AES 解密 Base64 `5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=`，再和输入比对。
- `sg/vantagepoint/a/a.java`：AES 助手，`Cipher.getInstance("AES")` + `init(2=DECRYPT,...)` → AES/ECB/PKCS5。

## 任务（按顺序做，每步留证据截图）
1. **jadx 通读**：打开 `jadx-out`，从 MainActivity 跟到校验类，画出调用链。
2. **Manifest 审计**：看 `apktool-out/AndroidManifest.xml`（allowBackup / exported / debuggable）。
3. **静态求解**：识别算法是 AES-128-ECB，运行 `node solve-static.js` 得到明文凭据；自己用 Python/OpenSSL 再算一遍验证。
4. **改包（可选）**：在 smali 里把 root 检测或校验返回值改掉，apktool 重打包 + 签名 + 安装，看 App 行为变化。
5. **动态 Hook（需模拟器/真机，下一阶段）**：跑 `frida-hook.js`，绕 root 检测并打印解密明文。

## 提示（卡壳再看）
- root 检测在 `sg.vantagepoint.a.c` 的三个无参静态方法，全让它们返回 false 即可过；可调试检测 `sg.vantagepoint.a.b.a(Context)` 返回 false。
- 求明文有三条路：① 纯静态（拿到 key+密文本地解密）；② Frida hook AES 助手 `sg.vantagepoint.a.a.a([B,[B)` 打印返回值；③ Frida 直接 hook `uncrackable1.a.a(String)` 强制返回 true。
- Frida 命令（设备就绪后）：`frida -U -f owasp.mstg.uncrackable1 -l frida-hook.js`

## 答案（自检用）
- 隐藏字符串：**`I want to believe`**（X 档案梗；输入它即 Success，root 检测需先绕过）。
- 在输入框输入它 → Success!（root 检测需先绕过才能在模拟器上正常进界面）。

## Writeup #1 产出要求
- 工具命令 + 关键反编译截图 + 调用链说明 + 密钥/密文/算法 + 你的求解过程；放到 GitHub 仓库。

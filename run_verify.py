import frida, sys, time, os
here = os.path.dirname(os.path.abspath(__file__))
target = sys.argv[1] if len(sys.argv) > 1 else "verify-final.bundle.js"
js = open(os.path.join(here, target), encoding="utf-8").read()
def on_message(m, d):
    if m.get("type") in ("send","log"): print(m.get("payload"))
    else: print("[message]", m)
dev = frida.get_usb_device(timeout=10)
print("[host] device:", dev.name)
pid = dev.spawn(["owasp.mstg.uncrackable1"])
s = dev.attach(pid)
sc = s.create_script(js)
sc.on("message", on_message)
sc.load()
dev.resume(pid)
print("[host] app resumed, collecting output...")
time.sleep(9)
try: dev.kill(pid)
except: pass
print("[host] done")
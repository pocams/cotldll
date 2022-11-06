import base64
import hashlib
import json
from typing import List, Optional

from flask import Flask, abort, make_response, render_template, request

MAX_DLL_SIZE = 1024 * 1024 * 15
PATCH_FROM = b"\xfe\x06\xf3\x25\x00\x06"
PATCH_TO = b"\xfe\x06\xf5\x25\x00\x06"

app = Flask(__name__)


def load_dll(path: str) -> dict:
    with open(path, "rb") as f:
        dll = f.read()
    sha256 = hashlib.sha256(dll).hexdigest()
    return {
        "dll": dll,
        "sha256": sha256
    }


DLLS = {
    "mac": load_dll("dlls/mac/20221106-patched.dll"),
    "windows": load_dll("dlls/windows/20221106-patched.dll")
}


def hexdump(b: bytes) -> str:
    return " ".join("%02x" % (byte, ) for byte in b)


@app.route("/dlls/<platform>/Assembly-CSharp.dll")
def dll(platform: str):
    if platform in DLLS:
        return (
            DLLS[platform]["dll"],
            {
                "Content-Type": "application/octet-stream"
            }
        )
    else:
        abort(404)


def patch_dll() -> (Optional[bytes], List[str]):
    f = request.files.get("dll")
    if not f:
        return None, ["No file uploaded!"]

    if f.content_length > MAX_DLL_SIZE:
        return None, [f"Content length of {f.content_length} too big, giving up!"]

    log = []
    content = bytearray(f.stream.read(MAX_DLL_SIZE))
    log.append(f"Processing {f.filename} ({len(content)} bytes)")

    patch_count = 0
    while True:
        pos = content.find(PATCH_FROM)
        if pos == -1:
            break
        patch_count += 1
        log.append(f"Patching [{hexdump(PATCH_FROM)}] to [{hexdump(PATCH_TO)}] at position 0x{pos:x}")
        content[pos:pos+len(PATCH_FROM)] = PATCH_TO
        content = content.replace(PATCH_FROM, PATCH_FROM)

    if patch_count == 0:
        log.append(f"Target bytes {hexdump(PATCH_FROM)} not found!")
        return None, log

    if patch_count == 1:
        log.append("Patched 1 location, looks good!")
    else:
        log.append(f"Patched {patch_count} locations, possibly failed")

    return content, log


@app.route("/patch", methods=["POST"])
def patch():
    # Return the patched DLL as the body, and set a cookie with the output so the
    # client side can get it without making separate requests
    result, log = patch_dll()
    app.logger.info(f"Patch results: {log!r}")

    if result:
        resp = make_response(result, {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": 'attachment; filename="Assembly-CSharp.dll"'
        })
    else:
        resp = make_response("", 204)

    cookie = {"status": ("ok" if result else "error"), "log": log}
    resp.set_cookie("log", base64.b64encode(json.dumps(cookie).encode("utf-8")).decode("ascii"))
    return resp


@app.route('/')
def index():
    return render_template("index.html.j2", dlls=DLLS)


if __name__ == '__main__':
    app.run()

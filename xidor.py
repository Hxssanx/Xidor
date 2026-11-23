import argparse
import concurrent.futures
import difflib
import hashlib
import json
import os
import re
import threading
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
lock = threading.Lock()
SUS_KEYS = {
    "id", "user", "user_id", "userid", "email", "username", "name",
    "phone", "mobile", "address", "role", "account", "profile",
    "order", "invoice", "balance", "token", "secret", "data"
}
ERR_REGEX = [
    r"not found", r"does not exist", r"invalid id", r"access denied",
    r"unauthorized", r"forbidden", r"permission denied", r"login", r"sign in",
]
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?")
def log(msg: str) -> None:
    with lock:
        print(msg)
def read_lines(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            out = []
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                out.append(s)
            return out
    except OSError as e:
        log(f"[-] couldn't read {path}: {e}")
        return []
def make_session(workers: int) -> requests.Session:
    s = requests.Session()
    pool = max(20, workers * 2)
    retry = Retry(
        total=2,
        backoff_factor=0.2,
        status_forcelist=[429, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(pool_connections=pool, pool_maxsize=pool, max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s
def set_param(url: str, key: str, val: str) -> str:
    u = urlsplit(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q[key] = val
    return urlunsplit((u.scheme, u.netloc, u.path, urlencode(q), u.fragment))
def grab_keys(data, prefix: str = "") -> set[str]:
    found = set()
    if isinstance(data, dict):
        for k, v in data.items():
            k_str = str(k).lower()
            full = f"{prefix}.{k_str}" if prefix else k_str
            found.add(k_str)
            found.add(full)
            found.update(grab_keys(v, full))
    elif isinstance(data, list):
        for item in data[:10]:
            found.update(grab_keys(item, prefix))
    return found
def clean_body(text: str) -> str:
    text = UUID_RE.sub("<UUID>", text)
    text = TS_RE.sub("<TS>", text)
    return text.strip()
def inspect_resp(resp: requests.Response) -> dict:
    raw = resp.content or b""
    txt = resp.text or ""
    norm = clean_body(txt)
    digest = hashlib.sha256(norm.encode("utf-8", errors="ignore")).hexdigest()
    errs = [p for p in ERR_REGEX if re.search(p, txt.lower())]
    is_json = False
    keys = set()
    try:
        parsed = resp.json()
        is_json = True
        keys = grab_keys(parsed)
    except ValueError:
        pass
    hits = sorted(k for k in keys if any(w in k for w in SUS_KEYS))
    return {
        "status": resp.status_code,
        "size": len(raw),
        "hash": digest,
        "norm": norm,
        "is_json": is_json,
        "hits": hits,
        "errs": errs,
    }
def sim(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()
def check_result(url: str, info: dict, base: dict | None, ref: dict | None, skip_word: str):
    if skip_word and skip_word.lower() in info["norm"].lower():
        return None
    code = info["status"]
    if code in (401, 403):
        return "AUTH", f"[!] [{code}] {url} | {info['size']}B"
    if code != 200 or info["size"] == 0:
        return None
    if info["errs"] and not info["hits"]:
        return None
    if base and info["hash"] == base["hash"]:
        return None
    if ref and info["hash"] == ref["hash"]:
        return "REF", f"[~] [same as ref] {url} | {info['size']}B"
    r_base = sim(info["norm"], base["norm"]) if base else 0.0
    r_ref = sim(info["norm"], ref["norm"]) if ref else 0.0
    score = 0
    why = []
    if info["hits"]:
        score += 2
        why.append(f"keys={','.join(info['hits'][:5])}")
    if info["is_json"] and not info["errs"]:
        score += 1
        why.append("json")
    if base and r_base < 0.90:
        score += 1
        why.append(f"base_diff={r_base:.2f}")
    if ref and 0.15 < r_ref < 0.98:
        score += 2
        why.append(f"ref_diff={r_ref:.2f}")
    tag = ", ".join(why)
    if score >= 3:
        return "HIT", f"[+] [likely idor | score={score}] {url} | {info['size']}B | {tag}"
    if score >= 1:
        return "MAYBE", f"[*] [interesting | score={score}] {url} | {info['size']}B | {tag}"
    return None
def hit_url(sess: requests.Session, url: str, headers: dict[str, str], timeout: float = 6.0) -> dict | None:
    try:
        r = sess.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        return inspect_resp(r)
    except requests.exceptions.RequestException:
        return None
def make_headers(raw_list: list[str]) -> dict[str, str]:
    hdrs = {"User-Agent": "xidor/1.3"}
    for raw in raw_list:
        if ":" in raw:
            k, v = raw.split(":", 1)
            if k.strip():
                hdrs[k.strip()] = v.strip()
    return hdrs
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IDOR parameter and value discovery helper")
    parser.add_argument("-u", "--url", help="Target base URL")
    parser.add_argument("-k", "--keys", default="parakeys.txt", help="Parameter keys wordlist")
    parser.add_argument("-w", "--values", default="valuepatterns.txt", help="Parameter values wordlist")
    parser.add_argument("-r", "--ref", default="", help="Reference ID value")
    parser.add_argument("-s", "--skip", default="", help="Ignore responses containing text")
    parser.add_argument("-H", "--header", action="append", default=[], help="Header in Name:Value format")
    parser.add_argument("-t", "--threads", type=int, default=15, help="Worker threads (1-60)")
    parser.add_argument("-o", "--output", default="", help="Save interesting hits to JSON file")
    return parser.parse_args()
def run() -> None:
    args = parse_args()
    print("=== xidor ===")
    target = (args.url or input("Base URL: ")).strip()
    p = urlsplit(target)
    if p.scheme not in ("http", "https") or not p.netloc:
        print("[-] bad url")
        return
    key_path = args.keys if args.url else (input("Keys file [parakeys.txt]: ").strip() or "parakeys.txt")
    val_path = args.values if args.url else (input("Values file [valuepatterns.txt]: ").strip() or "valuepatterns.txt")
    if not os.path.isfile(key_path) or not os.path.isfile(val_path):
        print("[-] missing wordlists")
        return
    ref_val = args.ref if args.url else input("Ref ID (optional): ").strip()
    skip_word = args.skip if args.url else input("Ignore text (optional): ").strip()
    raw_hdrs = list(args.header)
    if not args.url and not raw_hdrs:
        single_hdr = input("Header Name:Val (optional): ").strip()
        if single_hdr:
            raw_hdrs.append(single_hdr)
    hdrs = make_headers(raw_hdrs)
    raw_threads = args.threads if args.url else (input("Threads [15]: ").strip() or "15")
    try:
        threads = max(1, min(int(raw_threads), 60))
    except ValueError:
        threads = 15
    keys = read_lines(key_path)
    vals = read_lines(val_path)
    if not keys or not vals:
        print("[-] empty wordlists")
        return
    sess = make_session(threads)
    base_url = set_param(target, keys[0], "__xidor_nope_987654321__")
    base = hit_url(sess, base_url, hdrs)
    if base:
        print(f"[+] base: {base['status']} ({base['size']}B)")
    else:
        print("[-] no baseline")
    ref = None
    if ref_val:
        ref_url = set_param(target, keys[0], ref_val)
        ref = hit_url(sess, ref_url, hdrs)
        if ref:
            print(f"[+] ref ({ref_val}): {ref['status']} ({ref['size']}B)")
    combos = [set_param(target, k, v) for k in keys for v in vals]
    print(f"[+] firing {len(combos)} requests...\n")
    interesting = []
    def task(u: str) -> None:
        info = hit_url(sess, u, hdrs)
        if not info:
            return
        res = check_result(u, info, base, ref, skip_word)
        if not res:
            return
        kind, line = res
        log(line)
        if kind in ("HIT", "MAYBE"):
            with lock:
                interesting.append({
                    "kind": kind,
                    "url": u,
                    "status": info["status"],
                    "size": info["size"],
                    "keys": info["hits"],
                })
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futs = [ex.submit(task, u) for u in combos]
            for fut in concurrent.futures.as_completed(futs):
                try:
                    fut.result()
                except Exception as e:
                    log(f"[-] worker error: {e}")
    except KeyboardInterrupt:
        print("\n[!] bailed out early")
    finally:
        sess.close()
    if args.output and interesting:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(interesting, f, indent=2)
            print(f"[+] saved {len(interesting)} results to {args.output}")
        except OSError as e:
            print(f"[-] failed to write {args.output}: {e}")
    print(f"\n[+] done. {len(interesting)} interesting hits.")
if __name__ == "__main__":
    run()
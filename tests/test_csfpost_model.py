"""Round-trip and editing tests for csf_backend.csfpost_model.

Run from the project root:  python tests/test_csfpost_model.py
"""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
FIX = os.path.join(HERE, "fixtures")

from csf_backend import csfpost_model as M

src = open(os.path.join(FIX, "csfpost_mixed.sh"), encoding="utf-8").read()
live = open(os.path.join(FIX, "csfpost_managed.sh"), encoding="utf-8").read()

fails = []
def check(name, cond, extra=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + (("  " + extra) if extra and not cond else ""))
    if not cond:
        fails.append(name)

def nodes_by(doc, pred):
    return [n for n in M._walk(doc["nodes"]) if pred(n)]

print("\n== round trip ==")
for label, text in (("sample", src), ("live", live)):
    check("round-trip " + label, M.serialize(M.parse(text)) == text)
check("round-trip empty", M.serialize(M.parse("")) == "")
check("round-trip newline only", M.serialize(M.parse("\n")) == "\n")
check("round-trip no trailing nl", M.serialize(M.parse("iptables -A INPUT -j DROP")) == "iptables -A INPUT -j DROP")
check("round-trip crlf-free mixed", M.serialize(M.parse("a\n\n\nb\n")) == "a\n\n\nb\n")

print("\n== token-level field edit preserves odd spacing ==")
doc = M.parse(src)
n = [x for x in M._walk(doc["nodes"]) if x.get("kind")=="rule" and "-I INPUT  1 -i tun-ucm" in x["text"]][0]
out = M.apply_op(src, "update_rule", {"id": n["id"], "updates": {"src": "2001:db8::1"}})
line = [l for l in out.split("\n") if "-I INPUT" in l and "tun-ucm" in l][0]
check("double-space alignment kept", "iptables  -I INPUT  1 " in line, repr(line))
check("src inserted before -j", "-s 2001:db8::1 -j ACCEPT" in line, repr(line))
check("rest of file untouched", out.count("\n") == src.count("\n"))

print("\n== edit a multiline rule inside a heredoc ==")
doc = M.parse(src)
n = [x for x in M._walk(doc["nodes"]) if x.get("kind")=="rule" and x["spec"]["target"]=="DNAT"][0]
out = M.apply_op(src, "update_rule", {"id": n["id"], "updates": {"dport": "9096", "to_destination": "10.12.10.99:9096"}})
check("continuation layout kept", "iptables -t nat -A PREROUTING \\\n  -i enp3s0 \\\n  -p tcp --dport 9096 \\\n  -j DNAT --to-destination 10.12.10.99:9096" in out,
      repr(out[out.find("PREROUTING"):out.find("PREROUTING")+140]))

print("\n== edit a guarded check-then-add rule (both halves) ==")
# The live script keeps these rules in a section CSF-eUI maintains, and those
# are refused on purpose (see the managed-section test below). Rename the
# markers so this exercises the editing path rather than the guard.
live_mine = live.replace("CSFV2-DOCKER-FORWARDING", "MY-DOCKER-RULES")
doc = M.parse(live_mine)
n = [x for x in M._walk(doc["nodes"]) if x.get("kind")=="rule" and x["guard"]=="check-then-add" and x["spec"]["fields"].get("in_iface")][0]
out = M.apply_op(live_mine, "update_rule", {"id": n["id"], "updates": {"target": "RETURN"}})
seg = [l for l in out.split("\n") if "-C FORWARD -i" in l][0]
check("guard half updated", "-j RETURN" in seg, repr(seg))
check("insert half updated", out.count("-i \"$IFACE\" -j RETURN") == 2, str(out.count('-j RETURN')))
check("position only on insert half", "-C FORWARD 1" not in out)

print("\n== disable / enable round trip ==")
doc = M.parse(src)
n = [x for x in M._walk(doc["nodes"]) if x.get("kind")=="rule" and not x["disabled"]][0]
off = M.apply_op(src, "toggle", {"id": n["id"]})
check("disabled line commented", "# iptables -I FORWARD 1 -i wt0 -j ACCEPT" in off)
doc2 = M.parse(off)
n2 = [x for x in M._walk(doc2["nodes"]) if x.get("kind")=="rule" and x["disabled"] and "wt0 -j ACCEPT" in x["text"]][0]
on = M.apply_op(off, "toggle", {"id": n2["id"]})
check("re-enable restores original", on == src, repr(on[:120]))

doc = M.parse(src)
n = [x for x in M._walk(doc["nodes"]) if x.get("kind")=="rule" and x["disabled"] and x["multiline"]][0]
on = M.apply_op(src, "toggle", {"id": n["id"]})
check("multiline ### rule enables all lines", "iptables -t nat -A POSTROUTING \\\n  -o wt0 \\\n  -p tcp -d 10.12.10.12 --dport 8096 \\\n  -j MASQUERADE" in on)

print("\n== move / delete / duplicate ==")
doc = M.parse(src)
rules = [x for x in M._walk(doc["nodes"]) if x.get("kind")=="rule"]
out = M.apply_op(src, "delete", {"id": rules[0]["id"]})
check("delete removes one line", out.count("\n") == src.count("\n") - 1)
check("delete removed the right line", "\niptables -I FORWARD 1 -i wt0 -j ACCEPT\n" not in out)
out = M.apply_op(src, "duplicate", {"id": rules[0]["id"]})
check("duplicate adds the line again", out.count("iptables -I FORWARD 1 -i wt0 -j ACCEPT") == 3)
out = M.apply_op(src, "move", {"id": rules[1]["id"], "direction": "up"})
i_a = out.find("iptables -I FORWARD 1 -o wt0")
i_b = out.find("iptables -I FORWARD 1 -i wt0")
check("move up swaps order", 0 < i_a < i_b, "%d %d" % (i_a, i_b))

print("\n== managed sections are protected ==")
doc = M.parse(live)
sec = [x for x in M._walk(doc["nodes"]) if x.get("kind")=="section" and x["managed"]][0]
try:
    M.apply_op(live, "delete", {"id": sec["id"]})
    check("managed section delete refused", False)
except M.EditError as e:
    check("managed section delete refused", True)

print("\n== builder: render every shape in the sample ==")
cases = [
 ({"family":"ipv4","op":"insert","chain":"FORWARD","position":"1","fields":{"in_iface":"wt0"},"target":"ACCEPT"},
  "iptables -I FORWARD 1 -i wt0 -j ACCEPT"),
 ({"family":"ipv4","op":"insert","chain":"FORWARD","position":"1","fields":{"out_iface":"wt0","state":"ESTABLISHED,RELATED"},"target":"ACCEPT"},
  "iptables -I FORWARD 1 -o wt0 -m state --state ESTABLISHED,RELATED -j ACCEPT"),
 ({"family":"ipv4","table":"nat","op":"append","chain":"POSTROUTING","fields":{"src":"100.0.0.0/8","out_iface":"enp3s0"},"target":"MASQUERADE"},
  "iptables -t nat -A POSTROUTING -o enp3s0 -s 100.0.0.0/8 -j MASQUERADE"),
 ({"family":"ipv6","op":"append","chain":"UCMFWD","fields":{"in_iface":"enp3s0","out_iface":"tun-ucm","dst":"$UCM6","proto":"tcp","dports":"8089,8090"},"target":"ACCEPT"},
  "ip6tables -A UCMFWD -i enp3s0 -o tun-ucm -p tcp -d $UCM6 -m multiport --dports 8089,8090 -j ACCEPT"),
 ({"family":"ipv6","op":"new-chain","chain":"UCMFWD","guard":"create-or-flush"},
  "ip6tables -N UCMFWD 2>/dev/null || ip6tables -F UCMFWD"),
 ({"family":"ipv4","table":"nat","op":"append","chain":"PREROUTING","fields":{"in_iface":"enp3s0","proto":"tcp","dport":"8096","to_destination":"10.12.10.12:8096"},"target":"DNAT"},
  "iptables -t nat -A PREROUTING -i enp3s0 -p tcp -m tcp --dport 8096 -j DNAT --to-destination 10.12.10.12:8096"),
 ({"family":"ipv4","op":"insert","chain":"FORWARD","position":"1","fields":{"in_iface":"$IFACE"},"target":"ACCEPT","guard":"check-then-add"},
  "iptables -C FORWARD -i $IFACE -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i $IFACE -j ACCEPT"),
 ({"family":"ipv6","op":"append","chain":"UCMFWD","fields":{"in_iface":"enp3s0","out_iface":"tun-ucm","dst":"$UCM6","ctstate":"ESTABLISHED,RELATED"},"target":"ACCEPT"},
  "ip6tables -A UCMFWD -i enp3s0 -o tun-ucm -d $UCM6 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"),
]
for spec, want in cases:
    got = M.render_rule(spec)
    check("render " + want[:52], got == want, "\n        got:  %s\n        want: %s" % (got, want))

print("\n== generated rules re-parse to the same meaning ==")
for spec, want in cases:
    d = M.parse(M.render_rule(spec) + "\n")
    rn = [x for x in M._walk(d["nodes"]) if x.get("kind")=="rule"]
    check("reparse " + want[:40], len(rn) == 1 and not rn[0]["unknown"],
          str([x.get("kind") for x in d["nodes"]]) + str(rn[0]["unknown"] if rn else ""))

print("\n== validation ==")
check("missing chain rejected", M.validate_spec({"op":"append","target":"ACCEPT"}) != "")
check("missing target rejected", M.validate_spec({"op":"append","chain":"INPUT"}) != "")
check("port without proto rejected", M.validate_spec({"op":"append","chain":"INPUT","target":"ACCEPT","fields":{"dport":"80"}}) != "")
check("DNAT outside nat rejected", M.validate_spec({"op":"append","chain":"INPUT","target":"DNAT","fields":{"to_destination":"1.2.3.4"}}) != "")
check("valid spec accepted", M.validate_spec({"op":"append","chain":"INPUT","target":"ACCEPT","table":"filter","fields":{"proto":"tcp","dport":"80"}}) == "")

print("\n== add_rule / add_section / add_comment ==")
out = M.apply_op(src, "add_rule", {"spec": {"family":"ipv4","op":"append","chain":"INPUT","fields":{"proto":"tcp","dport":"8750"},"target":"ACCEPT"}, "comment": "CSF-eUI web port"})
check("add_rule appends with comment", out.endswith("# CSF-eUI web port\niptables -A INPUT -p tcp -m tcp --dport 8750 -j ACCEPT\n"), repr(out[-120:]))
check("add_rule left the rest alone", out.startswith(src))
sec = [x for x in M._walk(M.parse(src)["nodes"]) if x.get("kind")=="section"][0]
out = M.apply_op(src, "add_rule", {"spec": {"family":"ipv6","op":"append","chain":"UCMFWD","fields":{"proto":"udp","dport":"5070"},"target":"ACCEPT"}, "section_id": sec["id"]})
check("add_rule into a section", "--dport 5070 -j ACCEPT\n# END UCM6302 OpenVPN" in out, repr(out[out.find("5070")-60:out.find("5070")+80]))
out = M.apply_op(src, "add_section", {"label": "Jellyfin"})
check("add_section creates markers", "# BEGIN Jellyfin\n# END Jellyfin" in out)
d2 = M.parse(out)
check("new section parses back", any(x.get("kind")=="section" and x["label"]=="Jellyfin" for x in M._walk(d2["nodes"])))

print("\n== export / import ==")
b = M.export_bundle(src, "csfpost", "serverA")
check("bundle has items", len(b["items"]) > 10)
check("bundle summary counts rules", b["summary"]["rules"] == len([x for x in M._walk(M.parse(src)["nodes"]) if x.get("kind")=="rule"]))
restored = M.import_bundle("#!/bin/sh\n", b, mode="replace")
check("replace restores byte-identical", restored == src, repr(restored[:80]))
merged = M.import_bundle(src, b, mode="merge")
check("merge into itself adds nothing but disabled", "BEGIN imported from serverA" in merged)
fresh = M.import_bundle("#!/bin/sh\n", b, mode="append")
check("append wraps in a marked section", "# BEGIN imported from serverA" in fresh and "# END imported from serverA" in fresh)
d3 = M.parse(fresh)
imported_rules = [x for x in M._walk(d3["nodes"]) if x.get("kind")=="rule"]
orig_rules = [x for x in M._walk(M.parse(src)["nodes"]) if x.get("kind")=="rule"]
check("append carried every rule across", len(imported_rules) == len(orig_rules), "%d vs %d" % (len(imported_rules), len(orig_rules)))
partial = '#!/bin/sh\n\n# already here\niptables -I FORWARD 1 -i wt0 -j ACCEPT\niptables -t nat -A POSTROUTING -s 100.0.0.0/8 -o enp3s0 -j MASQUERADE\n'
m2 = M.import_bundle(partial, b, mode="merge")
ACTIVE_DUP = "\niptables -I FORWARD 1 -i wt0 -j ACCEPT\n"   # leading \n so ###-disabled copies do not match
check("merge skips rules the target already has", m2.count(ACTIVE_DUP) == 1, str(m2.count(ACTIVE_DUP)))
check("merge leaves no heading stranded by a skipped rule", "# NAT NetBird CGNAT range\n\n" not in m2.split("# BEGIN imported")[1].replace("##", "@@"))
check("merge still brings the disabled copies", "###iptables -t nat -A POSTROUTING -s 100.0.0.0/8 -o ens3" in m2)
check("merge keeps the section intact", "# BEGIN UCM6302 OpenVPN" in m2 and "# END UCM6302 OpenVPN" in m2)
check("merged file parses cleanly", M.serialize(M.parse(m2)) == m2)

lb = M.export_bundle(live, "csfpost", "serverB")
try:
    nm = M.import_bundle("#!/bin/sh\n", lb, mode="append")
    check("managed sections not pushed to another server", "CSFV2-DOCKER-FORWARDING" not in nm and "csfv2-exposure" not in nm, nm)
except M.EditError as e:
    check("managed sections not pushed to another server", "rebuilds" in str(e), str(e))
mixed = M.export_bundle(live.replace("# END CSFV2-DOCKER-FORWARDING", "# END CSFV2-DOCKER-FORWARDING\n\n# keep me\niptables -A INPUT -p tcp -m tcp --dport 9999 -j ACCEPT"), "csfpost", "serverB")
nm2 = M.import_bundle("#!/bin/sh\n", mixed, mode="append")
check("managed sections stripped, user rules kept", "CSFV2-DOCKER-FORWARDING" not in nm2 and "--dport 9999" in nm2, nm2)
try:
    M.import_bundle(src, {"format": "nope"}, "append")
    check("bad bundle refused", False)
except M.EditError:
    check("bad bundle refused", True)

print("\n== clearing a field drops the -m module it loaded ==")
doc = M.parse(src)
n = [x for x in M._walk(doc["nodes"]) if x.get("kind")=="rule" and "-o wt0 -m state" in x["text"] and not x["disabled"]][0]
out = M.apply_op(src, "update_rule", {"id": n["id"], "updates": {"neg_out_iface": True, "state": "", "proto": "tcp", "dport": "443"}})
got = [l for l in out.split("\n") if "FORWARD 1 !" in l][0]
check("negate + clear + add in one edit", got == "iptables -I FORWARD 1 ! -o wt0 -p tcp -m tcp --dport 443 -j ACCEPT", repr(got))
n2 = [x for x in M._walk(doc["nodes"]) if x.get("kind")=="rule" and "multiport" in x["text"] and not x["disabled"]][0]
o2 = M.apply_op(src, "update_rule", {"id": n2["id"], "updates": {"dports": "", "dport": "8089"}})
check("-m multiport dropped with --dports", "-m multiport" not in [l for l in o2.split("\n") if "8089" in l and not l.lstrip().startswith("#")][0])
n3 = [x for x in M._walk(doc["nodes"]) if x.get("kind")=="rule" and "conntrack" in x["text"]][0]
o3 = M.apply_op(src, "update_rule", {"id": n3["id"], "updates": {"ctstate": ""}})
check("-m conntrack dropped with --ctstate", "-m conntrack" not in o3)

print("\n== negation on both halves of a guarded rule ==")
d2 = M.parse(live_mine)
n4 = [x for x in M._walk(d2["nodes"]) if x.get("kind")=="rule" and x["spec"]["target"]=="MASQUERADE"][0]
o4 = M.apply_op(live_mine, "update_rule", {"id": n4["id"], "updates": {"neg_out_iface": False}})
check("negation removed from check and insert halves", "! -o" not in o4 and o4.count('-o "$IFACE" -j MASQUERADE') == 2)

print("\n== table flag added and removed cleanly ==")
n5 = [x for x in M._walk(M.parse(src)["nodes"]) if x.get("kind")=="rule" and x["text"].strip()=="iptables -I FORWARD 1 -i wt0 -j ACCEPT"][0]
o5 = M.apply_op(src, "update_rule", {"id": n5["id"], "updates": {"table": "mangle"}})
check("table flag inserted", "iptables -t mangle -I FORWARD 1 -i wt0 -j ACCEPT" in o5)
n6 = [x for x in M._walk(M.parse(o5)["nodes"]) if x.get("kind")=="rule" and "mangle" in x["text"]][0]
o6 = M.apply_op(o5, "update_rule", {"id": n6["id"], "updates": {"table": "filter"}})
check("table flag removed again, file identical", o6 == src)

print("\n== rules parked inside a heredoc do not count as applied ==")
s = M.summarize(M.parse(src))
check("parked rules split out of active", (s["active"], s["disabled"], s["parked"], s["rules"]) == (21, 6, 4, 31),
      str((s["active"], s["disabled"], s["parked"], s["rules"])))
hd = [x for x in M._walk(M.parse(src)["nodes"]) if x.get("kind")=="heredoc"][0]
un = M.apply_op(src, "unwrap", {"id": hd["id"]})
s2 = M.summarize(M.parse(un))
check("activating the block promotes its rules", s2["active"] == 24 and s2["parked"] == 0,
      str((s2["active"], s2["parked"])))
check("activating the block drops only the wrapper", "<<COMMENT" not in un and "\nCOMMENT\n" not in un and "--to-destination 10.12.10.12:8096" in un)
check("commented rule inside the block stays commented", "#iptables -t nat -A POSTROUTING \\" in un)

print("\n== loops and conditions read as plain English and edit as a form ==")
ui_live = M.doc_to_ui(M.parse(live))
flat = []
def _flatten(ns):
    for x in ns:
        flat.append(x); _flatten(x.get("children") or [])
_flatten(ui_live)
blocks = [b for b in flat if b["kind"] == "block"]
check("every block carries a description", all(b["description"] for b in blocks), str(len(blocks)))
loop = [b for b in blocks if b.get("parts", {}).get("var") == "SUBNET"][0]
check("for-loop offers a form", loop["form"] == "for" and loop["editable"])
check("for-loop names its variable", "$SUBNET" in loop["description"], loop["description"])
cond = [b for b in blocks if b["block_type"] == "if"][0]
check("if-block offers a condition form", cond["form"] == "cond" and cond["parts"]["cond"])

print("\n== structured edits touch exactly one line ==")
def _flat_of(text):
    out = []
    def walk(ns):
        for x in ns:
            out.append(x); walk(x.get("children") or [])
    walk(M.doc_to_ui(M.parse(text)))
    return out
fm = _flat_of(live_mine)

blk = [b for b in fm if b["kind"] == "block" and b.get("parts", {}).get("var") == "SUBNET"][0]
out = M.apply_op(live_mine, "update_block", {"id": blk["id"], "parts": {"var": "NET", "items": "$MY_NETS"}})
check("loop head rewritten", "for NET in $MY_NETS; do" in out)
check("only the head changed", sum(1 for a, b in zip(live_mine.split("\n"), out.split("\n")) if a != b) == 1)

v = [x for x in fm if x["kind"] == "var" and x["name"] == "DOCKER_VERSION"][0]
out = M.apply_op(live_mine, "update_var", {"id": v["id"], "name": "DVER", "value": v["value"]})
check("rename keeps the author's quoting",
      'DVER="$(docker version --format \'{{.Server.Version}}\' 2>/dev/null || true)"' in out)

v2 = [x for x in fm if x["kind"] == "var" and x["name"] == "DOCKER_IFACES"][0]
out = M.apply_op(live_mine, "update_var", {"id": v2["id"], "name": "DOCKER_IFACES", "value": "docker0 br0"})
check("a value with spaces is quoted", 'DOCKER_IFACES="docker0 br0"' in out)

fs = _flat_of(src)
c = [x for x in fs if x["kind"] == "comment" and "\n" not in x["raw"]][0]
out = M.apply_op(src, "update_text", {"id": c["id"], "text": "Keep container traffic working."})
check("comment reworded with its hash kept", "# Keep container traffic working." in out)
check("comment edit changed one line",
      sum(1 for a, b in zip(src.split("\n"), out.split("\n")) if a != b) == 1 and
      len(out.split("\n")) == len(src.split("\n")))

out = M.apply_op(live_mine, "replace_raw", {"id": blk["id"], "text": "# removed"})
check("replace_raw on a block really replaces it",
      "# removed" in out and "for SUBNET in" not in out)

print("\n== sections CSF-eUI maintains are refused, not just hidden ==")
fl = _flat_of(live)
inner = [x for x in fl if x["kind"] == "rule" and x["target"] == "MASQUERADE"][0]
for op, payload in (("update_rule", {"updates": {"target": "RETURN"}}),
                    ("toggle", {}), ("delete", {}), ("replace_raw", {"text": "x"})):
    payload["id"] = inner["id"]
    try:
        M.apply_op(live, op, payload)
        check("managed %s refused" % op, False, "it was allowed")
    except M.EditError:
        check("managed %s refused" % op, True)

print("\n== shell substitutions stay out of the suggestion lists ==")
s_live = M.summarize(M.parse(live))
check("no $VAR interfaces", not [i for i in s_live["interfaces"] if "$" in i], str(s_live["interfaces"]))
check("no $VAR chains", not [c for c in s_live["chains"] if "$" in c], str(s_live["chains"]))
check("no $VAR targets", not [t for t in s_live["targets"] if "$" in t], str(s_live["targets"]))

print("\n== ui projection is json-serialisable ==")
ui = M.doc_to_ui(M.parse(src))
try:
    json.dumps(ui); ok = True
except TypeError as e:
    ok = False; print(e)
check("doc_to_ui -> json", ok)
check("summary json", bool(json.dumps(M.summarize(M.parse(live)))))

print("\n%s  (%d failures)" % ("ALL PASS" if not fails else "FAILURES: " + ", ".join(fails), len(fails)))
sys.exit(1 if fails else 0)

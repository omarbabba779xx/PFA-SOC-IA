#!/usr/bin/env python3
"""
Fusionne les enregistrements auditd multi-lignes (SYSCALL + EXECVE + CWD + PATH + PROCTITLE,
lies par le meme identifiant audit(...)) en une seule ligne, au format attendu par le decodeur
auditd natif de Wazuh (voir /var/ossec/ruleset/decoders/0040-auditd_decoders.xml, qui documente
explicitement ce format fusionne en exemple mais ne le produit pas lui-meme a partir du
/var/log/audit/audit.log brut, qui reste multi-lignes). Sans cette fusion, le champ EXECVE
(arguments reels de la commande) n'est jamais rattache a l'evenement SYSCALL correspondant,
et reste invisible du champ full_log transmis au LLM.

Tourne en continu (tail -f), ecrit les lignes fusionnees dans /var/log/audit/audit-merged.log,
surveille par un <localfile> dedie dans ossec.conf.
"""
import os
import re
import sys
import time

SRC = "/var/log/audit/audit.log"
DST = "/var/log/audit/audit-merged.log"
FLUSH_TIMEOUT = 2.0
STAT_CHECK_INTERVAL = 5.0

id_re = re.compile(r"msg=audit\(([\d.]+:\d+)\)")


def open_src():
    f = open(SRC, "r")
    f.seek(0, 2)
    return f


def main():
    buffers = {}
    f = open_src()
    try:
        src_ino = os.fstat(f.fileno()).st_ino
    except OSError:
        src_ino = None
    last_stat_check = time.time()
    with open(DST, "a", buffering=1) as out:
        while True:
            line = f.readline()
            if not line:
                now = time.time()
                # auditd rotates audit.log (size/logrotate) - detect via inode change
                # and reopen, since a stale file handle would otherwise silently stop
                # seeing new data forever while still reporting as "running".
                if now - last_stat_check > STAT_CHECK_INTERVAL:
                    last_stat_check = now
                    try:
                        cur_ino = os.stat(SRC).st_ino
                    except OSError:
                        cur_ino = src_ino
                    if cur_ino != src_ino:
                        f.close()
                        f = open_src()
                        src_ino = cur_ino
                for aid, (parts, last_seen) in list(buffers.items()):
                    if now - last_seen > FLUSH_TIMEOUT:
                        out.write(" ".join(parts) + "\n")
                        del buffers[aid]
                time.sleep(0.3)
                continue
            line = line.rstrip("\n")
            m = id_re.search(line)
            if not m:
                continue
            aid = m.group(1)
            parts, _ = buffers.get(aid, ([], 0))
            parts.append(line)
            buffers[aid] = (parts, time.time())


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Fusionne les enregistrements auditd multi-lignes (SYSCALL + EXECVE + CWD + PATH + PROCTITLE,
lies par le meme identifiant audit(...)) en une seule ligne, au format attendu par le decodeur
auditd natif de Wazuh (voir /var/ossec/ruleset/decoders/0040-auditd_decoders.xml, qui documente
explicitement ce format fusionne en exemple mais ne le produit pas lui-meme a partir du
/var/log/audit/audit.log brut, qui reste multi-lignes). Sans cette fusion, le champ EXECVE
(arguments reels de la commande) n'est jamais rattache a l'evenement SYSCALL correspondant,
et reste invisible du champ full_log transmis au LLM.

Tourne en continu (tail -f), ecrit les lignes fusionnees dans le fichier de destination,
surveille par un <localfile> dedie dans ossec.conf. Unite systemd : voir
systemd/audit-merge.service dans ce depot.

Variables d'environnement :
  AUDIT_MERGE_SRC          (defaut: /var/log/audit/audit.log)
  AUDIT_MERGE_DST          (defaut: /var/log/audit/audit-merged.log)
  AUDIT_MERGE_FLUSH_TIMEOUT (defaut: 2.0 secondes)
  AUDIT_MERGE_MAX_BUFFERS  (defaut: 5000) -- nombre maximal d'evenements audit(...) en
                            attente de fusion simultanement ; au-dela, le plus ancien est
                            force-flushe pour eviter une croissance memoire non bornee
                            (protection contre une rafale d'evenements sans le record de
                            fermeture attendu)
  AUDIT_MERGE_MAX_LINES    (defaut: 20) -- nombre maximal de lignes brutes par evenement
                            fusionne, au-dela desquelles l'evenement est flushe tel quel
                            (protection contre un identifiant audit(...) recycle ou corrompu)
"""
import logging
import os
import re
import signal
import sys
import time

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("audit_merge")

SRC = os.environ.get("AUDIT_MERGE_SRC", "/var/log/audit/audit.log")
DST = os.environ.get("AUDIT_MERGE_DST", "/var/log/audit/audit-merged.log")
FLUSH_TIMEOUT = float(os.environ.get("AUDIT_MERGE_FLUSH_TIMEOUT", "2.0"))
STAT_CHECK_INTERVAL = 5.0
MAX_BUFFERS = int(os.environ.get("AUDIT_MERGE_MAX_BUFFERS", "5000"))
MAX_LINES_PER_EVENT = int(os.environ.get("AUDIT_MERGE_MAX_LINES", "20"))

id_re = re.compile(r"msg=audit\(([\d.]+:\d+)\)")

_shutdown_requested = False
_stats = {"merged": 0, "force_flushed_overflow": 0, "truncated_events": 0}


def _handle_signal(signum, _frame) -> None:
    global _shutdown_requested
    log.info("Signal %s recu, arret apres le flush du buffer courant", signal.Signals(signum).name)
    _shutdown_requested = True


def open_src():
    f = open(SRC)
    f.seek(0, 2)
    return f


def flush_all(buffers: dict, out) -> None:
    for parts, _ in buffers.values():
        out.write(" ".join(parts) + "\n")
    log.info("Flush final : %d evenement(s) en attente ecrit(s)", len(buffers))
    buffers.clear()


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    buffers: dict[str, tuple[list[str], float]] = {}
    f = open_src()
    try:
        src_ino = os.fstat(f.fileno()).st_ino
        src_size = os.fstat(f.fileno()).st_size
    except OSError:
        src_ino, src_size = None, 0
    last_stat_check = time.time()
    log.info("Demarrage : %s -> %s (flush_timeout=%.1fs, max_buffers=%d, max_lines_per_event=%d)",
              SRC, DST, FLUSH_TIMEOUT, MAX_BUFFERS, MAX_LINES_PER_EVENT)

    with open(DST, "a", buffering=1) as out:
        while not _shutdown_requested:
            line = f.readline()
            if not line:
                now = time.time()
                if now - last_stat_check > STAT_CHECK_INTERVAL:
                    last_stat_check = now
                    try:
                        st = os.stat(SRC)
                        cur_ino, cur_size = st.st_ino, st.st_size
                    except OSError:
                        cur_ino, cur_size = src_ino, src_size
                    # Rotation classique (logrotate rename+create) : l'inode change.
                    if cur_ino != src_ino:
                        log.info("Rotation detectee (changement d'inode), reouverture de %s", SRC)
                        f.close()
                        f = open_src()
                        src_ino, src_size = cur_ino, cur_size
                    # Rotation en mode copytruncate : meme inode mais la taille a diminue
                    # depuis la derniere lecture -- le fichier a ete vide sous nos pieds,
                    # notre position de lecture n'a plus de sens, on doit revenir au debut.
                    elif cur_size < src_size:
                        log.info("Troncature detectee (copytruncate), repositionnement en debut de fichier")
                        f.seek(0)
                        src_size = cur_size
                    else:
                        src_size = cur_size
                for aid, (parts, last_seen) in list(buffers.items()):
                    if now - last_seen > FLUSH_TIMEOUT:
                        out.write(" ".join(parts) + "\n")
                        _stats["merged"] += 1
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

            if len(parts) >= MAX_LINES_PER_EVENT:
                log.warning("Evenement audit(%s) tronque a %d lignes, flush force", aid, MAX_LINES_PER_EVENT)
                out.write(" ".join(parts) + "\n")
                _stats["merged"] += 1
                _stats["truncated_events"] += 1
                buffers.pop(aid, None)
                continue

            buffers[aid] = (parts, time.time())

            if len(buffers) > MAX_BUFFERS:
                oldest_aid = min(buffers, key=lambda k: buffers[k][1])
                oldest_parts, _ = buffers.pop(oldest_aid)
                out.write(" ".join(oldest_parts) + "\n")
                _stats["merged"] += 1
                _stats["force_flushed_overflow"] += 1
                log.warning(
                    "Nombre de buffers en attente > %d, flush force du plus ancien (audit(%s)) -- "
                    "%d flush(s) force(s) au total depuis le demarrage",
                    MAX_BUFFERS, oldest_aid, _stats["force_flushed_overflow"],
                )

        flush_all(buffers, out)

    log.info("Arret propre. Statistiques : %s", _stats)


if __name__ == "__main__":
    sys.exit(main())

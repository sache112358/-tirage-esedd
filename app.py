from __future__ import annotations

import hashlib
import itertools
import json
import secrets
import sqlite3
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CAPACITIES = [2, 2, 2, 1]
WEEKS = ["Semaine 1", "Semaine 2", "Semaine 3", "Semaine 4"]
EXPECTED_GROUPS = 7


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def random_code(n: int = 8) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def random_token(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


def init_db(db_path: str | Path) -> None:
    con = sqlite3.connect(str(db_path))
    con.executescript(
        """
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'registration',
            expected_groups INTEGER NOT NULL DEFAULT 7,
            created_at TEXT NOT NULL,
            preferences_locked_at TEXT,
            commit_phase_at TEXT,
            reveal_phase_at TEXT,
            drawn_at TEXT,
            result_json TEXT,
            draw_hash TEXT,
            seed_hex TEXT
        );
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            display_name TEXT NOT NULL,
            member1 TEXT NOT NULL,
            member2 TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            pref1 INTEGER,
            pref2 INTEGER,
            preferences_submitted INTEGER NOT NULL DEFAULT 0,
            contribution_commit TEXT,
            contribution_secret TEXT,
            joined_at TEXT NOT NULL,
            UNIQUE(session_id, display_name)
        );
        CREATE INDEX IF NOT EXISTS idx_groups_session ON groups(session_id);
        """
    )
    con.commit()
    con.close()


def connect(db_path: str | Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(db_path), timeout=30, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def create_session(db_path: str | Path) -> dict[str, Any]:
    for _ in range(20):
        code = random_code()
        try:
            con = connect(db_path)
            cur = con.execute(
                "INSERT INTO sessions(code, created_at) VALUES (?, ?)",
                (code, utcnow()),
            )
            sid = cur.lastrowid
            con.close()
            return {"id": sid, "code": code}
        except sqlite3.IntegrityError:
            continue
    raise RuntimeError("Impossible de générer un code de session unique")


def _session_by_code(con: sqlite3.Connection, code: str) -> sqlite3.Row:
    row = con.execute("SELECT * FROM sessions WHERE code = ?", (code.upper(),)).fetchone()
    if not row:
        raise KeyError("Session introuvable")
    return row


def register_group(db_path: str | Path, code: str, display_name: str, member1: str, member2: str) -> dict[str, Any]:
    display_name = " ".join(display_name.strip().split())
    member1 = " ".join(member1.strip().split())
    member2 = " ".join(member2.strip().split())
    if not display_name or not member1 or not member2:
        raise ValueError("Nom du groupe et deux membres requis")
    token = random_token()
    token_hash = sha256_text(token)
    con = connect(db_path)
    try:
        con.execute("BEGIN IMMEDIATE")
        s = _session_by_code(con, code)
        if s["status"] != "registration":
            raise ValueError("Les inscriptions sont closes")
        count = con.execute("SELECT COUNT(*) FROM groups WHERE session_id = ?", (s["id"],)).fetchone()[0]
        if count >= s["expected_groups"]:
            raise ValueError("Les 7 groupes sont déjà inscrits")
        cur = con.execute(
            """INSERT INTO groups(session_id, display_name, member1, member2, token_hash, joined_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (s["id"], display_name, member1, member2, token_hash, utcnow()),
        )
        con.execute("COMMIT")
        return {"group_id": cur.lastrowid, "token": token, "display_name": display_name}
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def _auth_group(con: sqlite3.Connection, code: str, group_id: int, token: str) -> tuple[sqlite3.Row, sqlite3.Row]:
    s = _session_by_code(con, code)
    g = con.execute("SELECT * FROM groups WHERE id = ? AND session_id = ?", (group_id, s["id"])).fetchone()
    if not g or not secrets.compare_digest(g["token_hash"], sha256_text(token)):
        raise PermissionError("Accès du binôme invalide")
    return s, g


def submit_preferences(db_path: str | Path, code: str, group_id: int, token: str, pref1: int | None, pref2: int | None) -> None:
    if pref1 is not None and pref1 not in range(4):
        raise ValueError("Premier choix invalide")
    if pref2 is not None and pref2 not in range(4):
        raise ValueError("Deuxième choix invalide")
    if pref1 is not None and pref2 is not None and pref1 == pref2:
        raise ValueError("Les deux préférences doivent être différentes")
    con = connect(db_path)
    try:
        con.execute("BEGIN IMMEDIATE")
        s, g = _auth_group(con, code, group_id, token)
        if s["status"] != "registration":
            raise ValueError("Les préférences sont déjà verrouillées")
        con.execute(
            "UPDATE groups SET pref1=?, pref2=?, preferences_submitted=1 WHERE id=?",
            (pref1, pref2, group_id),
        )
        total = con.execute("SELECT COUNT(*) FROM groups WHERE session_id=?", (s["id"],)).fetchone()[0]
        ready = con.execute("SELECT COUNT(*) FROM groups WHERE session_id=? AND preferences_submitted=1", (s["id"],)).fetchone()[0]
        if total == s["expected_groups"] and ready == s["expected_groups"]:
            con.execute(
                "UPDATE sessions SET status='commit', preferences_locked_at=?, commit_phase_at=? WHERE id=? AND status='registration'",
                (utcnow(), utcnow(), s["id"]),
            )
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def make_commit(code: str, group_id: int, secret: str) -> str:
    return sha256_text(f"ESEDD|{code.upper()}|{group_id}|{secret}")


def submit_commit(db_path: str | Path, code: str, group_id: int, token: str, commitment: str) -> None:
    if len(commitment) != 64 or any(c not in string.hexdigits for c in commitment):
        raise ValueError("Empreinte de contribution invalide")
    commitment = commitment.lower()
    con = connect(db_path)
    try:
        con.execute("BEGIN IMMEDIATE")
        s, g = _auth_group(con, code, group_id, token)
        if s["status"] != "commit":
            raise ValueError("Ce n'est pas la phase d'engagement")
        if g["contribution_commit"]:
            if g["contribution_commit"] == commitment:
                con.execute("COMMIT")
                return
            raise ValueError("Contribution déjà enregistrée et non modifiable")
        con.execute("UPDATE groups SET contribution_commit=? WHERE id=?", (commitment, group_id))
        committed = con.execute("SELECT COUNT(*) FROM groups WHERE session_id=? AND contribution_commit IS NOT NULL", (s["id"],)).fetchone()[0]
        if committed == s["expected_groups"]:
            con.execute("UPDATE sessions SET status='reveal', reveal_phase_at=? WHERE id=? AND status='commit'", (utcnow(), s["id"]))
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def _all_assignments() -> list[tuple[int, ...]]:
    slots = [0, 0, 1, 1, 2, 2, 3]
    return list(dict.fromkeys(itertools.permutations(slots, 7)))


ASSIGNMENTS = _all_assignments()


def _deterministic_index(seed_hex: str, n: int) -> int:
    return int(seed_hex, 16) % n


def canonical_locked_payload(code: str, groups: list[sqlite3.Row]) -> str:
    payload = {
        "session": code.upper(),
        "capacities": CAPACITIES,
        "groups": [
            {
                "id": int(g["id"]),
                "display_name": g["display_name"],
                "member1": g["member1"],
                "member2": g["member2"],
                "pref1": g["pref1"],
                "pref2": g["pref2"],
                "secret": g["contribution_secret"],
            }
            for g in sorted(groups, key=lambda x: x["id"])
        ],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_result(code: str, groups: list[sqlite3.Row]) -> tuple[dict[str, Any], str, str]:
    canonical = canonical_locked_payload(code, groups)
    seed_hex = sha256_text(canonical)
    best_first = -1
    best_second = -1
    best: list[tuple[int, ...]] = []
    for ass in ASSIGNMENTS:
        f = 0
        s = 0
        for idx, g in enumerate(sorted(groups, key=lambda x: x["id"])):
            if g["pref1"] is not None and ass[idx] == g["pref1"]:
                f += 1
            elif g["pref2"] is not None and ass[idx] == g["pref2"]:
                s += 1
        if f > best_first or (f == best_first and s > best_second):
            best_first, best_second, best = f, s, [ass]
        elif f == best_first and s == best_second:
            best.append(ass)
    chosen = best[_deterministic_index(seed_hex, len(best))]
    ordered = sorted(groups, key=lambda x: x["id"])
    weeks: list[list[dict[str, Any]]] = [[] for _ in range(4)]
    for i, w in enumerate(chosen):
        g = ordered[i]
        weeks[w].append({
            "group_id": g["id"],
            "display_name": g["display_name"],
            "member1": g["member1"],
            "member2": g["member2"],
            "pref1": g["pref1"],
            "pref2": g["pref2"],
        })
    result = {
        "weeks": weeks,
        "first_choices_satisfied": best_first,
        "second_choices_satisfied": best_second,
        "equivalent_optimal_allocations": len(best),
        "algorithm": "maximise_first_then_second_seeded_tiebreak_v1",
    }
    draw_hash = sha256_text(json.dumps({"seed": seed_hex, "result": result}, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return result, seed_hex, draw_hash


def submit_reveal(db_path: str | Path, code: str, group_id: int, token: str, secret: str) -> dict[str, Any] | None:
    if not secret or len(secret) > 500:
        raise ValueError("Contribution invalide")
    con = connect(db_path)
    try:
        con.execute("BEGIN IMMEDIATE")
        s, g = _auth_group(con, code, group_id, token)
        if s["status"] == "drawn":
            con.execute("COMMIT")
            return json.loads(s["result_json"])
        if s["status"] != "reveal":
            raise ValueError("Ce n'est pas la phase de révélation")
        expected = make_commit(code, group_id, secret)
        if not g["contribution_commit"] or not secrets.compare_digest(expected, g["contribution_commit"]):
            raise ValueError("La contribution révélée ne correspond pas à l'engagement enregistré")
        if g["contribution_secret"] is not None and g["contribution_secret"] != secret:
            raise ValueError("Contribution déjà révélée et non modifiable")
        con.execute("UPDATE groups SET contribution_secret=? WHERE id=?", (secret, group_id))
        revealed = con.execute("SELECT COUNT(*) FROM groups WHERE session_id=? AND contribution_secret IS NOT NULL", (s["id"],)).fetchone()[0]
        result = None
        if revealed == s["expected_groups"]:
            groups = con.execute("SELECT * FROM groups WHERE session_id=? ORDER BY id", (s["id"],)).fetchall()
            result, seed_hex, draw_hash = compute_result(code, groups)
            now = utcnow()
            # Atomic, one-way transition. No reset endpoint exists.
            cur = con.execute(
                """UPDATE sessions
                   SET status='drawn', drawn_at=?, result_json=?, draw_hash=?, seed_hex=?
                   WHERE id=? AND status='reveal' AND result_json IS NULL""",
                (now, json.dumps(result, ensure_ascii=False), draw_hash, seed_hex, s["id"]),
            )
            if cur.rowcount != 1:
                latest = con.execute("SELECT result_json FROM sessions WHERE id=?", (s["id"],)).fetchone()
                result = json.loads(latest["result_json"])
        con.execute("COMMIT")
        return result
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def public_state(db_path: str | Path, code: str) -> dict[str, Any]:
    con = connect(db_path)
    try:
        s = _session_by_code(con, code)
        groups = con.execute("SELECT * FROM groups WHERE session_id=? ORDER BY id", (s["id"],)).fetchall()
        result = json.loads(s["result_json"]) if s["result_json"] else None
        expose_secrets = s["status"] == "drawn"
        return {
            "code": s["code"],
            "status": s["status"],
            "expected_groups": s["expected_groups"],
            "created_at": s["created_at"],
            "preferences_locked_at": s["preferences_locked_at"],
            "drawn_at": s["drawn_at"],
            "draw_hash": s["draw_hash"],
            "seed_hex": s["seed_hex"] if expose_secrets else None,
            "counts": {
                "groups": len(groups),
                "preferences": sum(int(g["preferences_submitted"]) for g in groups),
                "commits": sum(1 for g in groups if g["contribution_commit"]),
                "reveals": sum(1 for g in groups if g["contribution_secret"]),
            },
            "groups": [
                {
                    "id": g["id"],
                    "display_name": g["display_name"],
                    "member1": g["member1"],
                    "member2": g["member2"],
                    "pref1": g["pref1"] if g["preferences_submitted"] else None,
                    "pref2": g["pref2"] if g["preferences_submitted"] else None,
                    "preferences_submitted": bool(g["preferences_submitted"]),
                    "committed": bool(g["contribution_commit"]),
                    "revealed": bool(g["contribution_secret"]),
                    "contribution_secret": g["contribution_secret"] if expose_secrets else None,
                    "commitment": g["contribution_commit"] if expose_secrets else None,
                }
                for g in groups
            ],
            "result": result,
        }
    finally:
        con.close()



# --- API / interface web ---
import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

BASE = Path(__file__).resolve().parent
_volume = os.getenv("RAILWAY_VOLUME_MOUNT_PATH")
_default_db = (Path(_volume) / "esedd.sqlite3") if _volume else (BASE / "esedd.sqlite3")
DB_PATH = Path(os.getenv("ESEDD_DB", _default_db))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
init_db(DB_PATH)

app = FastAPI(title="Tirage ESEDD", version="1.0.0")

class RegisterIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)
    member1: str = Field(min_length=1, max_length=80)
    member2: str = Field(min_length=1, max_length=80)

class PrefIn(BaseModel):
    group_id: int
    token: str
    pref1: int | None = None
    pref2: int | None = None

class CommitIn(BaseModel):
    group_id: int
    token: str
    commitment: str

class RevealIn(BaseModel):
    group_id: int
    token: str
    secret: str

INDEX_HTML = '<!doctype html>\n<html lang="fr">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n<meta name="theme-color" content="#0b1020">\n<title>Tirage ESEDD</title>\n<style>\n:root{--bg:#09101c;--card:#111a2a;--card2:#0d1523;--line:#26344a;--text:#f7f8fb;--muted:#9aa6b7;--violet:#7c3aed;--green:#10b981;--amber:#f59e0b;--red:#ef4444}\n*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,rgba(124,58,237,.16),transparent 30%),var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{max-width:960px;margin:auto;padding:20px 14px 60px}h1{font-size:clamp(30px,7vw,50px);margin:8px 0;letter-spacing:-.03em}.lead{color:var(--muted);line-height:1.55;max-width:760px}.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px;margin-top:14px;box-shadow:0 14px 35px rgba(0,0,0,.18)}.steps{display:grid;gap:8px}.step{display:flex;gap:10px;align-items:flex-start;background:var(--card2);border:1px solid var(--line);padding:10px 12px;border-radius:13px}.n{flex:0 0 26px;height:26px;border-radius:50%;display:grid;place-items:center;background:rgba(124,58,237,.18);color:#ddd6fe;font-weight:800}.muted,.small{color:var(--muted)}.small{font-size:12px;line-height:1.45}.progress{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.p{background:var(--card2);border:1px solid var(--line);border-radius:12px;padding:10px}.p b{font-size:20px;display:block}.p span{font-size:11px;color:var(--muted)}button,input,select{font:inherit}button{border:0;border-radius:12px;padding:12px 14px;font-weight:800;cursor:pointer}.primary{background:linear-gradient(135deg,#6d28d9,#8b5cf6);color:white}.secondary{background:#1c2940;color:white;border:1px solid #33445f}.green{background:rgba(16,185,129,.14);color:#a7f3d0;border:1px solid rgba(16,185,129,.35)}input,select{width:100%;background:#0a1321;color:white;border:1px solid #30415d;border-radius:11px;padding:11px}.form{display:grid;gap:9px}.two{display:grid;grid-template-columns:1fr 1fr;gap:9px}.groups{display:grid;gap:8px}.group{padding:11px;background:var(--card2);border:1px solid var(--line);border-radius:12px}.grouphead{display:flex;justify-content:space-between;gap:10px}.badges{display:flex;gap:6px;flex-wrap:wrap;margin-top:7px}.badge{font-size:11px;border:1px solid var(--line);border-radius:999px;padding:4px 7px;color:var(--muted)}.ok{color:#a7f3d0;border-color:rgba(16,185,129,.35)}.warn{color:#fde68a;border-color:rgba(245,158,11,.35)}.hidden{display:none!important}.weeks{display:grid;grid-template-columns:repeat(2,1fr);gap:9px}.week{background:var(--card2);border:1px solid var(--line);border-radius:13px;padding:12px}.week ul{padding-left:18px;margin-bottom:0}.proof{word-break:break-all;background:#07101d;border:1px dashed #33445f;border-radius:12px;padding:11px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px}.notice{padding:11px 12px;border-radius:12px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);color:#fde68a;font-size:13px;line-height:1.45}.success{background:rgba(16,185,129,.08);border-color:rgba(16,185,129,.25);color:#a7f3d0}.error{color:#fecaca}.actions{display:flex;gap:8px;flex-wrap:wrap}.actions button{flex:1;min-width:180px}@media(max-width:650px){.progress,.weeks,.two{grid-template-columns:1fr 1fr}.progress{grid-template-columns:1fr 1fr}}@media(max-width:430px){.weeks,.two{grid-template-columns:1fr}}\n</style>\n</head>\n<body>\n<div class="wrap">\n<h1>🎲 Tirage ESEDD</h1>\n<p class="lead">Un seul tirage, collectif et vérifiable. Il n’existe aucun bouton « refaire ». Le résultat n’apparaît qu’après la participation des 7 binômes.</p>\n\n<div class="card">\n<h2>Déroulé</h2>\n<div class="steps">\n<div class="step"><span class="n">1</span><div><b>7 binômes s’inscrivent</b><div class="small">Chaque binôme renseigne ses deux membres.</div></div></div>\n<div class="step"><span class="n">2</span><div><b>Chaque binôme indique ses préférences</b><div class="small">Premier choix, deuxième choix facultatif ou « peu importe ».</div></div></div>\n<div class="step"><span class="n">3</span><div><b>Les préférences sont verrouillées automatiquement</b><div class="small">Dès que 7/7 groupes ont répondu, plus personne ne peut les modifier.</div></div></div>\n<div class="step"><span class="n">4</span><div><b>Chaque binôme génère une contribution secrète</b><div class="small">L’application n’enregistre d’abord que son empreinte. Les autres ne voient pas le nombre.</div></div></div>\n<div class="step"><span class="n">5</span><div><b>Quand les 7 engagements sont reçus, chacun révèle sa contribution</b><div class="small">Impossible de la changer : elle doit correspondre à l’empreinte déjà enregistrée.</div></div></div>\n<div class="step"><span class="n">6</span><div><b>Au 7e dévoilement, le tirage est calculé automatiquement une seule fois</b><div class="small">Le résultat est ensuite figé définitivement pour cette session.</div></div></div>\n</div>\n</div>\n\n<div id="start" class="card">\n<h2>Créer ou rejoindre</h2>\n<div id="noSession">\n<p class="small">Crée une nouvelle session. Le lien obtenu est celui à partager dans WhatsApp.</p>\n<button id="create" class="primary">Créer le tirage officiel</button>\n</div>\n<div id="sessionInfo" class="hidden">\n<div class="actions"><button id="shareLink" class="secondary">Partager le lien</button><button id="copyLink" class="secondary">Copier le lien</button></div>\n<p class="small">Session : <b id="code"></b></p>\n</div>\n</div>\n\n<div id="live" class="hidden">\n<div class="card">\n<h2>État du tirage</h2>\n<div class="progress">\n<div class="p"><b id="cGroups">0/7</b><span>GROUPES</span></div>\n<div class="p"><b id="cPrefs">0/7</b><span>PRÉFÉRENCES</span></div>\n<div class="p"><b id="cCommits">0/7</b><span>ENGAGEMENTS</span></div>\n<div class="p"><b id="cReveals">0/7</b><span>RÉVÉLATIONS</span></div>\n</div>\n<p id="phase" class="notice" style="margin-top:10px"></p>\n</div>\n\n<div class="card">\n<h2>Les groupes</h2><div id="groupList" class="groups"></div>\n</div>\n\n<div id="registerCard" class="card">\n<h2>Inscrire mon binôme</h2>\n<div class="form"><input id="gname" placeholder="Nom du binôme (ex. Claire / Charlotte)"><div class="two"><input id="m1" placeholder="Membre 1"><input id="m2" placeholder="Membre 2"></div><button id="register" class="primary">Inscrire notre binôme</button><p id="regErr" class="small error"></p></div>\n</div>\n\n<div id="myCard" class="card hidden"><h2>Mon binôme</h2><p id="myName"></p><div id="myActions"></div><p id="myErr" class="small error"></p></div>\n\n<div id="resultCard" class="card hidden"><h2>✅ Tirage définitif</h2><p class="notice success">Cette session a été tirée une seule fois. Le résultat ci-dessous est enregistré et ne peut pas être relancé.</p><div id="weeks" class="weeks"></div><p id="resultStats" class="small"></p><h3>Preuve du tirage</h3><div id="proof" class="proof"></div><div class="actions" style="margin-top:10px"><button id="shareResult" class="green">Partager le résultat</button><button id="copyResult" class="secondary">Copier pour WhatsApp</button></div></div>\n</div>\n</div>\n<script>\nconst $=s=>document.querySelector(s);let state=null;const params=new URLSearchParams(location.search);const code=params.get(\'s\');const key=()=>`esedd:${code}:me`;const secretKey=()=>`esedd:${code}:secret`;\nasync function api(url,opt={}){const r=await fetch(url,{headers:{\'Content-Type\':\'application/json\',...(opt.headers||{})},...opt});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.detail||\'Erreur\');return j}\nfunction me(){try{return JSON.parse(localStorage.getItem(key()))}catch{return null}}\nfunction saveMe(v){localStorage.setItem(key(),JSON.stringify(v))}\nfunction esc(s){return String(s??\'\').replace(/[&<>"\']/g,m=>({\'&\':\'&amp;\',\'<\':\'&lt;\',\'>\':\'&gt;\',\'"\':\'&quot;\',"\'":\'&#039;\'}[m]))}\nfunction weekLabel(v){return v===null||v===undefined?\'Peu importe\':`Semaine ${v+1}`}\nasync function createSession(){const j=await api(\'/api/sessions\',{method:\'POST\'});location.href=`?s=${j.code}`}\nasync function load(){if(!code)return;try{state=await api(`/api/sessions/${code}`);render()}catch(e){$(\'#phase\').textContent=e.message}}\nfunction render(){\n $(\'#noSession\').classList.add(\'hidden\');$(\'#sessionInfo\').classList.remove(\'hidden\');$(\'#live\').classList.remove(\'hidden\');$(\'#code\').textContent=state.code;$(\'#cGroups\').textContent=`${state.counts.groups}/7`;$(\'#cPrefs\').textContent=`${state.counts.preferences}/7`;$(\'#cCommits\').textContent=`${state.counts.commits}/7`;$(\'#cReveals\').textContent=`${state.counts.reveals}/7`;\n const phases={registration:`Inscription et préférences : ${state.counts.groups}/7 groupes, ${state.counts.preferences}/7 préférences. Le verrouillage est automatique à 7/7.`,commit:`🔒 Préférences verrouillées. Chaque binôme doit maintenant enregistrer sa contribution secrète.`,reveal:`🔐 7/7 engagements reçus. Les contributions peuvent maintenant être révélées. Le tirage se déclenchera automatiquement au 7e dévoilement.`,drawn:`✅ Tirage terminé. Aucun nouveau tirage n\'est possible dans cette session.`};$(\'#phase\').textContent=phases[state.status];\n $(\'#groupList\').innerHTML=state.groups.map(g=>`<div class="group"><div class="grouphead"><b>${esc(g.display_name)}</b><span class="small">${esc(g.member1)} + ${esc(g.member2)}</span></div><div class="badges"><span class="badge ${g.preferences_submitted?\'ok\':\'warn\'}">Préférences ${g.preferences_submitted?\'✓\':\'…\'}</span><span class="badge ${g.committed?\'ok\':\'warn\'}">Engagement ${g.committed?\'✓\':\'…\'}</span><span class="badge ${g.revealed?\'ok\':\'warn\'}">Révélation ${g.revealed?\'✓\':\'…\'}</span></div>${g.preferences_submitted?`<div class="small" style="margin-top:6px">1er : ${weekLabel(g.pref1)} · 2e : ${g.pref2==null?\'—\':weekLabel(g.pref2)}</div>`:\'\'}</div>`).join(\'\')||\'<p class="small">Aucun groupe inscrit pour le moment.</p>\';\n const mine=me();$(\'#registerCard\').classList.toggle(\'hidden\',!!mine||state.counts.groups>=7||state.status!==\'registration\');$(\'#myCard\').classList.toggle(\'hidden\',!mine);if(mine)renderMine(mine);\n if(state.status===\'drawn\')renderResult(); else $(\'#resultCard\').classList.add(\'hidden\');\n}\nfunction renderMine(m){const g=state.groups.find(x=>x.id===m.group_id);if(!g){localStorage.removeItem(key());return}$(\'#myName\').innerHTML=`<b>${esc(g.display_name)}</b> — ${esc(g.member1)} + ${esc(g.member2)}`;let h=\'\';\n if(state.status===\'registration\'){h=`<p class="small">Indiquez vos préférences. Vous pouvez les modifier tant que les 7 groupes n\'ont pas tous répondu.</p><div class="two"><select id="pref1"><option value="">Peu importe</option>${[1,2,3,4].map(x=>`<option value="${x-1}" ${g.pref1===x-1?\'selected\':\'\'}>Semaine ${x}</option>`).join(\'\')}</select><select id="pref2"><option value="">Pas de 2e choix</option>${[1,2,3,4].map(x=>`<option value="${x-1}" ${g.pref2===x-1?\'selected\':\'\'}>Semaine ${x}</option>`).join(\'\')}</select></div><button class="primary" style="margin-top:9px" onclick="savePrefs()">${g.preferences_submitted?\'Mettre à jour mes préférences\':\'Valider mes préférences\'}</button>`}\n else if(state.status===\'commit\'&&!g.committed){h=`<p class="small">Votre téléphone va générer une contribution secrète. Seule son empreinte est envoyée maintenant. La valeur reste sur cet appareil jusqu\'à la phase suivante.</p><button class="primary" onclick="commitSecret()">Générer et engager ma contribution</button>`}\n else if(state.status===\'commit\'){h=`<p class="notice success">Votre engagement est enregistré. Attente des autres groupes…</p>`}\n else if(state.status===\'reveal\'&&!g.revealed){h=`<p class="small">Les 7 engagements sont figés. Vous pouvez maintenant révéler la contribution déjà créée sur cet appareil.</p><button class="primary" onclick="revealSecret()">Révéler ma contribution</button>`}\n else if(state.status===\'reveal\'){h=`<p class="notice success">Votre contribution est révélée. Attente des autres groupes…</p>`}\n else h=`<p class="notice success">Votre participation est terminée.</p>`;$(\'#myActions\').innerHTML=h}\nasync function register(){try{const j=await api(`/api/sessions/${code}/groups`,{method:\'POST\',body:JSON.stringify({display_name:$(\'#gname\').value,member1:$(\'#m1\').value,member2:$(\'#m2\').value})});saveMe(j);await load()}catch(e){$(\'#regErr\').textContent=e.message}}\nasync function savePrefs(){try{const m=me(),p1=$(\'#pref1\').value,p2=$(\'#pref2\').value;await api(`/api/sessions/${code}/preferences`,{method:\'POST\',body:JSON.stringify({group_id:m.group_id,token:m.token,pref1:p1===\'\'?null:+p1,pref2:p2===\'\'?null:+p2})});await load()}catch(e){$(\'#myErr\').textContent=e.message}}\nfunction randSecret(){const a=new Uint32Array(8);crypto.getRandomValues(a);return [...a].map(x=>x.toString(16).padStart(8,\'0\')).join(\'\')}\nasync function hashText(s){const b=new TextEncoder().encode(s),d=await crypto.subtle.digest(\'SHA-256\',b);return [...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,\'0\')).join(\'\')}\nasync function commitSecret(){try{const m=me();let sec=localStorage.getItem(secretKey());if(!sec){sec=randSecret();localStorage.setItem(secretKey(),sec)}const commitment=await hashText(`ESEDD|${code.toUpperCase()}|${m.group_id}|${sec}`);await api(`/api/sessions/${code}/commit`,{method:\'POST\',body:JSON.stringify({group_id:m.group_id,token:m.token,commitment})});await load()}catch(e){$(\'#myErr\').textContent=e.message}}\nasync function revealSecret(){try{const m=me(),sec=localStorage.getItem(secretKey());if(!sec)throw new Error("La contribution secrète n\'est plus présente sur cet appareil.");await api(`/api/sessions/${code}/reveal`,{method:\'POST\',body:JSON.stringify({group_id:m.group_id,token:m.token,secret:sec})});await load()}catch(e){$(\'#myErr\').textContent=e.message}}\nfunction resultText(){let t=`🎲 TIRAGE ESEDD — DÉFINITIF\\nSession : ${state.code}\\n\\n`;state.result.weeks.forEach((arr,i)=>{t+=`Semaine ${i+1}\\n`;arr.forEach(g=>t+=`• ${g.display_name}\\n`);t+=\'\\n\'});t+=`Empreinte : ${state.draw_hash}\\nUn seul tirage a été enregistré pour cette session.`;return t}\nfunction renderResult(){const r=state.result;$(\'#resultCard\').classList.remove(\'hidden\');$(\'#weeks\').innerHTML=r.weeks.map((arr,i)=>`<div class="week"><b>Semaine ${i+1} (${arr.length}/${[2,2,2,1][i]})</b><ul>${arr.map(g=>`<li>${esc(g.display_name)}</li>`).join(\'\')}</ul></div>`).join(\'\');$(\'#resultStats\').textContent=`${r.first_choices_satisfied} premiers choix satisfaits · ${r.second_choices_satisfied} deuxièmes choix satisfaits · ${r.equivalent_optimal_allocations} répartition(s) optimales avant départage cryptographique.`;$(\'#proof\').innerHTML=`Session: ${esc(state.code)}<br>Graine SHA-256: ${esc(state.seed_hex)}<br>Empreinte du résultat: ${esc(state.draw_hash)}<br><br>Contributions révélées:<br>${state.groups.map(g=>`${esc(g.display_name)} → ${esc(g.contribution_secret)}`).join(\'<br>\')}`}\n$(\'#create\').onclick=createSession;$(\'#register\').onclick=register;$(\'#copyLink\').onclick=async()=>{await navigator.clipboard.writeText(location.href);alert(\'Lien copié\')};$(\'#shareLink\').onclick=async()=>{if(navigator.share)await navigator.share({title:\'Tirage ESEDD\',text:\'Lien du tirage ESEDD :\',url:location.href});else navigator.clipboard.writeText(location.href)};$(\'#copyResult\').onclick=async()=>{await navigator.clipboard.writeText(resultText());alert(\'Résultat copié\')};$(\'#shareResult\').onclick=async()=>{if(navigator.share)await navigator.share({title:\'Tirage ESEDD\',text:resultText()});else navigator.clipboard.writeText(resultText())};if(code){load();setInterval(load,2500)}\n</script>\n</body>\n</html>\n'

@app.get("/", response_class=HTMLResponse)
def home():
    return INDEX_HTML

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/api/sessions")
def api_create_session():
    return create_session(DB_PATH)

@app.get("/api/sessions/{code}")
def api_state(code: str):
    try:
        return public_state(DB_PATH, code)
    except KeyError as e:
        raise HTTPException(404, str(e))

@app.post("/api/sessions/{code}/groups")
def api_register(code: str, body: RegisterIn):
    try:
        return register_group(DB_PATH, code, body.display_name, body.member1, body.member2)
    except KeyError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            raise HTTPException(409, "Ce nom de groupe est déjà utilisé")
        raise

@app.post("/api/sessions/{code}/preferences")
def api_preferences(code: str, body: PrefIn):
    try:
        submit_preferences(DB_PATH, code, body.group_id, body.token, body.pref1, body.pref2)
        return {"ok": True}
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except (KeyError, ValueError) as e:
        raise HTTPException(400, str(e))

@app.post("/api/sessions/{code}/commit")
def api_commit(code: str, body: CommitIn):
    try:
        submit_commit(DB_PATH, code, body.group_id, body.token, body.commitment)
        return {"ok": True}
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except (KeyError, ValueError) as e:
        raise HTTPException(400, str(e))

@app.post("/api/sessions/{code}/reveal")
def api_reveal(code: str, body: RevealIn):
    try:
        result = submit_reveal(DB_PATH, code, body.group_id, body.token, body.secret)
        return {"ok": True, "drawn": result is not None, "result": result}
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except (KeyError, ValueError) as e:
        raise HTTPException(400, str(e))

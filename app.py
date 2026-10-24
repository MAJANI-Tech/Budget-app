import json
import re
import hashlib
import hmac
import secrets
import time
from datetime import datetime
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

st.set_page_config(page_title="KILUNGA'S Budget", page_icon="💰", layout="centered")

# ---------- Mipangilio ----------
DATA_DIR = Path("data")
USERS_DIR = DATA_DIR / "users"
USERS_DIR.mkdir(parents=True, exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"
LEGACY_DB = DATA_DIR / "budget.json"  # data za toleo la zamani (mtumiaji mmoja)
CATS = ["NEEDS", "WANTS", "SAVINGS"]
DEFAULT_GOALS = {"NEEDS": 50, "WANTS": 30, "SAVINGS": 20}  # asilimia
MAX_TRIES = 5        # majaribio ya PIN kabla ya akaunti kufungwa kwa muda
LOCK_SECONDS = 300   # dakika 5
TOLERANCE = 5        # pointi za asilimia kwa alama ya 🟡
WARN_RATIO = 0.8     # onyo ukifika 80% ya kikomo
MONTH_RE = r"\d{4}-(0[1-9]|1[0-2])"


# ---------- Zana za faili ----------
def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def empty_month():
    return {"income": [], "expenses": []}


# ---------- Akaunti ----------
def hash_pin(pin, salt):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 100_000).hex()


def valid_username(name):
    return re.fullmatch(r"[a-z0-9_]{3,20}", name) is not None


def user_file(name):
    return USERS_DIR / f"{name}.json"


def register(name, pin):
    users = read_json(USERS_FILE, {})
    if name in users:
        return "Jina hili tayari linatumika. Chagua jingine."
    salt = secrets.token_hex(16)
    users[name] = {"salt": salt, "hash": hash_pin(pin, salt), "fails": 0, "locked_until": 0}
    write_json(USERS_FILE, users)
    # Mtumiaji wa kwanza anarithi data za toleo la zamani (kama zipo)
    if len(users) == 1 and LEGACY_DB.exists():
        user_file(name).write_text(LEGACY_DB.read_text(encoding="utf-8"), encoding="utf-8")
    return None


def login(name, pin):
    users = read_json(USERS_FILE, {})
    u = users.get(name)
    if not u:
        return "Jina au PIN si sahihi."
    now = time.time()
    if u.get("locked_until", 0) > now:
        mins = int((u["locked_until"] - now) // 60) + 1
        return f"Akaunti imefungwa kwa muda. Jaribu tena baada ya dakika {mins}."
    if hmac.compare_digest(hash_pin(pin, u["salt"]), u["hash"]):
        u["fails"] = 0
        u["locked_until"] = 0
        write_json(USERS_FILE, users)
        return None
    u["fails"] = u.get("fails", 0) + 1
    if u["fails"] >= MAX_TRIES:
        u["fails"] = 0
        u["locked_until"] = now + LOCK_SECONDS
    write_json(USERS_FILE, users)
    return "Jina au PIN si sahihi."


def verify(name, pin):
    u = read_json(USERS_FILE, {}).get(name)
    return bool(u) and hmac.compare_digest(hash_pin(pin, u["salt"]), u["hash"])


def change_pin(name, new_pin):
    users = read_json(USERS_FILE, {})
    salt = secrets.token_hex(16)
    users[name].update({"salt": salt, "hash": hash_pin(new_pin, salt)})
    write_json(USERS_FILE, users)


def delete_account(name):
    users = read_json(USERS_FILE, {})
    users.pop(name, None)
    write_json(USERS_FILE, users)
    f = user_file(name)
    if f.exists():
        f.unlink()


# ---------- Skrini ya kuingia ----------
if "user" not in st.session_state:
    st.title("💰 MY Budget")
    st.caption("Fuatilia mapato na matumizi yako kwa mfumo wa 50/30/20")
    tab_in, tab_reg = st.tabs(["Ingia", "Jisajili"])

    with tab_in:
        with st.form("login"):
            un = st.text_input("Jina la mtumiaji").strip().lower()
            pn = st.text_input("PIN", type="password")
            if st.form_submit_button("Ingia"):
                err = login(un, pn)
                if err:
                    st.error(err)
                else:
                    st.session_state.user = un
                    st.rerun()

    with tab_reg:
        with st.form("register"):
            un = st.text_input("Chagua jina la mtumiaji (herufi ndogo, namba au _ ; 3-20)").strip().lower()
            p1 = st.text_input("PIN (angalau tarakimu 4)", type="password")
            p2 = st.text_input("Rudia PIN", type="password")
            if st.form_submit_button("Fungua akaunti"):
                if not valid_username(un):
                    st.error("Jina lazima liwe herufi ndogo (a-z), namba au _, urefu 3 hadi 20.")
                elif len(p1) < 4:
                    st.error("PIN iwe na angalau tarakimu 4.")
                elif p1 != p2:
                    st.error("PIN hazilingani.")
                else:
                    err = register(un, p1)
                    if err:
                        st.error(err)
                    else:
                        st.session_state.user = un
                        st.rerun()
    st.stop()

# ---------- Mtumiaji ameingia ----------
user = st.session_state.user
DB_FILE = user_file(user)
db = read_json(DB_FILE, {})

# Mipangilio ya mtumiaji (malengo na vikomo) inakaa kwenye "_settings"
settings = db.setdefault("_settings", {})
goals_pct = settings.get("goals") or DEFAULT_GOALS
if set(goals_pct) != set(CATS) or sum(goals_pct.values()) != 100:
    goals_pct = DEFAULT_GOALS
limits = settings.get("limits", {})


def save():
    write_json(DB_FILE, db)


def summarize(mdata):
    inc = sum(x["amount"] for x in mdata["income"])
    cat_totals = {c: sum(x["amount"] for x in mdata["expenses"] if x["category"] == c) for c in CATS}
    spent_total = sum(x["amount"] for x in mdata["expenses"])
    return inc, spent_total, cat_totals


def status(cat, actual_pct, goal_pct):
    """NEEDS na WANTS ni kikomo (usizidi). SAVINGS ni kiwango cha chini (ufikie)."""
    if cat == "SAVINGS":
        if actual_pct >= goal_pct:
            return "✅", "Umefikia lengo"
        if actual_pct >= goal_pct - TOLERANCE:
            return "🟡", "Karibu na lengo"
        return "❌", "Chini ya lengo"
    if actual_pct <= goal_pct:
        return "✅", "Ndani ya lengo"
    if actual_pct <= goal_pct + TOLERANCE:
        return "🟡", "Umezidi kidogo"
    return "❌", "Umezidi lengo"


st.title("💰 MY Budget")
if "flash" in st.session_state:
    st.success(st.session_state.pop("flash"))

st.sidebar.write(f"👤 **{user}**")
if st.sidebar.button("Toka"):
    st.session_state.pop("user", None)
    st.rerun()
month = st.sidebar.text_input("Mwezi (YYYY-MM)", datetime.now().strftime("%Y-%m")).strip()
if not re.fullmatch(MONTH_RE, month):
    st.sidebar.error("Tumia muundo YYYY-MM, mfano 2026-10")
    st.stop()
m = db.setdefault(month, empty_month())

# ---------- Ongeza mapato / matumizi ----------
tab1, tab2 = st.tabs(["➕ Mapato", "➖ Matumizi"])
with tab1:
    with st.form("inc", clear_on_submit=True):
        n = st.text_input("Chanzo cha mapato")
        a = st.number_input("Kiasi (TSh)", min_value=0.0, step=1000.0)
        if st.form_submit_button("Hifadhi mapato") and n and a > 0:
            m["income"].append({"name": n, "amount": a})
            save()
            st.rerun()
with tab2:
    with st.form("exp", clear_on_submit=True):
        n = st.text_input("Matumizi (jina)")
        a = st.number_input("Kiasi (TSh)", min_value=0.0, step=500.0)
        c = st.selectbox("Aina", CATS)
        if st.form_submit_button("Hifadhi matumizi") and n and a > 0:
            m["expenses"].append({"name": n, "amount": a, "category": c})
            save()
            st.rerun()

# ---------- Jumla za mwezi ----------
income, spent, cats = summarize(m)
c1, c2, c3 = st.columns(3)
c1.metric("Mapato", f"{income:,.0f}")
c2.metric("Matumizi", f"{spent:,.0f}")
c3.metric("Salio", f"{income - spent:,.0f}")

t_sum, t_cmp, t_rec, t_set = st.tabs(["📊 Muhtasari", "📅 Miezi", "📝 Rekodi", "⚙️ Zaidi"])

# ================= MUHTASARI =================
with t_sum:
    rows = []
    for cat in CATS:
        gp = goals_pct[cat]
        rows.append({
            "Aina": cat,
            "Lengo %": gp,
            "Halisi %": round(cats[cat] / income * 100, 1) if income else 0,
            "Lengo (TSh)": round(income * gp / 100),
            "Halisi (TSh)": round(cats[cat]),
        })
    df = pd.DataFrame(rows)
    goal_text = "/".join(str(goals_pct[c]) for c in CATS)

    st.subheader(f"Hali ya malengo {goal_text}")
    if income > 0:
        cols = st.columns(3)
        for col, r in zip(cols, rows):
            icon, text = status(r["Aina"], r["Halisi %"], r["Lengo %"])
            col.metric(f"{icon} {r['Aina']}", f"{r['Halisi %']}%")
            col.caption(f"Lengo {r['Lengo %']}% · {text}")
        left = income - spent
        if left >= 0:
            st.caption(f"Haijapangiwa: {left:,.0f} TSh ({left / income * 100:.1f}% ya mapato)")
        else:
            st.warning(f"Umetumia {abs(left):,.0f} TSh zaidi ya mapato ya mwezi huu.")
        st.dataframe(df, hide_index=True)
    else:
        st.info("Ongeza mapato ili kuona hali ya malengo.")

    # ----- Vikomo vya bajeti -----
    active = [c for c in CATS if float(limits.get(c, 0) or 0) > 0]
    if active:
        st.subheader("Vikomo vya bajeti")
        for c in active:
            lim = float(limits[c])
            used = cats[c]
            ratio = used / lim
            st.progress(min(ratio, 1.0), text=f"{c}: {used:,.0f} / {lim:,.0f} TSh ({ratio * 100:.0f}%)")
            if c == "SAVINGS":
                if ratio >= 1:
                    st.success(f"✅ SAVINGS: umefikia lengo lako la akiba ({lim:,.0f} TSh).")
            elif ratio >= 1:
                st.error(f"❌ {c}: umezidi kikomo kwa {used - lim:,.0f} TSh.")
            elif ratio >= WARN_RATIO:
                st.warning(f"⚠️ {c}: umetumia {ratio * 100:.0f}% ya kikomo. Umebakiwa na {lim - used:,.0f} TSh.")

    # ----- Grafu -----
    if income > 0:
        st.subheader("Lengo dhidi ya halisi (TSh)")
        long = pd.concat([
            df[["Aina", "Lengo (TSh)"]].rename(columns={"Lengo (TSh)": "Kiasi"}).assign(Kipimo="Lengo"),
            df[["Aina", "Halisi (TSh)"]].rename(columns={"Halisi (TSh)": "Kiasi"}).assign(Kipimo="Halisi"),
        ])
        bars = (
            alt.Chart(long)
            .mark_bar()
            .encode(
                x=alt.X("Kipimo:N", title=None, axis=alt.Axis(labels=False, ticks=False)),
                y=alt.Y("Kiasi:Q", title="TSh"),
                color=alt.Color(
                    "Kipimo:N",
                    scale=alt.Scale(domain=["Lengo", "Halisi"], range=["#9aa5b1", "#1f77b4"]),
                ),
                column=alt.Column("Aina:N", title=None),
                tooltip=["Aina", "Kipimo", alt.Tooltip("Kiasi:Q", format=",.0f")],
            )
            .properties(width=90, height=250)
        )
        st.altair_chart(bars)

    if df["Halisi (TSh)"].sum() > 0:
        st.subheader("Mgawanyo wa matumizi")
        pie = alt.Chart(df).mark_arc().encode(
            theta="Halisi (TSh):Q",
            color="Aina:N",
            tooltip=["Aina", "Halisi (TSh)", "Halisi %"],
        )
        st.altair_chart(pie)

# ================= KULINGANISHA MIEZI =================
with t_cmp:
    st.subheader("Linganisha miezi")
    others = sorted(
        k for k, v in db.items()
        if not k.startswith("_") and k != month and (v["income"] or v["expenses"])
    )
    if not others:
        st.info("Hakuna mwezi mwingine wenye rekodi wa kulinganisha nao bado.")
    else:
        earlier = [k for k in others if k < month]
        default = others.index(earlier[-1]) if earlier else len(others) - 1
        other = st.selectbox("Linganisha " + month + " na", others, index=default)
        inc2, spent2, cats2 = summarize(db[other])

        a, b, c = st.columns(3)
        a.metric("Mapato", f"{income:,.0f}", f"{income - inc2:+,.0f}")
        b.metric("Matumizi", f"{spent:,.0f}", f"{spent - spent2:+,.0f}", delta_color="inverse")
        c.metric("Salio", f"{income - spent:,.0f}", f"{(income - spent) - (inc2 - spent2):+,.0f}")
        st.caption(f"Tofauti ni za {month} ukilinganisha na {other}.")

        diff = pd.DataFrame([
            {"Aina": k, other: round(cats2[k]), month: round(cats[k]), "Tofauti": round(cats[k] - cats2[k])}
            for k in CATS
        ])
        st.dataframe(diff, hide_index=True)

        cmp_df = pd.DataFrame([
            {"Aina": k, "Mwezi": mo, "Kiasi": val}
            for k in CATS
            for mo, val in ((other, cats2[k]), (month, cats[k]))
        ])
        cmp_chart = (
            alt.Chart(cmp_df)
            .mark_bar()
            .encode(
                x=alt.X("Mwezi:N", title=None, axis=alt.Axis(labels=False, ticks=False)),
                y=alt.Y("Kiasi:Q", title="TSh"),
                color=alt.Color(
                    "Mwezi:N",
                    scale=alt.Scale(domain=[other, month], range=["#9aa5b1", "#1f77b4"]),
                ),
                column=alt.Column("Aina:N", title=None),
                tooltip=["Aina", "Mwezi", alt.Tooltip("Kiasi:Q", format=",.0f")],
            )
            .properties(width=90, height=250)
        )
        st.altair_chart(cmp_chart)

# ================= REKODI: HARIRI / FUTA =================
with t_rec:
    st.subheader("Rekodi za mwezi huu")
    items = [("INCOME", i, x) for i, x in enumerate(m["income"])] + \
            [("EXPENSE", i, x) for i, x in enumerate(m["expenses"])]
    if items:
        st.dataframe(
            pd.DataFrame([
                {"Aina": k, "Jina": x["name"], "Kiasi": x["amount"], "Kundi": x.get("category", "")}
                for k, _, x in items
            ]),
            hide_index=True,
        )
        labels = [f"{k} | {x['name']} | {x['amount']:,.0f}" for k, _, x in items]
        pick = st.selectbox("Chagua rekodi ya kuhariri au kufuta", ["—"] + labels)
        if pick != "—":
            k, i, rec = items[labels.index(pick)]
            with st.form("edit"):
                en = st.text_input("Jina", rec["name"], key=f"en_{k}_{i}")
                ea = st.number_input(
                    "Kiasi (TSh)", min_value=0.0, value=float(rec["amount"]), step=500.0, key=f"ea_{k}_{i}"
                )
                if k == "EXPENSE":
                    cur = rec.get("category")
                    ec = st.selectbox(
                        "Aina", CATS, index=CATS.index(cur) if cur in CATS else 0, key=f"ec_{k}_{i}"
                    )
                b_save, b_del = st.columns(2)
                do_save = b_save.form_submit_button("💾 Hifadhi mabadiliko")
                do_del = b_del.form_submit_button("🗑️ Futa")
            if do_save:
                if en.strip() and ea > 0:
                    rec["name"] = en.strip()
                    rec["amount"] = ea
                    if k == "EXPENSE":
                        rec["category"] = ec
                    save()
                    st.session_state.flash = "Rekodi imebadilishwa."
                    st.rerun()
                else:
                    st.error("Jina lisiwe tupu na kiasi kiwe zaidi ya 0.")
            if do_del:
                (m["income"] if k == "INCOME" else m["expenses"]).pop(i)
                save()
                st.session_state.flash = "Rekodi imefutwa."
                st.rerun()
    else:
        st.info("Hakuna rekodi bado. Anza kuongeza mapato au matumizi.")

# ================= ZAIDI: MIPANGILIO, CSV, AKAUNTI =================
with t_set:
    st.subheader("Malengo na vikomo")
    st.write("**Asilimia za malengo** (jumla lazima iwe 100)")
    g1, g2, g3 = st.columns(3)
    gn = g1.number_input("NEEDS %", 0, 100, int(goals_pct["NEEDS"]), key="g_n")
    gw = g2.number_input("WANTS %", 0, 100, int(goals_pct["WANTS"]), key="g_w")
    gs = g3.number_input("SAVINGS %", 0, 100, int(goals_pct["SAVINGS"]), key="g_s")
    st.caption(f"Jumla: {gn + gw + gs}%")

    st.write("**Vikomo vya kila mwezi (TSh)**, weka 0 kama hutaki")
    l1, l2, l3 = st.columns(3)
    ln = l1.number_input("NEEDS (kikomo)", min_value=0.0, value=float(limits.get("NEEDS", 0) or 0),
                         step=10000.0, key="l_n")
    lw = l2.number_input("WANTS (kikomo)", min_value=0.0, value=float(limits.get("WANTS", 0) or 0),
                         step=10000.0, key="l_w")
    ls = l3.number_input("SAVINGS (lengo)", min_value=0.0, value=float(limits.get("SAVINGS", 0) or 0),
                         step=10000.0, key="l_s")

    if st.button("Hifadhi mipangilio"):
        if gn + gw + gs != 100:
            st.error("Jumla ya asilimia lazima iwe 100.")
        else:
            settings["goals"] = {"NEEDS": gn, "WANTS": gw, "SAVINGS": gs}
            settings["limits"] = {"NEEDS": ln, "WANTS": lw, "SAVINGS": ls}
            save()
            st.session_state.flash = "Mipangilio imehifadhiwa."
            st.rerun()
    if st.button("Rudisha 50/30/20"):
        settings.pop("goals", None)
        save()
        for key in ("g_n", "g_w", "g_s"):
            st.session_state.pop(key, None)
        st.session_state.flash = "Malengo yamerudishwa kuwa 50/30/20."
        st.rerun()

    st.divider()
    st.subheader("Backup (CSV)")
    flat = []
    for mo, d in db.items():
        if mo.startswith("_"):
            continue
        for x in d["income"]:
            flat.append({"month": mo, "kind": "INCOME", "name": x["name"], "amount": x["amount"], "category": ""})
        for x in d["expenses"]:
            flat.append({"month": mo, "kind": "EXPENSE", "name": x["name"], "amount": x["amount"],
                         "category": x["category"]})
    csv_df = pd.DataFrame(flat, columns=["month", "kind", "name", "amount", "category"])
    st.download_button(
        "⬇️ Pakua CSV",
        csv_df.to_csv(index=False).encode("utf-8"),
        f"budget_{user}.csv",
        "text/csv",
    )

    up = st.file_uploader("Pakia CSV (itaongezwa kwenye data iliyopo)", type="csv")
    if up and st.button("Pakia sasa"):
        try:
            imp = pd.read_csv(up)
            need = {"month", "kind", "name", "amount", "category"}
            if not need.issubset(imp.columns):
                raise ValueError("Safu za CSV hazilingani na zinazotakiwa.")
            added = 0
            for _, r in imp.iterrows():
                mo = str(r["month"])
                if not re.fullmatch(MONTH_RE, mo):
                    continue
                amt = float(r["amount"])
                if amt <= 0:
                    continue
                mm = db.setdefault(mo, empty_month())
                if r["kind"] == "INCOME":
                    mm["income"].append({"name": str(r["name"]), "amount": amt})
                elif r["kind"] == "EXPENSE" and str(r["category"]) in CATS:
                    mm["expenses"].append({"name": str(r["name"]), "amount": amt, "category": str(r["category"])})
                else:
                    continue
                added += 1
            save()
            st.session_state.flash = f"Rekodi {added} zimepakiwa."
            st.rerun()
        except Exception as e:
            st.error(f"Imeshindwa kupakia CSV: {e}")

    st.divider()
    with st.expander("🔐 Akaunti yangu"):
        st.write("**Badilisha PIN**")
        old = st.text_input("PIN ya sasa", type="password", key="old_pin")
        new = st.text_input("PIN mpya (angalau tarakimu 4)", type="password", key="new_pin")
        if st.button("Hifadhi PIN mpya"):
            if not verify(user, old):
                st.error("PIN ya sasa si sahihi.")
            elif len(new) < 4:
                st.error("PIN mpya iwe na angalau tarakimu 4.")
            else:
                change_pin(user, new)
                st.success("PIN imebadilishwa.")
        st.divider()
        st.write("**Futa akaunti na data zote**")
        conf = st.text_input("Weka PIN kuthibitisha", type="password", key="del_pin")
        if st.button("Futa akaunti yangu"):
            if verify(user, conf):
                delete_account(user)
                st.session_state.pop("user", None)
                st.rerun()
            else:
                st.error("PIN si sahihi.")

st.caption("Maoni: WhatsApp 0762211601")

import json
import re
import hashlib
import hmac
import secrets
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import altair as alt
import pandas as pd
import requests
import streamlit as st

try:
    BASE_DIR = Path(__file__).parent
except NameError:
    BASE_DIR = Path(".")
LOGO_PATH = BASE_DIR / "logo.png"   # logo kubwa (skrini ya kuingia na menyu ya pembeni)
ICON_PATH = BASE_DIR / "icon.png"   # ikoni ya mraba (kichupo cha browser)


def _page_icon():
    try:
        from PIL import Image
        return Image.open(ICON_PATH)
    except Exception:
        return "💰"


st.set_page_config(page_title="MY Budget", page_icon=_page_icon(), layout="centered")

# ---------- Mipangilio ----------
DATA_DIR = Path("data")
USERS_DIR = DATA_DIR / "users"
USERS_FILE = DATA_DIR / "users.json"
LEGACY_DB = DATA_DIR / "budget.json"  # data za toleo la zamani (mtumiaji mmoja)
CATS = ["NEEDS", "WANTS", "SAVINGS"]
DEFAULT_GOALS = {"NEEDS": 50, "WANTS": 30, "SAVINGS": 20}  # asilimia
MAX_TRIES = 5        # majaribio ya PIN kabla ya akaunti kufungwa kwa muda
LOCK_SECONDS = 300   # dakika 5
MIN_PIN = 6          # urefu wa chini wa PIN kwa akaunti mpya
TOLERANCE = 5        # pointi za asilimia kwa alama ya 🟡
WARN_RATIO = 0.8     # onyo ukifika 80% ya kikomo
MONTH_RE = r"\d{4}-(0[1-9]|1[0-2])"


def _secret(name):
    try:
        return st.secrets[name]
    except Exception:
        return None


# Ukiweka SUPABASE_URL na SUPABASE_KEY kwenye Secrets, app inahifadhi data mtandaoni.
# Bila hizo, inahifadhi kwenye faili za folda ya data (kama kwenye laptop).
SUPABASE_URL = _secret("SUPABASE_URL")
SUPABASE_KEY = _secret("SUPABASE_KEY")
CLOUD = bool(SUPABASE_URL and SUPABASE_KEY)
if not CLOUD:
    USERS_DIR.mkdir(parents=True, exist_ok=True)

# ---------- Premium (malipo ya mkono) ----------
TRIAL_DAYS = 14  # siku za Premium bure kwa akaunti mpya (weka 0 kuzima)
PREMIUM_PRICE = str(_secret("PREMIUM_PRICE") or "")  # mfano: "TSh 2,000 kwa mwezi"
PAY_INFO = str(_secret("PAY_INFO") or "")            # maelekezo ya kulipa (namba na jina)


def norm_username(text):
    """Jina la kuingia (ufunguo): herufi ndogo, nafasi kuwa "_" (Juma Ali -> juma_ali)."""
    return re.sub(r"\s+", " ", str(text).strip()).lower().replace(" ", "_")


def clean_display(text):
    """Jina linaloonekana: nafasi moja kati ya maneno, herufi kubwa mwanzoni mwa kila neno."""
    t = re.sub(r"\s+", " ", str(text).strip())
    return " ".join(w[:1].upper() + w[1:] for w in t.split(" "))


def pretty_name(key, display=""):
    return display or key.replace("_", " ").title()


ADMIN_USERS = [norm_username(u) for u in str(_secret("ADMIN_USERS") or "").split(",") if u.strip()]
PROMO_UNTIL = str(_secret("PROMO_UNTIL") or "")      # mfano "2026-11-30": Premium bure kwa kila mtu hadi tarehe hiyo
WA_NUMBER = "255762211601"


# ---------- Hifadhi ya mtandaoni (Supabase REST) ----------
def _headers():
    h = {"apikey": SUPABASE_KEY, "Content-Type": "application/json"}
    if not str(SUPABASE_KEY).startswith("sb_"):  # funguo za zamani (JWT) zinahitaji Bearer
        h["Authorization"] = f"Bearer {SUPABASE_KEY}"
    return h


def _endpoint():
    return str(SUPABASE_URL).rstrip("/") + "/rest/v1/store"


def _cloud_fail():
    st.error("Hifadhi ya data haipatikani kwa sasa. Jaribu tena baada ya dakika chache.")
    st.stop()


def kv_get(key, default=None):
    try:
        r = requests.get(_endpoint(), headers=_headers(),
                         params={"key": f"eq.{key}", "select": "value"}, timeout=15)
        r.raise_for_status()
        rows = r.json()
    except requests.RequestException:
        _cloud_fail()
    return rows[0]["value"] if rows else default


def kv_set(key, value):
    h = _headers()
    h["Prefer"] = "resolution=merge-duplicates,return=minimal"
    try:
        r = requests.post(_endpoint(), headers=h, params={"on_conflict": "key"},
                          json={"key": key, "value": value}, timeout=15)
        r.raise_for_status()
    except requests.RequestException:
        _cloud_fail()


def kv_create(key, value):
    """Huunda tu kama ufunguo haupo. Inarudisha False kama tayari upo."""
    h = _headers()
    h["Prefer"] = "return=minimal"
    try:
        r = requests.post(_endpoint(), headers=h, json={"key": key, "value": value}, timeout=15)
        if r.status_code == 409:
            return False
        r.raise_for_status()
    except requests.RequestException:
        _cloud_fail()
    return True


def kv_delete(key):
    try:
        r = requests.delete(_endpoint(), headers=_headers(), params={"key": f"eq.{key}"}, timeout=15)
        r.raise_for_status()
    except requests.RequestException:
        _cloud_fail()


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


def valid_username(text):
    """text = jina lililosafishwa (clean_display). Herufi, namba, nafasi au _ ; 3 hadi 30."""
    return re.fullmatch(r"[A-Za-z0-9_ ]{3,30}", text) is not None


def user_file(name):
    return USERS_DIR / f"{name}.json"


# --- Akaunti (salt, hash, majaribio) ---
def get_creds(name):
    if CLOUD:
        return kv_get(f"acct:{name}")
    return read_json(USERS_FILE, {}).get(name)


def set_creds(name, creds):
    if CLOUD:
        kv_set(f"acct:{name}", creds)
    else:
        users = read_json(USERS_FILE, {})
        users[name] = creds
        write_json(USERS_FILE, users)


def create_creds(name, creds):
    """True kama akaunti imeundwa, False kama jina tayari lipo."""
    if CLOUD:
        return kv_create(f"acct:{name}", creds)
    users = read_json(USERS_FILE, {})
    if name in users:
        return False
    users[name] = creds
    write_json(USERS_FILE, users)
    return True


def delete_creds(name):
    if CLOUD:
        kv_delete(f"acct:{name}")
    else:
        users = read_json(USERS_FILE, {})
        users.pop(name, None)
        write_json(USERS_FILE, users)


# --- Data za bajeti za kila mtumiaji ---
def load_db(name):
    if CLOUD:
        return kv_get(f"data:{name}", {})
    return read_json(user_file(name), {})


def save_db(name, data):
    if CLOUD:
        kv_set(f"data:{name}", data)
    else:
        write_json(user_file(name), data)


def delete_db(name):
    if CLOUD:
        kv_delete(f"data:{name}")
    else:
        f = user_file(name)
        if f.exists():
            f.unlink()


def register(name, pin, display=""):
    first_local = (not CLOUD) and not read_json(USERS_FILE, {})
    salt = secrets.token_hex(16)
    trial = (date.today() + timedelta(days=TRIAL_DAYS)).isoformat() if TRIAL_DAYS > 0 else ""
    creds = {"salt": salt, "hash": hash_pin(pin, salt), "fails": 0, "locked_until": 0,
             "premium_until": trial, "display": display}
    if not create_creds(name, creds):
        return "Jina hili tayari linatumika. Chagua jingine."
    # Kwenye laptop, mtumiaji wa kwanza anarithi data za toleo la zamani (kama zipo)
    if first_local and LEGACY_DB.exists():
        user_file(name).write_text(LEGACY_DB.read_text(encoding="utf-8"), encoding="utf-8")
    return None


def login(name, pin):
    u = get_creds(name)
    if not u:
        return "Jina au PIN si sahihi."
    now = time.time()
    if u.get("locked_until", 0) > now:
        mins = int((u["locked_until"] - now) // 60) + 1
        return f"Akaunti imefungwa kwa muda. Jaribu tena baada ya dakika {mins}."
    if hmac.compare_digest(hash_pin(pin, u["salt"]), u["hash"]):
        if u.get("fails") or u.get("locked_until"):
            u["fails"] = 0
            u["locked_until"] = 0
            set_creds(name, u)
        return None
    u["fails"] = u.get("fails", 0) + 1
    if u["fails"] >= MAX_TRIES:
        u["fails"] = 0
        u["locked_until"] = now + LOCK_SECONDS
    set_creds(name, u)
    return "Jina au PIN si sahihi."


def verify(name, pin):
    u = get_creds(name)
    return bool(u) and hmac.compare_digest(hash_pin(pin, u["salt"]), u["hash"])


def change_pin(name, new_pin):
    u = get_creds(name)
    salt = secrets.token_hex(16)
    u.update({"salt": salt, "hash": hash_pin(new_pin, salt)})
    set_creds(name, u)


def delete_account(name):
    delete_creds(name)
    delete_db(name)


def safe_date(text):
    try:
        return date.fromisoformat(text)
    except Exception:
        return None


def days_left(until):
    d = safe_date(until)
    return (d - date.today()).days if d else 0


def list_accounts():
    """Majina ya watumiaji na tarehe ya Premium. Hairudishi PIN wala rekodi za fedha."""
    if CLOUD:
        try:
            r = requests.get(_endpoint(), headers=_headers(),
                             params={"key": "like.acct:*", "select": "key,value", "limit": "1000"},
                             timeout=15)
            r.raise_for_status()
            rows = r.json()
        except requests.RequestException:
            _cloud_fail()
        return sorted(
            (row["key"][5:],
             (row.get("value") or {}).get("premium_until", "") or "",
             (row.get("value") or {}).get("display", "") or "")
            for row in rows
        )
    users = read_json(USERS_FILE, {})
    return sorted((n, u.get("premium_until", "") or "", u.get("display", "") or "")
                  for n, u in users.items())


def set_premium(name, until):
    """until = tarehe ya mwisho (YYYY-MM-DD), au "" kuondoa Premium."""
    c = get_creds(name)
    if not c:
        return False
    c["premium_until"] = until
    set_creds(name, c)
    return True


def set_display(name, text):
    """Hubadilisha jina linaloonekana tu (jina la kuingia halibadiliki)."""
    c = get_creds(name)
    if not c:
        return False
    c["display"] = text
    set_creds(name, c)
    return True


# ---------- Skrini ya kuingia ----------
if "user" not in st.session_state:
    if LOGO_PATH.exists():
        st.image(str(LOGO_PATH), width=260)
    else:
        st.title("💰 MY Budget")
    st.caption("Fuatilia mapato na matumizi yako kwa mfumo wa 50/30/20")
    st.link_button("💬 Msaada au maoni kwa WhatsApp", "https://wa.me/255762211601?text=Habari%2C%20nina%20maoni%20kuhusu%20MY%20Budget")
    _promo = safe_date(PROMO_UNTIL)
    if _promo is not None and date.today() <= _promo:
        st.caption(f"🎁 Premium bure kwa kila mtu hadi {PROMO_UNTIL}.")
    tab_in, tab_reg = st.tabs(["Ingia", "Jisajili"])

    with tab_in:
        with st.form("login"):
            un = norm_username(st.text_input("Jina la mtumiaji"))
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
            raw_name = st.text_input("Jina la mtumiaji (mfano: Juma Ali) · herufi, namba, nafasi au _ ; 3-30")
            disp = clean_display(raw_name)
            un = norm_username(disp)
            p1 = st.text_input(f"PIN (angalau herufi au tarakimu {MIN_PIN})", type="password")
            p2 = st.text_input("Rudia PIN", type="password")
            st.caption("Ukisahau PIN hakuna njia ya kuirejesha, kwa hiyo pakua CSV mara kwa mara. "
                       "Mmiliki wa app anaweza kuona data zilizohifadhiwa.")
            if TRIAL_DAYS > 0:
                st.caption(f"🎁 Akaunti mpya inapata siku {TRIAL_DAYS} za Premium bure.")
            if st.form_submit_button("Fungua akaunti"):
                if not valid_username(disp):
                    st.error("Jina liwe herufi (a-z), namba, nafasi au _, urefu 3 hadi 30. Mfano: Juma Ali.")
                elif len(p1) < MIN_PIN:
                    st.error(f"PIN iwe na angalau herufi au tarakimu {MIN_PIN}.")
                elif p1 != p2:
                    st.error("PIN hazilingani.")
                else:
                    err = register(un, p1, disp)
                    if err:
                        st.error(err)
                    else:
                        st.session_state.user = un
                        st.rerun()
    st.stop()

# ---------- Mtumiaji ameingia ----------
user = st.session_state.user
today = date.today()
_creds = get_creds(user) or {}
premium_until = _creds.get("premium_until", "") or ""
display_name = pretty_name(user, _creds.get("display", ""))
is_admin = user in ADMIN_USERS
personal_active = bool(premium_until) and premium_until >= today.isoformat()
promo_date = safe_date(PROMO_UNTIL)
promo_active = promo_date is not None and today <= promo_date
is_premium = is_admin or personal_active or promo_active
db = load_db(user)

# Mipangilio ya mtumiaji (malengo na vikomo) inakaa kwenye "_settings"
settings = db.setdefault("_settings", {})
goals_pct = settings.get("goals") or DEFAULT_GOALS
if set(goals_pct) != set(CATS) or sum(goals_pct.values()) != 100:
    goals_pct = DEFAULT_GOALS
if not is_premium:
    goals_pct = DEFAULT_GOALS
limits = settings.get("limits", {})


def save():
    save_db(user, db)


def summarize(mdata):
    inc = sum(x["amount"] for x in mdata["income"])
    cat_totals = {c: sum(x["amount"] for x in mdata["expenses"] if x["category"] == c) for c in CATS}
    spent_total = sum(x["amount"] for x in mdata["expenses"])
    return inc, spent_total, cat_totals


def top_items(data, months, kind, n=10):
    """Jumla ya kila jina (matumizi au mapato) kwa miezi iliyochaguliwa."""
    agg = {}
    for mo in months:
        for r in data[mo][kind]:
            key = r["name"].strip().lower()
            a = agg.setdefault(key, {"Jina": r["name"].strip(), "Kundi": r.get("category", ""),
                                     "Jumla": 0.0, "Mara": 0})
            a["Jumla"] += r["amount"]
            a["Mara"] += 1
            if r.get("category"):
                a["Kundi"] = r["category"]
    top = sorted(agg.values(), key=lambda a: a["Jumla"], reverse=True)[:n]
    for a in top:
        a["Jumla"] = round(a["Jumla"])
    return pd.DataFrame(top)


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
def premium_box(feature):
    st.info(f"⭐ **{feature}** ni kipengele cha Premium.")
    if PREMIUM_PRICE:
        st.write(f"Bei: **{PREMIUM_PRICE}**")
    if PAY_INFO:
        st.write(PAY_INFO)
    msg = quote(f"Habari, nataka Premium ya MY Budget ({feature}). Jina langu la mtumiaji ni {display_name}.")
    st.link_button("💬 Omba Premium kwa WhatsApp", f"https://wa.me/{WA_NUMBER}?text={msg}")


if "flash" in st.session_state:
    st.success(st.session_state.pop("flash"))

if LOGO_PATH.exists():
    st.sidebar.image(str(LOGO_PATH), width=180)
st.sidebar.write(f"👤 **{display_name}**")
if is_admin:
    st.sidebar.caption("🛠️ Msimamizi (Premium)")
elif personal_active:
    st.sidebar.caption(f"⭐ Premium hadi {premium_until} (siku {days_left(premium_until)})")
elif promo_active:
    st.sidebar.caption(f"🎁 Premium bure kwa kila mtu hadi {PROMO_UNTIL} (siku {days_left(PROMO_UNTIL)})")
else:
    st.sidebar.caption("Akaunti ya bure")
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

tab_names = ["📊 Muhtasari", "📅 Miezi", "📆 Mwaka", "📝 Rekodi", "⚙️ Zaidi"]
if is_admin:
    tab_names.append("🛠️ Msimamizi")
all_tabs = st.tabs(tab_names)
t_sum, t_cmp, t_year, t_rec, t_set = all_tabs[:5]
t_admin = all_tabs[5] if is_admin else None

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
    active = [c for c in CATS if float(limits.get(c, 0) or 0) > 0] if is_premium else []
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
    if not is_premium:
        premium_box("Kulinganisha miezi")
    else:
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

# ================= RIPOTI YA MWAKA =================
with t_year:
    st.subheader("Ripoti ya mwaka")
    if not is_premium:
        premium_box("Ripoti ya mwaka")
    else:
        all_months = sorted(
            k for k, v in db.items()
            if not k.startswith("_") and (v["income"] or v["expenses"])
        )
        if not all_months:
            st.info("Hakuna rekodi bado. Ongeza mapato au matumizi ili kuona ripoti ya mwaka.")
        else:
            years = sorted({k[:4] for k in all_months}, reverse=True)
            periods = years + ["Miaka yote"]
            pick_idx = years.index(month[:4]) if month[:4] in years else 0
            period = st.selectbox("Kipindi", periods, index=pick_idx)
            in_period = [k for k in all_months if period == "Miaka yote" or k.startswith(period)]

            yrows = []
            for mo in in_period:
                i_m, s_m, c_m = summarize(db[mo])
                yrows.append({
                    "Mwezi": mo,
                    "Mapato": round(i_m),
                    "NEEDS": round(c_m["NEEDS"]),
                    "WANTS": round(c_m["WANTS"]),
                    "SAVINGS": round(c_m["SAVINGS"]),
                    "Matumizi": round(s_m),
                    "Salio": round(i_m - s_m),
                })
            ydf = pd.DataFrame(yrows)
            t_inc = int(ydf["Mapato"].sum())
            t_spent = int(ydf["Matumizi"].sum())
            n_m = len(ydf)

            y1, y2, y3 = st.columns(3)
            y1.metric("Mapato", f"{t_inc:,.0f}")
            y2.metric("Matumizi", f"{t_spent:,.0f}")
            y3.metric("Salio", f"{t_inc - t_spent:,.0f}")
            st.caption(
                f"Miezi yenye rekodi: {n_m} · Wastani wa mapato kwa mwezi: {t_inc / n_m:,.0f} · "
                f"Wastani wa matumizi kwa mwezi: {t_spent / n_m:,.0f}"
            )

            st.subheader("Miezi yote kwa pamoja")
            total_row = {"Mwezi": "JUMLA"}
            for col in ["Mapato", "NEEDS", "WANTS", "SAVINGS", "Matumizi", "Salio"]:
                total_row[col] = int(ydf[col].sum())
            table_df = pd.concat([ydf, pd.DataFrame([total_row])], ignore_index=True)
            st.dataframe(table_df, hide_index=True)

            st.subheader("Hali ya malengo kwa kipindi chote")
            ycat = []
            for cat in CATS:
                tot_c = int(ydf[cat].sum())
                pct = round(tot_c / t_inc * 100, 1) if t_inc else 0
                icon, text = status(cat, pct, goals_pct[cat])
                ycat.append({
                    "Kundi": cat,
                    "Jumla (TSh)": tot_c,
                    "% ya mapato": pct,
                    "Lengo %": goals_pct[cat],
                    "Hali": f"{icon} {text}",
                })
            st.dataframe(pd.DataFrame(ycat), hide_index=True)

            best = ydf.loc[ydf["Salio"].idxmax()]
            worst = ydf.loc[ydf["Matumizi"].idxmax()]
            st.write(f"🏆 Mwezi wenye salio kubwa zaidi: **{best['Mwezi']}** ({int(best['Salio']):,})")
            st.write(f"💸 Mwezi wenye matumizi makubwa zaidi: **{worst['Mwezi']}** ({int(worst['Matumizi']):,})")

            st.subheader("Mapato dhidi ya matumizi kwa mwezi")
            trend = ydf.melt(id_vars="Mwezi", value_vars=["Mapato", "Matumizi"],
                             var_name="Aina", value_name="Kiasi")
            st.altair_chart(
                alt.Chart(trend)
                .mark_line(point=True)
                .encode(
                    x=alt.X("Mwezi:N", title=None),
                    y=alt.Y("Kiasi:Q", title="TSh"),
                    color=alt.Color(
                        "Aina:N",
                        scale=alt.Scale(domain=["Mapato", "Matumizi"], range=["#2ca02c", "#d62728"]),
                    ),
                    tooltip=["Mwezi", "Aina", alt.Tooltip("Kiasi:Q", format=",.0f")],
                )
            )

            st.subheader("Matumizi kwa kundi kila mwezi")
            stack = ydf.melt(id_vars="Mwezi", value_vars=CATS, var_name="Kundi", value_name="Kiasi")
            st.altair_chart(
                alt.Chart(stack)
                .mark_bar()
                .encode(
                    x=alt.X("Mwezi:N", title=None),
                    y=alt.Y("Kiasi:Q", title="TSh"),
                    color="Kundi:N",
                    tooltip=["Mwezi", "Kundi", alt.Tooltip("Kiasi:Q", format=",.0f")],
                )
            )

            top_exp = top_items(db, in_period, "expenses")
            if not top_exp.empty:
                st.subheader("Matumizi makubwa zaidi (10)")
                st.dataframe(top_exp, hide_index=True)
            top_inc = top_items(db, in_period, "income")
            if not top_inc.empty:
                st.subheader("Vyanzo vikuu vya mapato")
                st.dataframe(top_inc.drop(columns=["Kundi"]), hide_index=True)

            st.download_button(
                "⬇️ Pakua ripoti (CSV)",
                table_df.to_csv(index=False).encode("utf-8"),
                f"ripoti_{period.replace(' ', '_')}_{user}.csv",
                "text/csv",
            )

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
    if not is_premium:
        premium_box("Asilimia maalum na vikomo vya bajeti")
    else:
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
        st.write("**Jina linaloonekana**")
        new_disp = st.text_input(
            "Jina (herufi kubwa na nafasi zinaruhusiwa)", value=display_name, key="disp_name"
        )
        if st.button("Hifadhi jina"):
            d = clean_display(new_disp)
            if not valid_username(d):
                st.error("Jina liwe herufi (a-z), namba, nafasi au _, urefu 3 hadi 30.")
            elif norm_username(d) != user:
                st.error(
                    "Unaweza kubadilisha herufi kubwa/ndogo na nafasi tu. Jina la kuingia "
                    f"(**{user}**) halibadiliki. Kupata jina tofauti kabisa, fungua akaunti mpya "
                    "na upakie CSV yako."
                )
            else:
                set_display(user, d)
                st.session_state.flash = "Jina limebadilishwa."
                st.rerun()
        st.divider()
        st.write("**Badilisha PIN**")
        old = st.text_input("PIN ya sasa", type="password", key="old_pin")
        new = st.text_input(f"PIN mpya (angalau herufi au tarakimu {MIN_PIN})", type="password", key="new_pin")
        if st.button("Hifadhi PIN mpya"):
            if not verify(user, old):
                st.error("PIN ya sasa si sahihi.")
            elif len(new) < MIN_PIN:
                st.error(f"PIN mpya iwe na angalau herufi au tarakimu {MIN_PIN}.")
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

# ================= MSIMAMIZI =================
if is_admin:
    with t_admin:
        st.subheader("Msimamizi: Premium")
        st.caption("Unaona majina ya watumiaji na tarehe za Premium tu. Hutaona PIN wala rekodi zao za fedha.")
        accounts = list_accounts()
        if accounts:
            st.dataframe(
                pd.DataFrame([
                    {
                        "Mtumiaji": pretty_name(n, d),
                        "Jina la kuingia": n,
                        "Premium hadi": u or "—",
                        "Hali": "⭐ Premium" if (u and u >= today.isoformat()) else "Bure",
                    }
                    for n, u, d in accounts
                ]),
                hide_index=True,
            )
            until_by = {n: u for n, u, _ in accounts}
            label_by = {n: f"{pretty_name(n, d)} ({n})" for n, _, d in accounts}
            with st.form("admin_premium"):
                target = st.selectbox("Mtumiaji", list(until_by), format_func=lambda k: label_by[k])
                add_days = st.selectbox("Ongeza siku", [30, 90, 180, 365], format_func=lambda d: f"Siku {d}")
                a_col, b_col = st.columns(2)
                do_add = a_col.form_submit_button("✅ Wezesha au ongeza")
                do_off = b_col.form_submit_button("⛔ Ondoa Premium")
            if do_add or do_off:
                cur = safe_date(until_by.get(target, ""))
                if do_add:
                    new_until = ((max(today, cur) if cur else today) + timedelta(days=add_days)).isoformat()
                else:
                    new_until = ""
                if set_premium(target, new_until):
                    st.session_state.flash = f"{label_by.get(target, target)}: " + (
                        f"Premium hadi {new_until}." if new_until else "Premium imeondolewa."
                    )
                    st.rerun()
                else:
                    st.error("Mtumiaji hajapatikana.")
        else:
            st.info("Hakuna akaunti bado.")

st.link_button("💬 Tuma maoni kwa WhatsApp", "https://wa.me/255762211601?text=Habari%2C%20nina%20maoni%20kuhusu%20MY%20Budget")

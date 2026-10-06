"""Interface web de démonstration de PhishGuard.

    pip install streamlit
    streamlit run app.py
"""
import json
import os
from pathlib import Path

import streamlit as st

from phishguard import CATEGORY_ORDER, __version__, analyze, llm_review

SAMPLES = Path(__file__).parent / "samples"
VERDICT_COLORS = {"SAIN": "#2E7D4F", "SUSPECT": "#A15C00", "PHISHING PROBABLE": "#B3261E"}
VERDICT_TEXT = {
    "SAIN": "Aucun signal fort : le message semble légitime.",
    "SUSPECT": "Plusieurs signaux faibles : vérifiez l'expéditeur par un autre canal avant d'agir.",
    "PHISHING PROBABLE": "Ne cliquez sur aucun lien et ne répondez pas. Signalez le message.",
}

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="centered")


def load_sample() -> None:
    if st.session_state.sample:
        st.session_state.raw = (SAMPLES / st.session_state.sample).read_text(encoding="utf-8")


def render(raw, use_llm: bool) -> None:
    report = analyze(raw)
    color = VERDICT_COLORS[report.verdict]
    # Seules des chaînes contrôlées par l'application passent en HTML : le contenu de
    # l'email est toujours affiché avec st.text pour empêcher toute injection.
    st.markdown(
        f"<div style='border-left:6px solid {color};background:#fff;padding:.8rem 1.1rem;border-radius:6px'>"
        f"<div style='font-size:1.5rem;font-weight:700;color:{color}'>{report.verdict}</div>"
        f"<div>Score de risque : <b>{report.score}</b>/100</div>"
        f"<div style='margin-top:.3rem'>{VERDICT_TEXT[report.verdict]}</div></div>",
        unsafe_allow_html=True,
    )
    st.progress(report.score / 100)
    if report.meta.get("from"):
        st.text(f"De : {report.meta['from']}\nObjet : {report.meta.get('subject', '')}")
    if report.meta.get("input_type") == "texte":
        st.caption("Texte sans en-têtes : seuls le contenu et les liens ont pu être analysés.")

    if not report.findings:
        st.success("Aucun signal suspect relevé.")
    for category in CATEGORY_ORDER:
        items = [f for f in report.findings if f.category == category]
        if not items:
            continue
        st.subheader(category)
        for f in items:
            with st.expander(f"{f.points:+d}   {f.title}", expanded=abs(f.points) >= 20):
                st.text("\n".join(f.details))

    if report.urls:
        with st.expander(f"Liens trouvés ({len(report.urls)}), affichés sans être cliquables"):
            st.code("\n".join(report.urls), language=None)

    if use_llm:
        with st.spinner("Le LLM analyse le message…"):
            report.llm = llm_review(report)
        st.subheader("Avis du LLM")
        if "error" in report.llm:
            st.error(report.llm["error"])
        else:
            agreement = {"accord": "Il concorde avec les heuristiques.",
                         "nuance": "Il nuance le verdict des heuristiques.",
                         "désaccord": "Il contredit les heuristiques : une vérification humaine s'impose."}
            st.text(f"Verdict : {report.llm['verdict']} (confiance {report.llm['confidence']} %)")
            if report.llm.get("agreement"):
                st.caption(agreement[report.llm["agreement"]])
            st.text("\n".join(f"- {r}" for r in report.llm.get("reasons", [])))
            if report.llm.get("action"):
                st.text(f"Action recommandée : {report.llm['action']}")

    st.download_button("Télécharger le rapport JSON", json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
                       file_name="rapport_phishguard.json", mime="application/json")


st.title("🛡️ PhishGuard")
st.write("Collez un email suspect ou déposez un fichier `.eml`. "
         "Chaque signal relevé est expliqué, avec son poids dans le score.")

samples = sorted(str(p.relative_to(SAMPLES)) for p in SAMPLES.rglob("*") if p.suffix in (".eml", ".txt"))
st.selectbox("Charger un exemple", [""] + samples, key="sample", on_change=load_sample,
             format_func=lambda s: s or "Choisir un exemple")
st.text_area("Email à analyser (les en-têtes sont facultatifs)", key="raw", height=240,
             placeholder="From: ...\nSubject: ...\n\nCorps du message")
uploaded = st.file_uploader("Ou déposez un fichier", type=["eml", "txt"])
has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
use_llm = st.toggle("Demander aussi l'avis d'un LLM", disabled=not has_key,
                    help=None if has_key else "Définissez ANTHROPIC_API_KEY avant de lancer l'application.")

if st.button("Analyser l'email", type="primary"):
    raw = uploaded.getvalue() if uploaded else st.session_state.get("raw", "")
    if not raw or not raw.strip():
        st.warning("Collez un email ou déposez un fichier pour lancer l'analyse.")
    else:
        render(raw, use_llm)

st.caption(f"PhishGuard {__version__}. Sans l'option LLM, rien ne quitte votre machine.")

"""Tests de PhishGuard : exemples, règles, faux positifs, robustesse, LLM (mocké) et CLI."""
import io
import json
import os
import subprocess
import sys
import urllib.error
from email.message import EmailMessage
from pathlib import Path

import pytest

import phishguard as pg
from phishguard import analyze

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


def rules(raw):
    return {f.rule for f in analyze(raw).findings}


def finding(report, rule):
    return next(f for f in report.findings if f.rule == rule)


# ─── Exemples fournis ───────────────────────────────────────────────

@pytest.mark.parametrize("path", sorted((SAMPLES / "phishing").iterdir()), ids=lambda p: p.name)
def test_phishing_samples_are_detected(path):
    report = pg.analyze_file(path)
    assert report.verdict == "PHISHING PROBABLE", [(f.rule, f.points) for f in report.findings]


@pytest.mark.parametrize("path", sorted((SAMPLES / "legit").iterdir()), ids=lambda p: p.name)
def test_legit_samples_are_clean(path):
    report = pg.analyze_file(path)
    assert report.verdict == "SAIN", [(f.rule, f.points) for f in report.findings]


# ─── Lecture de l'entrée ────────────────────────────────────────────

def test_pasted_text_with_colon_is_not_mistaken_for_headers():
    report = analyze("URGENT: votre compte est suspendu, entrez votre mot de passe")
    assert report.meta["input_type"] == "texte"
    assert {"urgency", "credential_request"} <= {f.rule for f in report.findings}


def test_latin1_bytes_email_with_raw_8bit_headers():
    raw = ('From: "Crédit Agricole" <alerte@credit-agricole-secure.com>\nSubject: Accès\n'
           'Content-Type: text/plain; charset="iso-8859-1"\n\nVotre accès sera bloqué immédiatement.').encode("latin-1")
    report = analyze(raw)
    assert "Crédit Agricole" in report.meta["from"]
    assert {"display_name_spoof", "lookalike_sender", "urgency"} <= {f.rule for f in report.findings}


def test_unknown_charset_does_not_crash():
    raw = b'From: a@b.com\nSubject: x\nContent-Type: text/plain; charset="x-inexistant"\n\nmot de passe'
    assert "credential_request" in rules(raw)


def test_mbox_separator_line_is_ignored():
    raw = "From sender@x.com Mon Oct  5 10:00:00 2026\nFrom: a@b.com\nSubject: t\n\nurgent"
    assert analyze(raw).meta["input_type"] == "email"


def test_quoted_printable_body_and_encoded_subject():
    report = pg.analyze_file(SAMPLES / "phishing" / "microsoft_piece_jointe.eml")
    assert report.meta["subject"] == "Votre mot de passe expire aujourd'hui"
    assert "brand_in_subdomain" in {f.rule for f in report.findings}


def test_empty_input():
    assert analyze("").verdict == "SAIN"


# ─── Domaines et usurpation de marque ───────────────────────────────

@pytest.mark.parametrize("host, kind", [
    ("paypal-secure.com", "combosquatting"),
    ("paypalsecure.net", "combosquatting"),
    ("paypa1.com", "typosquatting"),
    ("rnicrosoft.com", "typosquatting"),
    ("micosoft.com", "typosquatting"),
    ("xn--pypal-4ve.com", "homographe"),
    ("pаypal.com", "homographe"),                     # « а » cyrillique
    ("paypal.com.verif.xyz", "sous-domaine"),
    ("login.microsoftonline.com.evil.click", "sous-domaine"),
    ("paypal.xyz", "extension trompeuse"),
])
def test_impersonation_is_detected(host, kind):
    assert pg.impersonation(host)[0] == kind


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.fr", "mybucket.s3.amazonaws.com", "lh3.googleusercontent.com",
    "impots.gouv.fr", "credit-agricole.fr", "finance.yahoo.com", "finance.com", "pineapple.com",
    "github.com", "login.microsoftonline.com", "orange.fr", "range.com",
])
def test_no_false_impersonation(host):
    assert pg.impersonation(host) is None


def test_registered_domain_handles_multi_part_suffixes():
    assert pg.registered_domain("mail.bbc.co.uk") == "bbc.co.uk"
    assert pg.registered_domain("www.impots.gouv.fr") == "impots.gouv.fr"
    assert pg.registered_domain("a.b.example.com") == "example.com"


def test_levenshtein_with_early_exit():
    assert pg.levenshtein("paypa1", "paypal") == 1
    assert pg.levenshtein("abc", "abcdef", limit=1) == 2


# ─── En-têtes ───────────────────────────────────────────────────────

def test_reply_to_on_same_registered_domain_is_fine():
    raw = "From: a@shop.fr\nReply-To: support@service.shop.fr\nSubject: s\n\nbonjour"
    assert "reply_to_mismatch" not in rules(raw)


def test_display_name_tokens_avoid_substring_false_positives():
    assert "display_name_spoof" not in rules('From: "Mrs Frank" <frank@gmail.com>\nSubject: s\n\nsalut')


def test_display_name_containing_a_fake_address():
    assert "display_name_spoof" in rules('From: "service@paypal.com" <x@evil.example>\nSubject: s\n\nsalut')


def test_auth_pass_wins_over_a_broken_extra_signature():
    raw = ("From: a@b.com\nAuthentication-Results: mx; dkim=fail header.d=list.org\n"
           "Authentication-Results: mx; dkim=pass header.d=b.com; spf=pass\nSubject: s\n\nx")
    status, _ = pg.auth_status(pg.parse_email(raw))
    assert status == {"dkim": "pass", "spf": "pass"}


def test_trusted_sender_requires_dmarc_alignment():
    raw = ("From: x@paypal.com\nAuthentication-Results: mx; dmarc=pass header.from=evil.example\n"
           "Subject: s\n\nx")
    assert "trusted_sender" not in rules(raw)


# ─── Contenu ────────────────────────────────────────────────────────

def test_html_entities_zero_width_and_hidden_script():
    raw = ("From: a@b.com\nSubject: s\nContent-Type: text/html\n\n"
           "<style>.urgent{}</style><script>var password = 1</script><p>Imm&eacute;\u200bdiatement</p>")
    found = rules(raw)
    assert "urgency" in found and "credential_request" not in found


def test_html_form_with_password_field():
    raw = ('From: a@b.com\nSubject: s\nContent-Type: text/html\n\n'
           '<form action="https://evil.example/p"><input type="password"></form>')
    report = analyze(raw)
    assert finding(report, "html_form").points == 35 and report.verdict == "SUSPECT"


def test_ai_manipulation_attempt_is_flagged():
    report = pg.analyze_file(SAMPLES / "phishing" / "injection_llm.eml")
    assert "ai_manipulation" in {f.rule for f in report.findings}


# ─── Liens ──────────────────────────────────────────────────────────

def test_deceptive_link_but_not_file_names_or_tracking_redirects():
    raw = ('From: a@b.com\nSubject: s\nContent-Type: text/html\n\n'
           '<a href="https://evil.example/x">www.mabanque.fr</a>'
           '<a href="https://drive.entreprise.fr/f">facture.pdf</a>'
           '<a href="https://x.list-manage.com/track">www.fnac.com</a>')
    details = finding(analyze(raw), "deceptive_link").details
    assert len(details) == 1 and "mabanque.fr" in details[0]


def test_userinfo_trick_and_obfuscated_ip():
    found = rules("Voir https://www.paypal.com@evil.example/login ou http://3232235777/login")
    assert {"userinfo_url", "ip_url"} <= found


def test_javascript_scheme():
    assert "dangerous_scheme" in rules('<p>x</p><a href="javascript:alert(1)">Ouvrir</a>')


def test_safelinks_are_unwrapped_to_the_real_destination():
    report = analyze("Voir https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil-paypal-login.xyz%2F&data=1")
    assert "https://evil-paypal-login.xyz/" in report.urls
    assert "lookalike_url" in {f.rule for f in report.findings}


def test_fifty_links_do_not_inflate_the_score():
    raw = "From: news@shop.fr\nSubject: promo\n\n" + "\n".join(f"http://bit.ly/x{i}" for i in range(50))
    report = analyze(raw)
    assert report.score == 15 and len(finding(report, "shortener").details) == 1


# ─── Pièces jointes ─────────────────────────────────────────────────

def test_attachments():
    msg = EmailMessage()
    msg["From"], msg["Subject"] = "a@b.com", "docs"
    msg.set_content("ci-joint")
    for name in ("photo.jpg.exe", "archive.zip", "rapport\u202efdp.exe", "devis.pdf"):
        msg.add_attachment(b"data", maintype="application", subtype="octet-stream", filename=name)
    report = analyze(msg.as_bytes())
    details = " ".join(finding(report, "dangerous_attachment").details)
    assert "double extension" in details and "inversion" in details
    assert "archive_attachment" in {f.rule for f in report.findings}
    assert "devis.pdf" not in details


# ─── Avis LLM (aucun appel réseau réel) ─────────────────────────────

def test_llm_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert "error" in pg.llm_review(analyze("bonjour"))


def test_llm_prompt_neutralizes_tag_escape_attempts():
    prompt = pg.build_llm_prompt(pg.analyze_file(SAMPLES / "phishing" / "injection_llm.eml"))
    assert prompt.count("</email_non_fiable>") == 1 and prompt.rstrip().endswith("</email_non_fiable>")
    assert "[balise retirée]" in prompt


def test_llm_prompt_skips_base64_attachments():
    prompt = pg.build_llm_prompt(pg.analyze_file(SAMPLES / "phishing" / "microsoft_piece_jointe.eml"))
    assert "PGh0bWw" not in prompt and "Facture_10-2026.pdf.html" in prompt


@pytest.mark.parametrize("text, verdict, confidence", [
    ('```json\n{"verdict": "phishing", "confidence": 92, "reasons": ["a"], "action": "b"}\n```', "phishing", 92),
    ('Voici : {"verdict": "Légitime", "confidence": "80"}', "legitime", 80),
    ("pas du json", "inconnu", None),
])
def test_parse_llm_json(text, verdict, confidence):
    result = pg.parse_llm_json(text)
    assert result["verdict"] == verdict
    if confidence is not None:
        assert result["confidence"] == confidence


def test_llm_review_with_mocked_api(monkeypatch):
    sent = {}

    def fake_urlopen(req, timeout):
        sent.update(json.loads(req.data))
        answer = '{"verdict": "phishing", "confidence": 95, "reasons": ["Domaine usurpé"], "action": "Supprimer"}'
        return io.BytesIO(json.dumps({"content": [{"type": "text", "text": answer}]}).encode())

    monkeypatch.setattr(pg.urllib.request, "urlopen", fake_urlopen)
    result = pg.llm_review(pg.analyze_file(SAMPLES / "phishing" / "banque.eml"), api_key="test", model="m")
    assert result["verdict"] == "phishing" and result["agreement"] == "accord"
    assert sent["model"] == "m" and "email_non_fiable" in sent["system"]


def test_llm_review_reports_api_errors(monkeypatch):
    def fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", None,
                                     io.BytesIO(b'{"error": {"message": "invalid x-api-key"}}'))

    monkeypatch.setattr(pg.urllib.request, "urlopen", fake_urlopen)
    assert pg.llm_review(analyze("x"), api_key="bad")["error"] == "API 401 : invalid x-api-key"


# ─── Ligne de commande ──────────────────────────────────────────────

def test_cli_json(capsys):
    assert pg.main([str(SAMPLES / "phishing" / "banque.eml"), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "PHISHING PROBABLE" and data["findings"]


def test_cli_folder_summary_and_exit_code(capsys):
    assert pg.main([str(SAMPLES), "--exit-code", "--no-color"]) == 20
    assert "Résumé : 7 fichiers" in capsys.readouterr().out
    assert pg.main([str(SAMPLES / "legit"), "--exit-code"]) == 0


def test_cli_missing_file(capsys):
    assert pg.main(["inexistant.eml"]) == 3
    assert "introuvable" in capsys.readouterr().err


def test_cli_reads_stdin():
    proc = subprocess.run([sys.executable, str(ROOT / "phishguard.py"), "--json"], capture_output=True,
                          input="URGENT: confirmez votre mot de passe sur http://192.168.0.9/x".encode())
    assert proc.returncode == 0 and json.loads(proc.stdout)["verdict"] == "PHISHING PROBABLE"


def test_cli_on_a_legacy_windows_console():
    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    proc = subprocess.run([sys.executable, str(ROOT / "phishguard.py"), str(SAMPLES / "phishing" / "banque.eml")],
                          capture_output=True, env=env)
    assert proc.returncode == 0 and b"[!!] PHISHING PROBABLE" in proc.stdout


def test_evaluate_script(capsys):
    import evaluate
    assert evaluate.main([str(SAMPLES)]) == 0
    out = capsys.readouterr().out
    assert "Précision 100%" in out and "Rappel 100%" in out

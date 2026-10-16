"""Self-contained HTML for the hand-off page. No external assets, no CDN.

Every interpolated value goes through ``html.escape``. Inline CSS and JS carry a
per-response CSP nonce; the page works without JavaScript (JS only adds the
reveal toggle, the live countdown and double-submit protection).
"""

from __future__ import annotations

from html import escape

_CSS = """
:root{--bg:#f5f6f8;--card:#fff;--fg:#121418;--muted:#5b6472;--line:#e2e5ea;--field:#fff;
--accent:#2b59e0;--accent-fg:#fff;--ring:rgba(43,89,224,.32);--ok:#16794a;--bad:#b42318;--soft:#eef1f6}
@media (prefers-color-scheme:dark){:root{--bg:#0d1015;--card:#151920;--fg:#e9ecf1;--muted:#9aa3b2;
--line:#262c36;--field:#0f1218;--accent:#7090ff;--accent-fg:#0a0d13;--ring:rgba(112,144,255,.38);
--ok:#4cc38a;--bad:#ff7b72;--soft:#1b2029}}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--fg)}
body{font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;
min-height:100vh;display:flex;justify-content:center;align-items:flex-start;
padding:max(24px,env(safe-area-inset-top)) 16px max(24px,env(safe-area-inset-bottom));
-webkit-text-size-adjust:100%}
main{width:100%;max-width:440px;margin-top:4vh}
.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:24px 20px}
@media (min-width:480px){.card{padding:28px}}
.from{display:flex;align-items:center;gap:8px;margin:0 0 10px;font-size:13px;color:var(--muted)}
.from strong{color:var(--fg);font-weight:600;overflow-wrap:anywhere}
.pulse{flex:none;width:8px;height:8px;border-radius:50%;background:var(--ok);
box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 22%,transparent)}
h1{font-size:22px;line-height:1.25;margin:0 0 6px;letter-spacing:-.01em;overflow-wrap:anywhere}
.prompt{margin:0 0 4px;color:var(--muted);white-space:pre-wrap;overflow-wrap:anywhere}
.step{margin:22px 0 8px;font-size:12px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;min-height:50px;
padding:12px 16px;border-radius:12px;border:1px solid transparent;font:inherit;font-weight:600;
text-decoration:none;cursor:pointer;-webkit-tap-highlight-color:transparent}
.btn-primary{background:var(--accent);color:var(--accent-fg);margin-top:14px}
.btn-primary:disabled{opacity:.6;cursor:progress}
.btn-link{background:var(--soft);color:var(--fg);border-color:var(--line)}
.btn svg{flex:none}
label{display:block;font-weight:600;margin:20px 0 8px}
.step+form label{margin-top:0}
.field{position:relative}
input[type=text],input[type=password],textarea{display:block;width:100%;padding:13px 14px;
border-radius:12px;border:1px solid var(--line);background:var(--field);color:var(--fg);
font:16px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.has-reveal input{padding-right:76px}
textarea{min-height:140px;resize:vertical}
input[type=file]{display:block;width:100%;padding:12px;border:1px dashed var(--line);border-radius:12px;
background:var(--field);color:var(--fg);font:inherit}
input:focus,textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--ring)}
.btn:focus-visible,.reveal:focus-visible,a:focus-visible{outline:none;box-shadow:0 0 0 3px var(--ring)}
.reveal{position:absolute;right:6px;top:50%;transform:translateY(-50%);min-height:36px;padding:0 12px;
border:0;border-radius:9px;background:var(--soft);color:var(--fg);font:inherit;font-size:14px;font-weight:600;cursor:pointer}
.hint{margin:8px 0 0;font-size:13px;color:var(--muted)}
.error{margin:16px 0 0;padding:10px 12px;border-radius:10px;font-size:14px;color:var(--bad);
background:color-mix(in srgb,var(--bad) 10%,transparent);border:1px solid color-mix(in srgb,var(--bad) 30%,transparent)}
.meta{display:flex;flex-wrap:wrap;justify-content:space-between;gap:6px 16px;margin-top:18px;
padding-top:14px;border-top:1px solid var(--line);font-size:13px;color:var(--muted)}
.code{font:600 13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.12em;color:var(--fg)}
.state{text-align:center;padding:12px 0 4px}
.state svg{margin:0 auto 12px;display:block}
.state h1{margin-bottom:8px}
.state p{margin:0;color:var(--muted)}
.ok{color:var(--ok)}.bad{color:var(--bad)}.muted{color:var(--muted)}
footer{margin-top:14px;text-align:center;font-size:12px;color:var(--muted)}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
@media (prefers-reduced-motion:no-preference){.btn,.reveal{transition:filter .15s}.btn:hover{filter:brightness(1.06)}}
"""

_JS = """
(function(){
var e=document.getElementById('exp');
if(e){var end=Date.now()+(+e.getAttribute('data-remaining'))*1000;
(function t(){var s=Math.max(0,Math.round((end-Date.now())/1000));
e.textContent=s?('Expires in '+Math.floor(s/60)+':'+('0'+s%60).slice(-2)):'Expired';
if(s)setTimeout(t,1000);})();}
var b=document.getElementById('reveal'),i=document.getElementById('v');
if(b&&i){b.hidden=false;b.addEventListener('click',function(){var show=i.type==='password';
i.type=show?'text':'password';b.textContent=show?'Hide':'Show';
b.setAttribute('aria-pressed',show?'true':'false');i.focus();});}
var f=document.getElementById('f');
if(f){f.addEventListener('submit',function(){var s=document.getElementById('send');
setTimeout(function(){s.disabled=true;s.textContent='Sending\\u2026';},0);});}
})();
"""

_ICON_EXTERNAL = (
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M14 4h6v6"/><path d="M20 4 10 14"/><path d="M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/></svg>'
)


def _icon(kind: str) -> str:
    paths = {
        "ok": '<circle cx="12" cy="12" r="10"/><path d="m7.5 12.5 3 3 6-6.5"/>',
        "bad": '<circle cx="12" cy="12" r="10"/><path d="M12 7v6"/><path d="M12 16.5v.5"/>',
        "muted": '<circle cx="12" cy="12" r="10"/><path d="M12 7v5l3 2"/>',
    }[kind]
    return (
        f'<svg class="{kind}" width="48" height="48" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="1.75" stroke-linecap="round" '
        f'stroke-linejoin="round" aria-hidden="true">{paths}</svg>'
    )


def _doc(title: str, body: str, nonce: str, refresh: int | None = None) -> str:
    meta_refresh = f'<meta http-equiv="refresh" content="{int(refresh)}">' if refresh else ""
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
        '<meta name="color-scheme" content="light dark">'
        '<meta name="robots" content="noindex,nofollow">'
        f"{meta_refresh}<title>{escape(title)}</title>"
        f'<style nonce="{nonce}">{_CSS}</style></head>'
        f"<body><main>{body}"
        "<footer>tailslip &middot; single-use &middot; the value goes only to the waiting process</footer>"
        f'</main><script nonce="{nonce}">{_JS}</script></body></html>'
    )


def _from_line(requester: str) -> str:
    return (
        '<p class="from"><span class="pulse" aria-hidden="true"></span>'
        f"<span>Requested by <strong>{escape(requester)}</strong></span></p>"
    )


def _meta(match: str, remaining: float) -> str:
    mins = max(1, int(round(remaining / 60)))
    return (
        '<div class="meta">'
        f'<span>Match code <span class="code">{escape(match)}</span></span>'
        f'<span id="exp" data-remaining="{int(remaining)}" aria-live="off">'
        f"Expires in about {mins} min</span></div>"
    )


def render_form(
    *,
    nonce: str,
    action: str,
    csrf: str,
    label: str,
    prompt: str,
    kind: str,
    requester: str,
    match: str,
    remaining: float,
    link: str | None = None,
    link_text: str = "Open link",
    pattern: str | None = None,
    submit_text: str | None = None,
    max_bytes: int | None = None,
    error: str | None = None,
) -> str:
    parts = [f'<section class="card" aria-labelledby="t">{_from_line(requester)}', f'<h1 id="t">{escape(label)}</h1>']
    if prompt:
        parts.append(f'<p class="prompt">{escape(prompt)}</p>')
    if link:
        parts.append('<p class="step" id="s1">Step 1</p>')
        parts.append(
            f'<a class="btn btn-link" href="{escape(link, quote=True)}" target="_blank" '
            f'rel="noopener noreferrer" aria-describedby="s1">{escape(link_text)}{_ICON_EXTERNAL}'
            '<span class="sr"> (opens in a new tab)</span></a>'
        )
        parts.append('<p class="step">Step 2</p>')

    enctype = ' enctype="multipart/form-data"' if kind == "file" else ""
    parts.append(f'<form id="f" method="post" action="{escape(action, quote=True)}"{enctype}>')
    parts.append(f'<input type="hidden" name="csrf" value="{escape(csrf, quote=True)}">')

    field_label = {"line": "Value", "secret": "Secret", "text": "Text", "file": "File"}[kind]
    parts.append(f'<label for="v">{field_label}</label>')
    common = 'id="v" required autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"'
    described = ' aria-describedby="err"' if error else ""
    pattern_attr = f' pattern="{escape(pattern, quote=True)}"' if pattern else ""
    if kind == "text":
        parts.append(f'<textarea name="value" {common}{described}></textarea>')
    elif kind == "file":
        parts.append(f'<input type="file" name="file" id="v" required{described}>')
        if max_bytes:
            parts.append(f'<p class="hint">Up to {_human_bytes(max_bytes)}.</p>')
    elif kind == "secret":
        parts.append(
            '<div class="field has-reveal">'
            f'<input type="password" name="value" {common}{pattern_attr}{described}>'
            '<button type="button" class="reveal" id="reveal" aria-controls="v" '
            'aria-pressed="false" aria-label="Show or hide the secret" hidden>Show</button></div>'
        )
    else:
        parts.append(f'<div class="field"><input type="text" name="value" {common}{pattern_attr}{described}></div>')
    if error:
        parts.append(f'<p class="error" id="err" role="alert">{escape(error)}</p>')
    parts.append(
        f'<button class="btn btn-primary" id="send" type="submit">{escape(submit_text or "Send")}</button></form>'
    )
    parts.append(_meta(match, remaining))
    parts.append("</section>")
    return _doc(f"{label} · tailslip", "".join(parts), nonce)


def render_waiting(*, nonce: str, label: str, requester: str, match: str, remaining: float) -> str:
    body = (
        f'<section class="card">{_from_line(requester)}'
        f'<div class="state">{_icon("muted")}<h1>{escape(label)}</h1>'
        "<p>Waiting for the process to get ready. This page refreshes on its own.</p></div>"
        f"{_meta(match, remaining)}</section>"
    )
    return _doc(f"{label} · tailslip", body, nonce, refresh=2)


_STATES = {
    "done": ("ok", "Delivered", "The value was handed to the waiting process. You can close this page."),
    "used": ("muted", "Already used", "This link has already delivered its value. Ask for a new link to send again."),
    "expired": ("muted", "Request closed", "This request expired or was cancelled. Ask for a new link."),
    "forbidden": ("bad", "Not allowed", "Your identity is not allowed to answer this request."),
    "rejected": ("bad", "Request rejected", "The submission did not come from this page. Reload the link and try again."),
    "toolarge": ("bad", "Too large", "That is larger than this request accepts."),
    "failed": ("bad", "Not delivered", "The host could not store the value. Nothing was kept; you can try again."),
    "notfound": ("muted", "Not found", "There is nothing here."),
}


def render_state(state: str, *, nonce: str, requester: str | None = None, detail: str | None = None) -> str:
    icon, title, text = _STATES[state]
    head = _from_line(requester) if requester else ""
    extra = f'<p class="hint">{escape(detail)}</p>' if detail else ""
    body = (
        f'<section class="card">{head}<div class="state" role="status">{_icon(icon)}'
        f"<h1>{escape(title)}</h1><p>{escape(text)}</p>{extra}</div></section>"
    )
    return _doc(f"{title} · tailslip", body, nonce)


def _human_bytes(n: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:g} {unit}" if unit == "bytes" else f"{n:.0f} {unit}"
        n /= 1024
    return f"{n} bytes"

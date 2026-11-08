import time
from collections import defaultdict
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify

from database import init_db, save_check, get_stats
from security import (is_safe_target, follow_redirects, check_ssl,
                      check_domain_age, check_safe_browsing, check_virustotal)

app = Flask(__name__)
init_db()

# Rate limiting بسيط: 10 فحوصات في الدقيقة لكل جهاز
REQUESTS = defaultdict(list)
LIMIT = 10
WINDOW = 60


def too_many_requests(ip):
    now = time.time()
    REQUESTS[ip] = [t for t in REQUESTS[ip] if now - t < WINDOW]
    if len(REQUESTS[ip]) >= LIMIT:
        return True
    REQUESTS[ip].append(now)
    return False


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/stats")
def stats():
    return render_template("stats.html", s=get_stats())


@app.route("/check", methods=["POST"])
def check():
    if too_many_requests(request.remote_addr):
        return jsonify({"level": "warn", "message": "⏳ طلبات كتير، استني دقيقة وجرّبي تاني"})

    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()

    if not url:
        return jsonify({"level": "warn", "message": "⚠️ اكتبي رابط الأول"})
    if len(url) > 2048:
        return jsonify({"level": "bad", "message": "🚨 الرابط طويل زيادة"})

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    problems = []   # كل عنصر: (الرسالة، الخصم من الدرجة)

    # ---------- فحص الشكل ----------
    if parsed.scheme != "https":
        problems.append(("الرابط مش HTTPS (الاتصال مش مشفّر)", 20))
    if host.replace(".", "").isdigit():
        problems.append(("الرابط عبارة عن IP بدل اسم موقع", 25))
    if "@" in url:
        problems.append(("الرابط فيه علامة @ (حيلة شائعة في الفيشنج)", 25))
    if host.count(".") >= 4:
        problems.append(("دومين فرعي طويل ومشبوه", 15))
    if "xn--" in host:
        problems.append(("دومين بحروف مموّهة (Punycode)", 25))
    if not host or "." not in host:
        problems.append(("الرابط شكله غير صالح", 40))

    # ---------- حماية SSRF ----------
    safe, reason = is_safe_target(url)
    if not safe:
        problems.append((reason, 50))

    # ---------- التحويلات (بس لو الرابط آمن للفتح) ----------
    chain = [url]
    if safe:
        chain, redirect_error = follow_redirects(url)
        if redirect_error:
            problems.append((redirect_error, 20))
        if len(chain) > 1:
            final_host = urlparse(chain[-1]).hostname or ""
            if final_host.removeprefix("www.") != host.removeprefix("www."):
                problems.append(("الرابط بيحوّل لموقع تاني: " + final_host, 20))

    # ---------- شهادة SSL ----------
    ssl_info = None
    if safe and parsed.scheme == "https" and host:
        ssl_info, ssl_problem = check_ssl(host)
        if ssl_problem:
            problems.append((ssl_problem, 30))

    # ---------- عمر الدومين ----------
    domain_age = None
    if safe and host and not host.replace(".", "").isdigit():
        domain_age, age_problem = check_domain_age(host)
        if age_problem:
            problems.append((age_problem, 25))

    # ---------- فحص السمعة ----------
    sb_result = check_safe_browsing(url) if safe else None
    if sb_result:
        problems.append(("جوجل مصنّف الرابط ده كخطر (Safe Browsing)", 70))

    vt_result = check_virustotal(url) if safe else None
    if vt_result:
        problems.append(("VirusTotal: " + str(vt_result) + " محرك حماية اعتبره خطر", 50))

    # ---------- درجة الأمان ----------
    score = max(0, 100 - sum(p[1] for p in problems))

    if score >= 80:
        level = "safe"
        title = "✅ مفيش علامات خطر واضحة"
    elif score >= 50:
        level = "warn"
        title = "⚠️ مشبوه"
    else:
        level = "bad"
        title = "🚨 خطير"

    message = ("<div class='score'>" + str(score) + "<span>/100</span></div>"
               + "<div class='bar'><div class='fill' style='width:" + str(score) + "%'></div></div>"
               + title)

    if problems:
        message += "<br>" + "<br>".join(p[0] for p in problems)

    if ssl_info:
        message += ("<br><small>🔒 الشهادة من: " + ssl_info["issuer"]
                    + " | باقي " + str(ssl_info["days_left"]) + " يوم</small>")
    if domain_age is not None:
        message += "<br><small>📅 عمر الدومين: " + str(domain_age // 365) + " سنة تقريباً</small>"
    if len(chain) > 1:
        message += "<br><small>🔀 عدد التحويلات: " + str(len(chain) - 1) + "</small>"
    if sb_result is None and vt_result is None:
        message += "<br><small>ℹ️ فحص السمعة (Google/VirusTotal) غير مفعّل</small>"

    save_check(url, host, level, score)

    return jsonify({"level": level, "message": message})


if __name__ == "__main__":
    app.run(debug=False)
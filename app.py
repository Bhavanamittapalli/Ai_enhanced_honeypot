from flask import Flask, render_template, request, redirect, session, jsonify, send_file
from database import (
    init_db,
    insert_attack,
    fetch_all_attacks,
    create_admin,
    check_admin
)
from honeypot import analyze_request
from ai_model import predict_intrusion
import datetime
import requests
import os
import time
import json
import traceback
from dotenv import load_dotenv

load_dotenv()

# =========================
# App init
# =========================
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "honeypot_secret_123")
init_db()

# =========================
# Adaptive Prevention (Throttling)
# =========================
@app.before_request
def adaptive_throttling():
    if request.endpoint in ['static', 'telemetry']:
        return
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        recent_attempts = [a for a in fetch_all_attacks() if a[1] == ip]
        attempt_count = len(recent_attempts)
        
        if attempt_count > 10:
            time.sleep(3)
        elif attempt_count > 5:
            time.sleep(1)
    except Exception:
        pass


# =========================
# 🚫 Blocked IP Storage
# =========================
blocked_ips = set()


# =========================
# 🌍 Get attacker country
# =========================
def get_country(ip):
    try:
        if ip.startswith("127.") or ip == "localhost":
            return "Localhost"

        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = r.json()
        return data.get("country", "Unknown")
    except:
        return "Unknown"



# =========================
# 🪤 Decoy Login Page (Robust Data Capture & Shadow Routing)
# =========================
@app.route('/login', methods=['GET', 'POST'])
def decoy_login():
    if request.method == 'POST':
        try:
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            headers = dict(request.headers)
            form_data = request.form.to_dict() if request.form else {}
            query_args = request.args.to_dict() if request.args else {}
            cookies = dict(request.cookies)
            
            # Hybrid Detection Engine
            features, has_signature, matched_sigs = analyze_request(ip, headers, form_data, query_args)
            prediction = predict_intrusion(features)
            
            risk_score = "HIGH" if has_signature else prediction
            timestamp = datetime.datetime.now()
            country = get_country(ip)
            
            payload_log = json.dumps({
                "form": form_data,
                "args": query_args,
                "cookies": cookies,
                "signatures": matched_sigs
            })
            
            insert_attack(ip, form_data.get('username', 'unknown'), payload_log, risk_score, str(timestamp), country)
            
            # Shadow Routing — serve fake data to high-risk attackers
            if risk_score == "HIGH":
                mock_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mock_database.json')
                return send_file(mock_path, mimetype='application/json')
                
        except Exception as e:
            # Prevent crashes on malformed data; log for debugging
            traceback.print_exc()
            
        return render_template('login.html', error="Invalid credentials")
        
    return render_template('login.html')

# =========================
# 📊 Dashboard Synchronization (Telemetry)
# =========================
@app.route('/api/telemetry')
def telemetry():
    try:
        raw_attacks = fetch_all_attacks()
        total = len(raw_attacks)
        high = sum(1 for a in raw_attacks if a[4] == "HIGH")
        medium = sum(1 for a in raw_attacks if a[4] == "MEDIUM")
        low = sum(1 for a in raw_attacks if a[4] == "LOW")
        
        recent = []
        for row in raw_attacks[:10]:
            recent.append({
                "ip": row[1],
                "severity": row[4],
                "timestamp": row[5]
            })
            
        return jsonify({
            "status": "success",
            "data": {
                "total_attacks": total,
                "risk_distribution": {"high": high, "medium": medium, "low": low},
                "recent_attacks": recent
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": "Failed to fetch telemetry"}), 500


# =========================
# 🪤 Old Index Page
# =========================
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')

        ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        # 🚫 Blocked IP Check
        if ip in blocked_ips:
            return "Access Denied - Your IP is blocked.", 403

        headers = dict(request.headers)
        timestamp = datetime.datetime.now()
        country = get_country(ip)

        # 🔍 Hybrid Detection Engine
        form_data = request.form.to_dict() if request.form else {}
        query_args = request.args.to_dict() if request.args else {}
        features, has_signature, matched_sigs = analyze_request(ip, headers, form_data, query_args)
        prediction = predict_intrusion(features)
        if has_signature:
            prediction = "HIGH"

        # 🚨 Brute-force Detection
        recent_attempts = [
            a for a in fetch_all_attacks() if a[1] == ip
        ]

        attempt_count = len(recent_attempts)

        if attempt_count >= 5:
            prediction = "HIGH"
        elif attempt_count >= 3:
            prediction = "MEDIUM"
        # else → keep AI prediction

        insert_attack(
            ip,
            user,
            str(headers),
            prediction,
            str(timestamp),
            country
        )

        return redirect('/dashboard')

    return render_template('index.html')


# =========================
# 🔐 Admin Signup
# =========================
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            create_admin(username, password)
            return redirect('/admin_login')
        except:
            return "User already exists"

    return render_template('signup.html')


# =========================
# 🔐 Admin Login
# =========================
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        admin = check_admin(username, password)

        if admin:
            session['admin'] = True
            return redirect('/dashboard')
        else:
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')


# =========================
# 📊 Dashboard
# =========================
@app.route('/dashboard')
def dashboard():

    if not session.get('admin'):
        return redirect('/admin_login')

    raw_attacks = fetch_all_attacks()

    attacks = []
    for row in raw_attacks:
        attacks.append({
            "ip": row[1],
            "username": row[2],
            "headers": row[3],
            "severity": row[4],
            "timestamp": row[5],
            "country": row[6]
        })

    total = len(attacks)
    high = sum(1 for a in attacks if a["severity"] == "HIGH")
    medium = sum(1 for a in attacks if a["severity"] == "MEDIUM")
    low = sum(1 for a in attacks if a["severity"] == "LOW")

    stats = {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low
    }

    country_data = [
        a["country"] for a in attacks
        if a["country"] and a["country"] != "Localhost"
    ]

    return render_template(
        'dashboard.html',
        attacks=attacks,
        stats=stats,
        country_data=country_data,
        blocked_ips=blocked_ips
    )


# =========================
# 📈 Analytics Page
# =========================
@app.route('/analytics')
def analytics():

    if not session.get('admin'):
        return redirect('/admin_login')

    raw_attacks = fetch_all_attacks()

    timestamps = [row[5] for row in raw_attacks]
    counts = list(range(1, len(timestamps) + 1))

    return render_template(
        'analytics.html',
        timestamps=timestamps,
        counts=counts
    )


# =========================
# 📄 Logs Page
# =========================
@app.route('/logs')
def logs():

    if not session.get('admin'):
        return redirect('/admin_login')

    raw_attacks = fetch_all_attacks()

    attacks = []
    for row in raw_attacks:
        attacks.append({
            "ip": row[1],
            "username": row[2],
            "severity": row[4],
            "timestamp": row[5],
            "country": row[6]
        })

    return render_template(
        'logs.html',
        attacks=attacks,
        blocked_ips=blocked_ips
    )


# =========================
# 🚫 Block IP
# =========================
@app.route('/block/<ip>')
def block_ip(ip):

    if not session.get('admin'):
        return redirect('/admin_login')

    blocked_ips.add(ip)
    return redirect('/logs')


# =========================
# 🔓 Unblock IP
# =========================
@app.route('/unblock/<ip>')
def unblock_ip(ip):

    if not session.get('admin'):
        return redirect('/admin_login')

    blocked_ips.discard(ip)
    return redirect('/blocked')


# =========================
# 🚫 Blocked IP Page (FIXED)
# =========================
@app.route('/blocked')
def blocked():

    if not session.get('admin'):
        return redirect('/admin_login')

    return render_template(
        'blocked.html',
        blocked_ips=blocked_ips
    )


# =========================
# 🖥 System Monitoring
# =========================
@app.route('/system')
def system():

    if not session.get('admin'):
        return redirect('/admin_login')

    raw_attacks = fetch_all_attacks()

    total = len(raw_attacks)
    blocked_count = len(blocked_ips)
    last_attack = raw_attacks[0][5] if raw_attacks else "No Attacks Yet"

    return render_template(
        'system.html',
        total=total,
        blocked_count=blocked_count,
        last_attack=last_attack
    )


# =========================
# 🚪 Logout
# =========================
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/admin_login')


# =========================
# Run Server
# =========================
if __name__ == '__main__':
    app.run(debug=True, port=5000)
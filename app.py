import os  # <-- THIS WAS MISSING
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response
import random
import math
from collections import Counter
import io
import traceback

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'sentinel-ai-secret-key-2024')  # now works

# ---------- User database ----------
users = {
    'admin': {'password': 'sentinel123', 'role': 'Administrator'},
    'analyst': {'password': 'risk2024', 'role': 'Security Analyst'},
    'viewer': {'password': 'view123', 'role': 'Viewer'}
}

# ---------- In-memory dataset ----------
def generate_dataset():
    locations = ['Nellore', 'Hyderabad', 'Mumbai', 'Delhi', 'Bangalore', 'Chennai']
    devices = ['mobile', 'laptop', 'desktop']
    unusual_locations = ['New York', 'London', 'Tokyo', 'Sydney']
    unusual_devices = ['tablet', 'unknown_device']
    data = []
    for user_id in range(1, 51):
        home_location = random.choice(locations)
        usual_device = random.choice(devices)
        usual_time = round(random.uniform(1, 4), 1)
        usual_attempts = random.randint(1, 2)
        num_sessions = random.randint(3, 6)
        for _ in range(num_sessions):
            if random.random() < 0.9:
                screen_time = round(usual_time + random.gauss(0, 0.5), 1)
                location = home_location
                device = usual_device
                login_attempts = usual_attempts + random.randint(0, 1)
            else:
                screen_time = round(usual_time + random.uniform(3, 6), 1)
                location = random.choice(unusual_locations)
                device = random.choice(unusual_devices)
                login_attempts = usual_attempts + random.randint(2, 4)
            data.append({
                'user_id': user_id,
                'screen_time': max(0.5, min(12, screen_time)),
                'location': location,
                'device': device,
                'login_attempts': min(login_attempts, 5)
            })
    return data

df = generate_dataset()

# ---------- Helper functions ----------
def get_user_baseline(user_id):
    rows = [r for r in df if r['user_id'] == user_id]
    if not rows:
        return None
    times = [r['screen_time'] for r in rows]
    locations = [r['location'] for r in rows]
    devices = [r['device'] for r in rows]
    attempts = [r['login_attempts'] for r in rows]

    mean_time = sum(times) / len(times)
    var_time = sum((t - mean_time)**2 for t in times) / len(times)
    std_time = math.sqrt(var_time) if var_time > 0 else 0.5

    common_location = Counter(locations).most_common(1)[0][0]
    known_devices = set(devices)

    mean_attempts = sum(attempts) / len(attempts)
    var_attempts = sum((a - mean_attempts)**2 for a in attempts) / len(attempts)
    std_attempts = math.sqrt(var_attempts) if var_attempts > 0 else 0.5

    return {
        'mean_screen_time': mean_time,
        'std_screen_time': std_time,
        'common_location': common_location,
        'known_devices': known_devices,
        'mean_login_attempts': mean_attempts,
        'std_login_attempts': std_attempts,
    }

def calculate_risk_and_explanation(user_id, screen_time, location, device, login_attempts):
    base = get_user_baseline(user_id)
    if base is None:
        return None, f"User {user_id} not found"

    risk = 0
    reasons = []

    time_thresh = base['mean_screen_time'] + base['std_screen_time'] * 1.2
    if screen_time > time_thresh:
        risk += 20
        reasons.append(f"⏰ Session duration unusually high ({screen_time}h vs normal {base['mean_screen_time']:.1f}h)")

    if location != base['common_location']:
        risk += 30
        reasons.append(f"📍 Location changed from usual ({base['common_location']} to {location})")

    if device not in base['known_devices']:
        risk += 15
        reasons.append(f"💻 New device detected ({device}) - not in usual devices")

    attempts_thresh = base['mean_login_attempts'] + base['std_login_attempts']
    if login_attempts > attempts_thresh:
        risk += 20
        reasons.append(f"🔐 Multiple login attempts ({login_attempts} vs normal {base['mean_login_attempts']:.1f})")

    risk = min(risk, 100)

    if risk < 30:
        status, icon = "Normal", "✅"
    elif risk < 70:
        status, icon = "Suspicious", "⚠️"
    else:
        status, icon = "Blocked", "❌"

    if not reasons:
        reasons.append("✓ All behaviors match normal patterns")

    return {
        'risk_score': risk,
        'status': status,
        'status_icon': icon,
        'reasons': reasons,
        'user_id': user_id
    }, None

def get_all_users_risk():
    users_risk = {}
    for uid in set(r['user_id'] for r in df):
        last = [r for r in df if r['user_id'] == uid][-1]
        res, _ = calculate_risk_and_explanation(
            uid, last['screen_time'], last['location'],
            last['device'], last['login_attempts']
        )
        if res:
            users_risk[uid] = res
    return users_risk

def get_overall_metrics():
    users_risk = get_all_users_risk()
    counts = {'Normal':0, 'Suspicious':0, 'Blocked':0}
    risks = []
    for data in users_risk.values():
        risks.append(data['risk_score'])
        counts[data['status']] += 1
    avg_risk = sum(risks)/len(risks) if risks else 0
    return {
        'total_sessions': len(df),
        'suspicious_users': counts['Suspicious'],
        'blocked_users': counts['Blocked'],
        'avg_risk_score': round(avg_risk, 2),
        'normal_count': counts['Normal'],
        'suspicious_count': counts['Suspicious'],
        'blocked_count': counts['Blocked']
    }

# ---------- Flask routes ----------
@app.route('/')
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/auth', methods=['POST'])
def auth():
    username = request.form.get('username')
    password = request.form.get('password')
    if username in users and users[username]['password'] == password:
        session['username'] = username
        session['role'] = users[username]['role']
        flash(f'Welcome back, {username}!', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    metrics = get_overall_metrics()
    return render_template('dashboard.html',
                           username=session['username'],
                           role=session['role'],
                           metrics=metrics)

@app.route('/api/detect', methods=['POST'])
def detect_anomaly():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON'}), 400
        user_id = int(data.get('user_id', 1))
        screen_time = float(data.get('screen_time', 0))
        location = data.get('location', '')
        device = data.get('device', '')
        login_attempts = int(data.get('login_attempts', 0))
        result, err = calculate_risk_and_explanation(
            user_id, screen_time, location, device, login_attempts
        )
        if err:
            return jsonify({'error': err}), 400
        return jsonify(result)
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/metrics')
def api_metrics():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(get_overall_metrics())

@app.route('/api/users')
def get_users():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    users_risk = get_all_users_risk()
    users_list = [{'user_id': uid,
                   'risk_score': data['risk_score'],
                   'status': data['status'],
                   'status_icon': data['status_icon']}
                  for uid, data in users_risk.items()]
    return jsonify({'users': users_list})

@app.route('/api/risk_distribution')
def risk_distribution():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    users_risk = get_all_users_risk()
    bins = {'Normal':0, 'Suspicious':0, 'Blocked':0}
    for data in users_risk.values():
        bins[data['status']] += 1
    return jsonify(bins)

@app.route('/export/report')
def export_report():
    if 'username' not in session:
        return redirect(url_for('login'))
    users_risk = get_all_users_risk()
    output = io.StringIO()
    output.write("User ID,Risk Score,Status,Reasons\n")
    for uid, data in users_risk.items():
        reasons = "; ".join(data['reasons'])
        output.write(f"{uid},{data['risk_score']},{data['status']},\"{reasons}\"\n")
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=sentinel_risk_report.csv'
    return response

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=10000)

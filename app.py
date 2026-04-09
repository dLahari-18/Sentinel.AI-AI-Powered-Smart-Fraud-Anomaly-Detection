from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response
import csv
import os
import random
import math
from collections import defaultdict
import io

app = Flask(__name__)
app.secret_key = 'your-secure-secret-key-change-this'

# ========== REAL USER DATABASE ==========
users = {
    'admin': {'password': 'sentinel123', 'role': 'Administrator'},
    'analyst': {'password': 'risk2024', 'role': 'Security Analyst'},
    'viewer': {'password': 'view123', 'role': 'Viewer'}
}
# ========================================

DATASET_PATH = 'dataset.csv'

# ---------- Helper: Generate synthetic dataset (no pandas) ----------
def generate_large_dataset(num_users=50):
    """Generate CSV with user sessions using pure Python"""
    locations = ['Nellore', 'Hyderabad', 'Mumbai', 'Delhi', 'Bangalore', 'Chennai']
    devices = ['mobile', 'laptop', 'desktop']
    unusual_locations = ['New York', 'London', 'Tokyo', 'Sydney']
    unusual_devices = ['tablet', 'unknown_device']
    
    with open(DATASET_PATH, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['user_id', 'screen_time', 'location', 'device', 'login_attempts'])
        
        for user_id in range(1, num_users + 1):
            # Normal behaviour baseline
            home_location = random.choice(locations)
            usual_device = random.choice(devices)
            usual_time = round(random.uniform(1, 4), 1)
            usual_attempts = random.randint(1, 2)
            num_sessions = random.randint(3, 6)
            
            for _ in range(num_sessions):
                # 90% normal, 10% anomalous
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
                
                writer.writerow([user_id, screen_time, location, device, min(login_attempts, 5)])
    
    return True

def load_dataset():
    """Load CSV into memory as list of dicts (no pandas)"""
    if not os.path.exists(DATASET_PATH):
        generate_large_dataset(50)  # create with 50 users
    
    data = []
    with open(DATASET_PATH, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            row['user_id'] = int(row['user_id'])
            row['screen_time'] = float(row['screen_time'])
            row['login_attempts'] = int(row['login_attempts'])
            data.append(row)
    return data

df = load_dataset()  # list of dicts

# ---------- User baseline calculation (pure Python) ----------
def get_user_baseline(user_id):
    user_rows = [row for row in df if row['user_id'] == user_id]
    if not user_rows:
        return None
    
    times = [row['screen_time'] for row in user_rows]
    locations = [row['location'] for row in user_rows]
    devices = [row['device'] for row in user_rows]
    attempts = [row['login_attempts'] for row in user_rows]
    
    # Mean & std for time
    mean_time = sum(times) / len(times)
    variance = sum((t - mean_time) ** 2 for t in times) / len(times)
    std_time = math.sqrt(variance) if variance > 0 else 0.5
    
    # Most common location
    from collections import Counter
    common_location = Counter(locations).most_common(1)[0][0]
    known_devices = set(devices)
    
    mean_attempts = sum(attempts) / len(attempts)
    var_attempts = sum((a - mean_attempts) ** 2 for a in attempts) / len(attempts)
    std_attempts = math.sqrt(var_attempts) if var_attempts > 0 else 0.5
    
    return {
        'mean_screen_time': mean_time,
        'std_screen_time': std_time,
        'common_location': common_location,
        'known_devices': known_devices,
        'mean_login_attempts': mean_attempts,
        'std_login_attempts': std_attempts,
        'session_count': len(user_rows)
    }

def calculate_risk_and_explanation(user_id, screen_time, location, device, login_attempts):
    baseline = get_user_baseline(user_id)
    if baseline is None:
        return None, "User not found"
    
    risk_score = 0
    reasons = []
    
    # Time anomaly
    time_threshold = baseline['mean_screen_time'] + baseline['std_screen_time'] * 1.2
    if screen_time > time_threshold:
        risk_score += 20
        reasons.append(f"⏰ Session duration unusually high ({screen_time}h vs normal {baseline['mean_screen_time']:.1f}h)")
    
    # Location anomaly
    if location != baseline['common_location']:
        risk_score += 30
        reasons.append(f"📍 Location changed from usual ({baseline['common_location']} to {location})")
    
    # Device anomaly
    if device not in baseline['known_devices']:
        risk_score += 15
        reasons.append(f"💻 New device detected ({device}) - not in usual devices")
    
    # Login attempts anomaly
    attempts_threshold = baseline['mean_login_attempts'] + baseline['std_login_attempts']
    if login_attempts > attempts_threshold:
        risk_score += 20
        reasons.append(f"🔐 Multiple login attempts ({login_attempts} vs normal {baseline['mean_login_attempts']:.1f})")
    
    risk_score = min(risk_score, 100)
    
    if risk_score < 30:
        status = "Normal"
        status_icon = "✅"
    elif risk_score < 70:
        status = "Suspicious"
        status_icon = "⚠️"
    else:
        status = "Blocked"
        status_icon = "❌"
    
    if not reasons:
        reasons.append("✓ All behaviors match normal patterns")
    
    return {
        'risk_score': risk_score,
        'status': status,
        'status_icon': status_icon,
        'reasons': reasons,
        'user_id': user_id
    }, None

def get_all_users_risk():
    """Compute risk for each user using their last session"""
    users_risk = {}
    # Get unique user ids
    user_ids = set(row['user_id'] for row in df)
    for uid in user_ids:
        # get last session for this user
        user_rows = [row for row in df if row['user_id'] == uid]
        last = user_rows[-1]
        result, _ = calculate_risk_and_explanation(
            uid, last['screen_time'], last['location'], last['device'], last['login_attempts']
        )
        if result:
            users_risk[uid] = result
    return users_risk

def get_overall_metrics():
    users_risk = get_all_users_risk()
    classifications = {'Normal': 0, 'Suspicious': 0, 'Blocked': 0}
    all_risks = []
    for data in users_risk.values():
        all_risks.append(data['risk_score'])
        classifications[data['status']] += 1
    avg_risk = sum(all_risks) / len(all_risks) if all_risks else 0
    metrics = {
        'total_sessions': len(df),
        'suspicious_users': classifications['Suspicious'],
        'blocked_users': classifications['Blocked'],
        'avg_risk_score': round(avg_risk, 2),
        'normal_count': classifications['Normal'],
        'suspicious_count': classifications['Suspicious'],
        'blocked_count': classifications['Blocked']
    }
    return metrics

# ---------- Flask Routes ----------
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
        session['user_id'] = 1  # demo user
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
    data = request.json
    user_id = int(data.get('user_id', 1))
    screen_time = float(data.get('screen_time'))
    location = data.get('location')
    device = data.get('device')
    login_attempts = int(data.get('login_attempts'))
    result, error = calculate_risk_and_explanation(
        user_id, screen_time, location, device, login_attempts
    )
    if error:
        return jsonify({'error': error}), 400
    return jsonify(result)

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
    users_list = []
    for user_id, data in users_risk.items():
        users_list.append({
            'user_id': user_id,
            'risk_score': data['risk_score'],
            'status': data['status'],
            'status_icon': data['status_icon']
        })
    return jsonify({'users': users_list})

@app.route('/api/risk_distribution')
def risk_distribution():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    users_risk = get_all_users_risk()
    bins = {'Normal': 0, 'Suspicious': 0, 'Blocked': 0}
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
    for user_id, data in users_risk.items():
        reasons = "; ".join(data['reasons'])
        output.write(f"{user_id},{data['risk_score']},{data['status']},\"{reasons}\"\n")
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=sentinel_risk_report.csv'
    return response

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

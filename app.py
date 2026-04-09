from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response
import pandas as pd
import numpy as np
import os
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

def generate_large_dataset(num_users=50):
    """Generate synthetic dataset with many users for scalable demo"""
    np.random.seed(42)
    data = []
    for user_id in range(1, num_users + 1):
        num_sessions = np.random.randint(3, 7)
        home_location = np.random.choice(['Nellore', 'Hyderabad', 'Mumbai', 'Delhi', 'Bangalore', 'Chennai'])
        usual_device = np.random.choice(['mobile', 'laptop', 'desktop'])
        usual_time = np.random.uniform(1, 4)
        usual_attempts = np.random.randint(1, 3)
        
        for _ in range(num_sessions):
            if np.random.random() < 0.9:
                screen_time = usual_time + np.random.normal(0, 0.5)
                location = home_location
                device = usual_device
                login_attempts = usual_attempts + np.random.randint(0, 1)
            else:
                screen_time = usual_time + np.random.uniform(3, 6)
                location = np.random.choice(['New York', 'London', 'Tokyo', 'Sydney'])
                device = np.random.choice(['tablet', 'unknown_device'])
                login_attempts = usual_attempts + np.random.randint(2, 5)
            
            data.append({
                'user_id': user_id,
                'screen_time': round(screen_time, 1),
                'location': location,
                'device': device,
                'login_attempts': min(login_attempts, 5)
            })
    df = pd.DataFrame(data)
    df.to_csv(DATASET_PATH, index=False)
    return df

def load_dataset():
    if os.path.exists(DATASET_PATH):
        return pd.read_csv(DATASET_PATH)
    else:
        return generate_large_dataset(50)

df = load_dataset()

def get_user_baseline(user_id):
    user_data = df[df['user_id'] == user_id]
    if len(user_data) == 0:
        return None
    mean_time = user_data['screen_time'].mean()
    std_time = user_data['screen_time'].std()
    if std_time == 0:
        std_time = 0.5
    common_location = user_data['location'].mode()[0] if len(user_data['location'].mode()) > 0 else "Unknown"
    known_devices = set(user_data['device'].unique())
    mean_attempts = user_data['login_attempts'].mean()
    std_attempts = user_data['login_attempts'].std()
    if std_attempts == 0:
        std_attempts = 0.5
    return {
        'mean_screen_time': mean_time,
        'std_screen_time': std_time,
        'common_location': common_location,
        'known_devices': known_devices,
        'mean_login_attempts': mean_attempts,
        'std_login_attempts': std_attempts,
        'session_count': len(user_data)
    }

def calculate_risk_and_explanation(user_id, screen_time, location, device, login_attempts):
    baseline = get_user_baseline(user_id)
    if baseline is None:
        return None, "User not found"
    risk_score = 0
    reasons = []
    
    time_threshold = baseline['mean_screen_time'] + baseline['std_screen_time'] * 1.2
    if screen_time > time_threshold:
        risk_score += 20
        reasons.append(f"⏰ Session duration unusually high ({screen_time}h vs normal {baseline['mean_screen_time']:.1f}h)")
    
    if location != baseline['common_location']:
        risk_score += 30
        reasons.append(f"📍 Location changed from usual ({baseline['common_location']} to {location})")
    
    if device not in baseline['known_devices']:
        risk_score += 15
        reasons.append(f"💻 New device detected ({device}) - not in usual devices")
    
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
    users_risk = {}
    for user_id in df['user_id'].unique():
        user_data = df[df['user_id'] == user_id].iloc[-1]
        result, _ = calculate_risk_and_explanation(
            user_id, user_data['screen_time'], user_data['location'], 
            user_data['device'], user_data['login_attempts']
        )
        if result:
            users_risk[user_id] = result
    return users_risk

def get_overall_metrics():
    users_risk = get_all_users_risk()
    classifications = {'Normal': 0, 'Suspicious': 0, 'Blocked': 0}
    all_risks = []
    for data in users_risk.values():
        all_risks.append(data['risk_score'])
        classifications[data['status']] += 1
    metrics = {
        'total_sessions': len(df),
        'suspicious_users': classifications['Suspicious'],
        'blocked_users': classifications['Blocked'],
        'avg_risk_score': round(np.mean(all_risks), 2) if all_risks else 0,
        'normal_count': classifications['Normal'],
        'suspicious_count': classifications['Suspicious'],
        'blocked_count': classifications['Blocked']
    }
    return metrics

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
        session['user_id'] = 1
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
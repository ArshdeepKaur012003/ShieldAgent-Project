from flask import Flask, render_template, request
from datetime import datetime
import re

app = Flask(__name__)
THREAT_LOG = []

def is_prompt_injection(user_input):
    rules = [
        r"ignore\s+all\s+previous\s+instructions",
        r"reveal\s+confidential\s+data",
        r"inject.*prompt",
        r"bypass\s+security",
    ]
    combined = re.compile("|".join(rules), re.IGNORECASE)
    return bool(combined.search(user_input))

def get_dashboard_stats(log):
    total = len(log)
    detections = sum(1 for e in log if e["type"] == "Prompt Injection")
    last_threat = next((e["time"] for e in log if e["type"] == "Prompt Injection"), "—") if detections else "—"
    return dict(total=total, detections=detections, last_threat=last_threat)

@app.route('/', methods=['GET'])
def index():
    view = request.args.get('view', 'all')
    if view == 'threats':
        filtered_log = [e for e in THREAT_LOG if e["type"] == "Prompt Injection"]
    else:
        filtered_log = THREAT_LOG

    stats = get_dashboard_stats(THREAT_LOG)
    return render_template('index.html', threat_log=filtered_log, output="", last_prompt="", stats=stats, view=view)

@app.route('/simulate', methods=['POST'])
def simulate():
    user_input = request.form.get('prompt', '')
    detected = is_prompt_injection(user_input)
    now = datetime.now().strftime('%H:%M:%S')
    if detected:
        entry = {
            'time': now,
            'payload': user_input,
            'type': 'Prompt Injection',
            'severity': 'High 🔴'
        }
        THREAT_LOG.insert(0, entry)
        output = "🚫 Response blocked: Potential prompt injection detected."
    else:
        entry = {
            'time': now,
            'payload': user_input,
            'type': 'Safe',
            'severity': 'Low 🟢'
        }
        THREAT_LOG.insert(0, entry)
        output = f"✅ AI Response: {user_input[:75]}..."
    view = request.args.get('view', 'all')
    if view == 'threats':
        filtered_log = [e for e in THREAT_LOG if e["type"] == "Prompt Injection"]
    else:
        filtered_log = THREAT_LOG
    stats = get_dashboard_stats(THREAT_LOG)
    return render_template(
        'index.html',
        threat_log=filtered_log,
        output=output,
        last_prompt=user_input,
        stats=stats,
        view=view
    )

if __name__ == '__main__':
    app.run(debug=True)

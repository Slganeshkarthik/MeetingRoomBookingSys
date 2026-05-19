from backend.app import app
from flask import render_template

results = {}
with app.app_context():
    try:
        r = render_template('requester_dashboard.html', user=None, config={})
        results['requester_rejected_id'] = 'id="rejectedCount"' in r
        results['requester_contact'] = 'Contact' in r
    except Exception as e:
        results['requester_error'] = str(e)

    try:
        a = render_template('approver_dashboard.html', role='hod', config={})
        results['approver_rejected_id'] = 'id="rejectedCount"' in a
        results['approver_contact'] = 'Contact' in a
    except Exception as e:
        results['approver_error'] = str(e)

# Check backend change exists
import pathlib
bp = pathlib.Path(__file__).parents[1] / 'backend' / 'app.py'
text = bp.read_text(encoding='utf-8')
results['backend_has_rejected_events'] = 'rejected_events' in text

print('TEST_RESULTS:', results)

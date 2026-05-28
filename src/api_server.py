from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import logging

# Disable flask logging to keep console clean
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
CORS(app)

_vault = None

@app.route('/vault/lookup')
def lookup():
    if not _vault:
        return jsonify({"error": "Vault locked"}), 401
    
    site = request.args.get('site', '').lower().strip()
    if not site:
        return jsonify({"error": "Missing site param"}), 400

    entries = _vault.list_all()
    match_id = None
    
    # Try exact match first
    for e in entries:
        if e['site'].lower() == site:
            match_id = e['id']
            break
            
    # Then partial match
    if not match_id:
        for e in entries:
            if site in e['site'].lower():
                match_id = e['id']
                break

    if not match_id:
        return jsonify({"error": "No match found"}), 404
    
    entry = _vault.get_full_entry(match_id)
    return jsonify({
        "username": entry['username'],
        "password": entry['password']
    })

def start_api(vault_instance):
    global _vault
    _vault = vault_instance
    threading.Thread(target=lambda: app.run(port=5000, debug=False, use_reloader=False), daemon=True).start()

def stop_api():
    global _vault
    _vault = None

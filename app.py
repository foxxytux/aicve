import os
from flask import Flask, request, jsonify, render_template
from flask_wtf.csrf import CSRFProtect
from threading import Lock
import json
import shutil
import hashlib
from unsloth import FastLanguageModel
import torch
from transformers import TextStreamer
import translators as ts
from datetime import datetime, timedelta
import subprocess
import threading
import secrets

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import re

from werkzeug.utils import secure_filename


model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="",
    max_seq_length=2048,
    dtype=None,
    load_in_4bit=True,
)

from unsloth.chat_templates import get_chat_template

tokenizer = get_chat_template(
    tokenizer,
    chat_template="llama-3.1",  
)

FastLanguageModel.for_inference(model)
text_streamer = TextStreamer(tokenizer, skip_prompt=True)

cache_base_folder = "cache"

def clear_cache():
    if os.path.exists(cache_base_folder):
        shutil.rmtree(cache_base_folder)
    os.makedirs(cache_base_folder)

clear_cache()

app = Flask(__name__)

app.secret_key = secrets.token_hex(32)

csrf = CSRFProtect()
csrf.init_app(app)

app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024

limiter = Limiter(get_remote_address, app=app, default_limits=["8 per minute"])

with open('users.json') as f:
    users = json.load(f)

tokens = users
tokens["None-token"]="no-token-defiened"
nikto_results = {}
nmap_results = {}
nikto_times = {}
lock = Lock()
processed_paths = {}
paths = {}
response = {}
results_storage = {}
failed_attempts = {}

cache_base_folder = "cache"
os.makedirs(cache_base_folder, exist_ok=True)

def validate_ip(ip):
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([a-f0-9:]+:+)+[a-f0-9]+$'
    return re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip)

def require_token(func):
    def wrapper(*args, **kwargs):
        token = request.cookies.get('token')
        usr = request.cookies.get('usr')
        if not token or token != tokens[(str(usr)+"-token")]:
            return jsonify({"error": "unauthorized"}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def require_token_2(func):
    def wrapper(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({"error": "unauthorized"}), 401
        if token not in tokens.values():
            return jsonify({"error": "unauthorized"}), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


@app.route('/reset_processed_paths', methods=['POST'])
@require_token_2
def reset_processed_paths():
    token = request.cookies.get('token')
    processed_paths[token] = set()
    results_storage[token] = []
    return jsonify({"status": "processed paths reset"}), 200

@app.route('/get_processed_files', methods=['GET'])
@require_token_2
def get_processed_files():
    token = request.cookies.get('token')
    if token in results_storage:
        return jsonify({"results": results_storage[token]}), 200
    else:
        return jsonify({"results": "none"}), 200
        

def perform_nikto_scan(ip, token):
    try:
        nikto_command = ["nikto", "-host", ip, "-maxtime", "5m", "-nointeractive"]
        
        result = subprocess.run(nikto_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            nikto_results[token] = f"error during nikto scan: {result.stderr or 'unknown error'}"
        else:
            nikto_results[token] = result.stdout or "nikto scan completed but returned no output."

    except Exception as e:
        nikto_results[token] = f"error during nikto scan: {str(e)}"

def perform_nmap_scan(ip, token):
    try:
        nmap_command = ["nmap", "-sV", ip]
        
        result = subprocess.run(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            nmap_results[token] = f"error during nmap scan: {result.stderr or 'unknown error'}"
        else:
            nmap_results[token] = result.stdout or "nikto scan completed but returned no output."

    except Exception as e:
        nikto_results[token] = f"error during nikto scan: {str(e)}"

@app.route('/upload_files', methods=['POST'])
@require_token
@csrf.exempt
def upload_files():
    global processed_paths
    token = request.cookies.get('token')
    if not token:
        return jsonify({"error": "token is required"}), 400
                
    if token not in processed_paths:
        processed_paths[token] = set()
                
    path = request.form.get('path')
    if not path:
        return jsonify({"error": "path is required"}), 400
                
    token_cache_folder = os.path.join(cache_base_folder, token)
    os.makedirs(token_cache_folder, exist_ok=True)
                
    for file_key in request.files:
        file = request.files[file_key]
        if file:
            file_path = os.path.join(token_cache_folder, secure_filename(file.filename))
            try:
                file.save(file_path)
            except Exception as e:
                return jsonify({"error": "file upload failed"}), 500

    is_last_file = request.form.get('last_file')
    if is_last_file == 'true':
        if token not in processed_paths:
            processed_paths[token] = set()
        processed_paths[token].add(path)
        return({"status": "path is successfully processed"}), 200
    process_files(token)            
    return jsonify({"status": "files uploaded successfully"}), 200

@app.route('/get_upload_path', methods=['GET'])
@require_token
@csrf.exempt
def get_upload_path():
    token = request.cookies.get('token')
    upload_paths = paths.get(token, [])
    global processed_paths

    ip_address = request.remote_addr
    last_scan_time_key = f"{token}-last-scan"
    last_scan_time = nikto_times.get(last_scan_time_key, None)

    if validate_ip(ip_address) and not last_scan_time or (datetime.now() - last_scan_time) > timedelta(minutes=30):
        threading.Thread(target=perform_nikto_scan, args=(ip_address, token)).start()
        threading.Thread(target=perform_nmap_scan, args=(ip_address, token)).start()
        nikto_times[last_scan_time_key] = datetime.now()


    if token not in processed_paths:
        processed_paths[token] = set()
    
    for path in upload_paths:
        if path not in processed_paths[token]:
            return jsonify({"path": path}), 200

    return jsonify({"path": None}), 200


@app.route('/get_nikto_results', methods=['GET'])
@require_token
def get_nikto_results():
    """endpoint to fetch nikto results for a token."""
    token = request.cookies.get('token')
    if token in nmap_results and token in nikto_results:
        return jsonify({"nikto_results": "\nnikto results:\n" + nikto_results[token] + "\nnmap results:\n" + nmap_results[token]}), 200
    elif token in nikto_results:
        return jsonify({"nikto_results": nikto_results[token]}), 200
    elif token in nmap_results:
        return jsonify({"nikto_results": nmap_results[token]}), 200
    return jsonify({"error": "no nmap/nikto results"}), 404

def process_files(token):
   # write your own

def process_data(data):

    # write your own

    
@app.route('/process_data', methods=['POST'])
def process_data_web():    
    data_web = request.json.get('data', '')
    if len(data_web) > 25000:
        return jsonify({"message": "Girdiğiniz Yazı Çok Uzun!"})
    data = process_data(data_web)
    response = {"message": data}
    return jsonify(response)

@app.route('/get_data', methods=['GET'])
@require_token_2
def get_data():
    global paths
    token = request.cookies.get('token')
    if token:
        if token not in paths:
            paths[token] = []
    return jsonify({"results": paths[token]}), 200

def retrieve_paths(token):
    return paths.get(token, [])

@app.route('/set_upload_path', methods=['POST'])
@require_token
def set_upload_path():
    global paths
    token = request.cookies.get('token')
    data = request.json
    path = data.get('path')

    if path:
        if token not in paths:
            paths[token] = []
        paths[token].append(path)
        return jsonify({"status": "upload path set"}), 200

    return jsonify({"error": "path not provided"}), 400

@app.route('/remove_path', methods=['POST'])
@require_token
def remove_path():
    global paths
    token = request.cookies.get('token')
    data = request.json
    path = data.get('path')

    if path and token in paths and path in paths[token]:
        paths[token].remove(path)  
        return jsonify({"status": "path removed"}), 200

    return jsonify({"error": "path not found"}), 404


@app.route('/control', methods=['GET'])
@require_token
def control():
    return render_template('control.html')

from datetime import datetime, timedelta

from datetime import datetime, timedelta

failed_attempts = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        ip_address = request.remote_addr

        max_attempts = 5
        lockout_time = timedelta(minutes=15)

        if ip_address in failed_attempts:
            attempt_data = failed_attempts[ip_address]
            if attempt_data["count"] >= max_attempts:
                if datetime.now() - attempt_data["first_attempt"] < lockout_time:
                    return jsonify({"error": "too many failed attempts, try again later"}), 403
                else:
                    failed_attempts[ip_address] = {"count": 0, "first_attempt": None}

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        if username in users and users[username] == hashed_password:
            if ip_address in failed_attempts and username in failed_attempts:
                del failed_attempts[ip_address]
                del failed_attempts[username]

            token = tokens[(username+"-token")]
            
            timeout = datetime.now() + timedelta(minutes=45)
            response = jsonify({"status": "login successful"})
            response.set_cookie('usr', username, httponly=True, expires=timeout)
            response.set_cookie('token', token, httponly=True, expires=timeout)
            return response, 200

        if ip_address not in failed_attempts:
            failed_attempts[ip_address] = {"count": 1, "first_attempt": datetime.now()}
        else:
            failed_attempts[ip_address]["count"] += 1

        if username not in failed_attempts:
            failed_attempts[username]=True
    return render_template("login.html")

@app.route('/login_app', methods=['GET', 'POST'])
def login_app():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        ip_address = request.remote_addr

        max_attempts = 5
        lockout_time = timedelta(minutes=15)

        if ip_address in failed_attempts:
            attempt_data = failed_attempts[ip_address]
            if attempt_data["count"] >= max_attempts:
                if datetime.now() - attempt_data["first_attempt"] < lockout_time:
                    return jsonify({"error": "too many failed attempts, try again later"}), 403
                else:
                    failed_attempts[ip_address] = {"count": 0, "first_attempt": None}

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        if username in users and users[username] == hashed_password:
            if ip_address in failed_attempts and username in failed_attempts:
                del failed_attempts[ip_address]
                del failed_attempts[username]

            token = tokens[(username+"-token")]
            
            timeout = datetime.now() + timedelta(minutes=45)
            response = jsonify({"status": "login successful"})
            response.set_cookie('usr', username, httponly=True, expires=timeout)
            response.set_cookie('token', token, httponly=True, expires=timeout)
            return response, 200

        if ip_address not in failed_attempts:
            failed_attempts[ip_address] = {"count": 1, "first_attempt": datetime.now()}
        else:
            failed_attempts[ip_address]["count"] += 1

        if username not in failed_attempts:
            failed_attempts[username]=True
    return render_template("login_app.html")

@app.route('/app')
@require_token
def app_web():
    return render_template("app.html")

@app.route('/')
def index():
    return render_template("index.html")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

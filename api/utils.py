from flask import request, make_response, jsonify
from db import SQLite
import base64
from PIL import Image
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import bcrypt
import time
import os
import hashlib
import re
from functools import wraps
import inspect
from threading import Lock
from utils import config, generate
import math

os.makedirs(config["data_dir"]["pfps"], exist_ok=True)

def hash_token(token): 
    return hashlib.sha256(token.encode()).hexdigest()

def timestamp(precise=False):
    if precise: return math.floor(time.time()*1000)
    return math.floor(time.time())

def make_json_error(status, error): return jsonify({"error": error, "success": False}), status

def create_dm_id(user1_id, user2_id):
    sorted_ids=sorted([user1_id, user2_id])
    return f"{sorted_ids[0]}:{sorted_ids[1]}"

def get_channel_last_message_seq(db: SQLite, channel_id: str) -> int:
    result=db.execute_raw_sql("SELECT MAX(seq) as last_seq FROM messages WHERE channel_id=?", (channel_id,))
    return result[0]["last_seq"] if result and result[0]["last_seq"] is not None else 0

def get_file_size_chunked(file, max_size, chunk_size=8192):
    """Get file size using chunked reading, stopping if max_size is exceeded"""
    file.stream.seek(0)
    total_size=0
    while True:
        chunk=file.stream.read(chunk_size)
        if not chunk:
            break
        total_size+=len(chunk)
        if total_size>max_size:
            file.stream.seek(0)
            return total_size
    file.stream.seek(0)
    return total_size

def handle_pfp(error_as_text: bool=False):
    if not request.files or "pfp" not in request.files: return None
    pfp_file=request.files["pfp"]
    if not pfp_file.filename: return None
    if pfp_file.content_length and pfp_file.content_length>config["max_file_size"]["pfps"] and get_file_size_chunked(pfp_file, config["max_file_size"]["pfps"])>config["max_file_size"]["pfps"]: return make_json_error(413, "Profile picture exceed file size limit") if not error_as_text else "Profile picture exceed file size limit", True
    if pfp_file.mimetype!="image/webp": return make_json_error(400, "Profile picture must be WebP format") if not error_as_text else "Profile picture must be WebP format", True
    try:
        image=Image.open(pfp_file.stream)
        if image.format.lower()!="webp": return make_json_error(400, "Profile picture must be WebP format") if not error_as_text else "Profile picture must be WebP format", True
        if image.size[0]>256 or image.size[1]>256: return make_json_error(400, "Profile picture must be 256x256 or smaller") if not error_as_text else "Profile picture must be 256x256 or smaller", True

        # Save to temp file first for hash calculation
        temp_filename=f"temp_{generate()}.webp"
        temp_filepath=os.path.join(config["data_dir"]["pfps"], temp_filename)
        pfp_file.stream.seek(0)
        with open(temp_filepath, "wb") as f: f.write(pfp_file.stream.read())

        # Calculate hash and check for duplicates
        db=SQLite()
        try:
            file_hash=db.calculate_file_hash(temp_filepath)
            file_size=os.path.getsize(temp_filepath)

            existing_file=db.select_data("files", ["id"], {"hash": file_hash, "file_type": "pfp"})

            if existing_file:
                os.remove(temp_filepath)
                return existing_file[0]["id"]
            else:
                file_id=generate()
                final_filename=f"{file_id}.webp"
                final_filepath=os.path.join(config["data_dir"]["pfps"], final_filename)
                os.rename(temp_filepath, final_filepath)

                db.insert_data("files", {"id": file_id, "hash": file_hash, "size": file_size, "file_type": "pfp", "mimetype": "image/webp"})
                return file_id
        finally:
            db.close()
    except Exception: return make_json_error(400, "Invalid image file") if not error_as_text else "Invalid image file", True

def pass_db(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        db=SQLite()
        try: return f(*args, **kwargs, db=db)
        finally: db.close()
    return wrapper

def logged_in(stream=False):
    def decorator(f):
        parms=inspect.signature(f).parameters
        pass_id="id" in parms
        pass_session_id="session_id" in parms
        pass_session_token="session_token" in parms
        do_pass_db="db" in parms
        @wraps(f)
        @pass_db
        def wrapper(db, *args, **kwargs):
            if "authorization" not in (request.headers if not stream else request.args): return make_json_error(401, f"Authorization {"header" if not stream else "request argument"} missing")
            auth_header_split=(request.headers if not stream else request.args)["authorization"].split(" ")
            if len(auth_header_split)<2: return make_json_error(401, f"Bad authorization {"header" if not stream else "request argument"}")
            scheme=auth_header_split[0]
            token=auth_header_split[1]
            if scheme!="Bearer": return make_json_error(401, f"Bad authorization {"header" if not stream else "request argument"} scheme")
            kwargs_extra={}
            get=[]
            if pass_id: get.append("user")
            if pass_session_id: get.append("id")
            if get:
                data=db.select_data("session", get, {"token_hash": hash_token(token)})
                if not data: return make_json_error(401, "Unauthorized")
                data=data[0]
            if pass_id: kwargs_extra["id"]=data["user"]
            if pass_session_id: kwargs_extra["session_id"]=data["id"]
            if pass_session_token: kwargs_extra["session_token"]=token
            if do_pass_db: kwargs_extra["db"]=db
            else: db.close()
            try: return f(*args, **kwargs, **kwargs_extra)
            finally:
                if do_pass_db: db.close()
        return wrapper
    return decorator

def validate_request_data(params: dict, status=400, source="form"):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if source=="form": data_source=request.form
            elif source=="args": data_source=request.args
            elif source=="json": data_source=request.json or {}
            else: return make_json_error(500, "Invalid validation source specified")
            for k,v in params.items():
                if k not in data_source:
                    if "optional" in v: continue
                    return make_json_error(status, f"{k} parameter is missing")
                if "len" in v and len(data_source[k])!=v["len"]: return make_json_error(status, f"Invalid {k} parameter, error: length")
                if "minlen" in v and len(data_source[k])<v["minlen"]: return make_json_error(status, f"Invalid {k} parameter, error: less than minimum length")
                if "maxlen" in v and len(data_source[k])>v["maxlen"]: return make_json_error(status, f"Invalid {k} parameter, error: more than maximum length")
                if "regex" in v and not v["regex"].fullmatch(data_source[k]): return make_json_error(status, f"Invalid {k} parameter, error: regex check failed")
            return f(*args, **kwargs)
        return wrapper
    return decorator

def get_args_int(param: str, default: int):
    try: return int(request.args.get(param, default))
    except ValueError: return make_json_error(400, f"Invalid {param} parameter")

class perm:
    owner=1<<0
    admin=1<<1
    send_messages=1<<2
    manage_messages=1<<3
    manage_members=1<<4
    manage_channel=1<<5
    manage_permissions=1<<6
    mask=(1<<7)-1

def has_permission(user_permissions, required_permission, channel_permissions):
    if user_permissions is None: user_permissions=channel_permissions
    if (user_permissions&perm.owner or user_permissions&perm.admin) and not required_permission&perm.owner: return True
    return bool(user_permissions&required_permission)

rsa_padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=b"parley")

def public_key_open(public_key_base64=None):
    try: return serialization.load_der_public_key(base64.b64decode(public_key_base64 if public_key_base64 else request.form["public"])), None
    except Exception as e: return None, make_json_error(400, f"Invalid public key: {e}")

def rsa_encrypt(public_key, plaintext): return base64.b64encode(public_key.encrypt(plaintext[:100].encode(), rsa_padding)).decode()

def rsa_verify_signature(public_key, signature_base64, data):
    try:
        signature=base64.b64decode(signature_base64)
        public_key.verify(signature, data.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except: return False

def get_challenge(public_key):
    challenge=generate()
    return generate(), bcrypt.hashpw(challenge.encode(), bcrypt.gensalt()).decode(), rsa_encrypt(public_key, challenge)

browser_regex=re.compile(r"([a-zA-Z]+)\/[0-9.]+(?: Mobile(?:\/[0-9a-zA-Z]+)?)?(?: Safari\/[0-9]+.[0-9]+)?$")
device_regex=re.compile(r"^.*?\(([a-zA-Z0-9]+)")

def regex_first_group_encrypted(match, public_key): return rsa_encrypt(public_key, match.group(1)[:50]) if match else None

challenges={}
challenges_lock=Lock()

all_sliding_window_ratelimits=[]

def cleaner():
    from utils import stopping
    while not stopping.is_set():
        now=timestamp()
        with challenges_lock:
            for cid in list(challenges):
                if challenges[cid]["expire"]<now: del challenges[cid]
        for lock, sliding_window_ratelimits in all_sliding_window_ratelimits:
            with lock:
                for ip in list(sliding_window_ratelimits):
                    while sliding_window_ratelimits[ip] and sliding_window_ratelimits[ip][0]<timestamp():
                        del sliding_window_ratelimits[ip][0]
                    if not sliding_window_ratelimits[ip]: del sliding_window_ratelimits[ip]
        stopping.wait(30)

def sliding_window_rate_limiter(limit=10, window=3600, user_limit=None):
    ip_ratelimits={}
    user_ratelimits={}
    lock=Lock()
    all_sliding_window_ratelimits.append((lock, ip_ratelimits))
    all_sliding_window_ratelimits.append((lock, user_ratelimits))
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            with lock:
                ip=request.remote_addr
                if ip not in ip_ratelimits: ip_ratelimits[ip]=[]
                while ip_ratelimits[ip] and ip_ratelimits[ip][0]<timestamp():
                    del ip_ratelimits[ip][0]
                if len(ip_ratelimits[ip])>=limit: 
                    return jsonify({"success": False, "ratelimit": True, "type": "ip"}), 429, {"X-RateLimit-Limit": str(limit), "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(ip_ratelimits[ip][0])}
                user_id=None
                if "Authorization" in request.headers:
                    auth_header_split=request.headers["Authorization"].split(" ")
                    if len(auth_header_split)>=2 and auth_header_split[0]=="Bearer" and len(auth_header_split[1])==20:
                        db=SQLite()
                        user_data=db.select_data("session", ["user"], {"token_hash": hash_token(auth_header_split[1])})
                        if user_data: user_id=user_data[0]["user"]
                        db.close()
                if user_id and user_limit is not None:
                    if user_id not in user_ratelimits: user_ratelimits[user_id]=[]
                    while user_ratelimits[user_id] and user_ratelimits[user_id][0]<timestamp():
                        del user_ratelimits[user_id][0]
                    if len(user_ratelimits[user_id])>=user_limit:
                        return jsonify({"success": False, "ratelimit": True, "type": "user"}), 429, {"X-RateLimit-Limit": str(user_limit), "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(user_ratelimits[user_id][0])}
                ip_ratelimits[ip].append(timestamp()+window)
                if user_id and user_limit is not None: user_ratelimits[user_id].append(timestamp()+window)
                ip_ratelimits_length=len(ip_ratelimits[ip])
                ip_ratelimit_reset=ip_ratelimits[ip][0]
                user_ratelimits_length=len(user_ratelimits[user_id]) if user_id and user_limit is not None else None
                user_ratelimit_reset=user_ratelimits[user_id][0] if user_id and user_limit is not None and user_ratelimits[user_id] else None
                limits=[{"limit": limit, "remaining": limit-ip_ratelimits_length, "reset": ip_ratelimit_reset}]
                if user_id and user_limit is not None: limits.append({"limit": user_limit, "remaining": user_limit-user_ratelimits_length, "reset": user_ratelimit_reset})
                lowest_limit=min(limits, key=lambda x: x["remaining"])
            resp=make_response(f(*args, **kwargs))
            resp.headers["X-RateLimit-Limit"]=str(lowest_limit["limit"])
            resp.headers["X-RateLimit-Remaining"]=str(lowest_limit["remaining"])
            if lowest_limit["reset"]: resp.headers["X-RateLimit-Reset"]=str(lowest_limit["reset"])
            return resp
        return wrapper
    return decorator

def check_user_channel_limit(db, user_id):
    user_channel_count=db.execute_raw_sql("SELECT COUNT(*) as count FROM members WHERE user_id=? AND hidden IS NULL", (user_id,))[0]["count"]
    if user_channel_count>=config["max_members"]["max_channels"]:
        return make_json_error(400, "You have reached the maximum number of channels")
    return False

def get_pagination_params():
    page=get_args_int("page", 1)
    if isinstance(page, tuple): return page
    page_size=get_args_int("page_size", 50)
    if isinstance(page_size, tuple): return page_size
    if page<1: page=1
    if page_size<1: page_size=1
    if page_size>100: page_size=100
    offset=(page-1)*page_size
    return {"page": page, "page_size": page_size, "offset": offset}

def process_cors_headers(resp):
    resp.headers["Access-Control-Allow-Headers"]="Accept, Accept-Encoding, Accept-Language, Authorization, Cache-Control, Connection, Content-Type, Host, Origin, Range, Referer, User-Agent"
    resp.headers["Access-Control-Allow-Methods"]="GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Origin"]="*"

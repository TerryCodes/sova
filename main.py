import os
os.chdir(os.path.dirname(__file__))
from utils import stopping, db_version, dev_mode, config, BLUE, YELLOW, RED, colored_log
os.makedirs(os.path.dirname(config["data_dir"]["database"]), exist_ok=True)
from flask import Flask, send_from_directory, abort, request, jsonify, redirect, make_response
from api import api_bp
from api.utils import make_json_error, pass_db, process_cors_headers
from werkzeug.utils import safe_join
from db import SQLite
from migrations import run_migrations
import sys

try: run_migrations()
except Exception as e:
    colored_log(RED, "ERROR", f"Migration failed: {e}")
    sys.exit(1)

with SQLite() as db:
    db.create_table("users", {"seq": "INTEGER PRIMARY KEY AUTOINCREMENT", "id": "TEXT UNIQUE NOT NULL", "username": "TEXT UNIQUE NOT NULL", "display_name": "TEXT", "pfp": "TEXT", "passkey": "TEXT NOT NULL", "public_key": "TEXT NOT NULL", "created_at": "INTEGER NOT NULL", "FOREIGN KEY (pfp)": "REFERENCES files (id) ON DELETE SET NULL"})
    db.create_table("session", {"seq": "INTEGER PRIMARY KEY AUTOINCREMENT", "user": "TEXT NOT NULL", "token_hash": "TEXT UNIQUE NOT NULL", "id": "TEXT UNIQUE NOT NULL", "device": "TEXT", "browser": "TEXT", "logged_in_at": "INTEGER NOT NULL", "next_challenge": "INTEGER", "FOREIGN KEY (user)": "REFERENCES users (id) ON DELETE CASCADE"})
    db.create_table("channels", {"id": "TEXT PRIMARY KEY", "name": "TEXT", "pfp": "TEXT", "type": "INTEGER NOT NULL CHECK (type IN (1, 2, 3))", "permissions": "INTEGER NOT NULL DEFAULT 0", "dm": "TEXT", "invite_code": "TEXT UNIQUE", "created_at": "INTEGER NOT NULL", "FOREIGN KEY (pfp)": "REFERENCES files (id) ON DELETE SET NULL"})
    db.create_table("members", {"seq": "INTEGER PRIMARY KEY AUTOINCREMENT", "user_id": "TEXT", "channel_id": "TEXT", "joined_at": "INTEGER NOT NULL", "permissions": "INTEGER", "message_seq": "INTEGER DEFAULT 0", "hidden": "INTEGER CHECK (hidden IS NULL OR hidden = 1)", "UNIQUE": "(user_id, channel_id)", "FOREIGN KEY (user_id)": "REFERENCES users (id) ON DELETE CASCADE", "FOREIGN KEY (channel_id)": "REFERENCES channels (id) ON DELETE CASCADE"})
    db.create_table("messages", {"seq": "INTEGER PRIMARY KEY AUTOINCREMENT", "id": "TEXT UNIQUE NOT NULL", "channel_id": "TEXT NOT NULL", "user_id": "TEXT NOT NULL", "content": "TEXT NOT NULL", "key": "TEXT", "iv": "TEXT", "timestamp": "INTEGER NOT NULL", "edited_at": "INTEGER", "replied_to": "TEXT", "signature": "TEXT", "signed_timestamp": "INTEGER", "nonce": "TEXT", "FOREIGN KEY (channel_id)": "REFERENCES channels (id) ON DELETE CASCADE", "FOREIGN KEY (user_id)": "REFERENCES users (id) ON DELETE CASCADE"})
    db.create_table("message_pins", {"seq": "INTEGER PRIMARY KEY AUTOINCREMENT", "id": "TEXT UNIQUE NOT NULL", "FOREIGN KEY (id)": "REFERENCES messages (id) ON DELETE CASCADE"})
    db.create_table("files", {"id": "TEXT PRIMARY KEY", "filename": "TEXT", "hash": "TEXT NOT NULL", "size": "INTEGER NOT NULL", "mimetype": "TEXT", "file_type": "TEXT NOT NULL CHECK (file_type IN ('attachment', 'pfp'))", "UNIQUE": "(hash, file_type)"})
    db.create_table("attachment_message", {"file_id": "TEXT NOT NULL", "message_id": "TEXT NOT NULL", "PRIMARY KEY": "(file_id, message_id)", "FOREIGN KEY (file_id)": "REFERENCES files (id) ON DELETE CASCADE", "FOREIGN KEY (message_id)": "REFERENCES messages (id) ON DELETE CASCADE"})
    db.create_table("channels_keys", {"id": "TEXT NOT NULL", "channel_id": "TEXT", "user_id": "TEXT", "key": "TEXT", "FOREIGN KEY (channel_id)": "REFERENCES channels (id) ON DELETE CASCADE", "FOREIGN KEY (user_id)": "REFERENCES users (id) ON DELETE CASCADE"})
    db.create_table("channels_keys_info", {"seq": "INTEGER PRIMARY KEY AUTOINCREMENT", "key_id": "TEXT UNIQUE NOT NULL", "channel_id": "TEXT", "by": "TEXT", "timestamp": "INTEGER NOT NULL", "expires_at": "INTEGER NOT NULL", "FOREIGN KEY (channel_id)": "REFERENCES channels (id) ON DELETE CASCADE", "FOREIGN KEY (by)": "REFERENCES users (id) ON DELETE SET NULL"})
    db.create_table("message_reads", {"seq": "INTEGER PRIMARY KEY AUTOINCREMENT", "user_id": "TEXT NOT NULL", "channel_id": "TEXT NOT NULL", "last_message_id": "TEXT NOT NULL", "read_at": "INTEGER NOT NULL", "UNIQUE": "(user_id, channel_id)", "FOREIGN KEY (user_id)": "REFERENCES users (id) ON DELETE CASCADE", "FOREIGN KEY (channel_id)": "REFERENCES channels (id) ON DELETE CASCADE", "FOREIGN KEY (last_message_id)": "REFERENCES messages (id) ON DELETE CASCADE"})
    db.create_table("bans", {"seq": "INTEGER PRIMARY KEY AUTOINCREMENT", "user_id": "TEXT NOT NULL", "channel_id": "TEXT NOT NULL", "banned_by": "TEXT NOT NULL", "banned_at": "INTEGER NOT NULL", "reason": "TEXT", "UNIQUE": "(user_id, channel_id)", "FOREIGN KEY (user_id)": "REFERENCES users (id) ON DELETE CASCADE", "FOREIGN KEY (channel_id)": "REFERENCES channels (id) ON DELETE CASCADE", "FOREIGN KEY (banned_by)": "REFERENCES users (id) ON DELETE CASCADE"})
    db.create_table("blocks", {"seq": "INTEGER PRIMARY KEY AUTOINCREMENT", "blocker_id": "TEXT NOT NULL", "blocked_id": "TEXT NOT NULL", "blocked_at": "INTEGER NOT NULL", "UNIQUE": "(blocker_id, blocked_id)", "FOREIGN KEY (blocker_id)": "REFERENCES users (id) ON DELETE CASCADE", "FOREIGN KEY (blocked_id)": "REFERENCES users (id) ON DELETE CASCADE"})
    db.create_index("session", "user")
    db.create_index("members", "channel_id")
    db.create_index("members", "message_seq")
    db.create_index("messages", "channel_id")
    db.create_index("messages", "user_id")
    db.create_index("messages", "timestamp")
    db.create_index("files", "file_type")
    db.create_index("attachment_message", "message_id")
    db.create_index("channels_keys", "id")
    db.create_index("channels_keys", "channel_id")
    db.create_index("channels_keys", "user_id")
    db.create_index("channels_keys_info", "channel_id")
    db.create_index("message_reads", "user_id")
    db.create_index("message_reads", "channel_id")
    if db.execute_raw_sql("PRAGMA user_version;")[0]["user_version"]!=db_version: db.execute_raw_sql(f"PRAGMA user_version={db_version};")

uri_prefix="/"+config["uri_prefix"] if config["uri_prefix"] else ""
def route_rule(rule: str): return uri_prefix+rule

app=Flask(__name__, static_folder=None)

if config["server"]["proxy"]:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app=ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

app.config["MAX_CONTENT_LENGTH"]=config["server"]["max_content_length"]

def app_route(rule: str, **options): return app.route(uri_prefix+rule, **options)

frontend_hosted=config["frontend"]["hosted"]
frontend_present=os.path.isdir(config["frontend"]["frontend_directory"])
frontend=frontend_hosted and frontend_present

error_text={
    "404": "not found",
    "405": "method not allowed",
    "400": "bad request",
    "413": "content too big",
    "415": "unsupported media type",
    "500": "internal server error"
}

api_url=route_rule("/api/v1/")
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(400)
@app.errorhandler(413)
@app.errorhandler(415)
@app.errorhandler(500)
def error_handler(error):
    if request.path.startswith(uri_prefix):
        if request.path==api_url or (request.path+"/").startswith(api_url): return make_json_error(error.code, error_text[str(error.code)])
        try: return send_from_directory(config["frontend"]["frontend_directory"], f"{error.code}.html") if frontend else error_text[str(error.code)], error.code
        except: return error_text[str(error.code)], error.code
    else: return jsonify({"error": error_text[str(error.code)]}), error.code

if frontend:
    colored_log(BLUE, "INFO", "Frontend directory present, serving it")

    excluded=[i.lower() for i in config["frontend"]["excluded_frontend_root_paths"]]

    @app_route("/")
    def index(): return send_from_directory(config["frontend"]["frontend_directory"], "index.html")

    @app_route("/<path:path>")
    def serve_static(path):
        if "." not in path: path+=".html"
        safe_path=safe_join(config["frontend"]["frontend_directory"], path)
        if not safe_path: abort(404)
        safe_path=os.path.relpath(safe_path).lower()
        for exclude in excluded:
            if safe_path.startswith(exclude+os.sep) or safe_path==exclude: abort(404)
        return send_from_directory(config["frontend"]["frontend_directory"], path)
elif not frontend_hosted:
    colored_log(BLUE, "INFO", "Frontend directory isn't hosted")
elif not frontend_present:
    colored_log(RED, "ERROR", "Frontend directory isn't present")

app.register_blueprint(api_bp, url_prefix=route_rule("/api/v1"))

api_url=route_rule("/api/v1/")
@app_route("/api/v1")
def api_index():
    resp=make_response(redirect(api_url, 301))
    process_cors_headers(resp)
    return resp

@app_route("/pfp/<string:pfp>", methods=["GET"])
@pass_db
def serve_pfp(db:SQLite, pfp:str):
    pfp_data=db.select_data("files", ["id", "mimetype"], {"id": pfp, "file_type": "pfp"})
    if not pfp_data: abort(404)
    try:
        resp=send_from_directory(config["data_dir"]["pfps"], f"{pfp_data[0]["id"]}.webp", mimetype=pfp_data[0]["mimetype"], as_attachment=False)
        process_cors_headers(resp)
        return resp
    except:
        db.cleanup_unused_files()
        abort(404)

@app_route("/attachment/<string:file_id>", methods=["GET"])
@pass_db
def serve_attachment(db:SQLite, file_id:str):
    file_data=db.select_data("files", ["id", "filename", "mimetype"], {"id": file_id, "file_type": "attachment"})
    if not file_data: abort(404)
    filename=file_data[0]["filename"] or "attachment"
    try:
        resp=send_from_directory(config["data_dir"]["attachments"], file_data[0]["id"], mimetype=file_data[0]["mimetype"], as_attachment=True, download_name=filename)
        process_cors_headers(resp)
        return resp
    except:
        db.cleanup_unused_files()
        abort(404)

@app_route("/health")
def health(): return jsonify({"status": "ok"})

colored_log(BLUE, "INFO", f"Access instance at http://{config["server"]["host"]}:{config["server"]["port"]}{uri_prefix}/")
if dev_mode: colored_log(YELLOW, "WARNING", "Dev mode is enabled, please disable this mode if you're running this in production")
if dev_mode: colored_log(BLUE, "DEV MODE INFO", f"Access instance at http://localhost:{config["server"]["port"]}{uri_prefix}/ for local access")
try:
    if dev_mode: app.run(host=config["server"]["host"], port=config["server"]["port"], debug=dev_mode, threaded=True)
    else:
        from waitress import serve
        serve(app, host=config["server"]["host"], port=config["server"]["port"], threads=config["server"]["threads"])
except KeyboardInterrupt: pass
finally:
    colored_log(BLUE, "LOG", "Exiting...")
    stopping.set()

from flask import Blueprint, request, jsonify
from .utils import (
    logged_in, sliding_window_rate_limiter, make_json_error, handle_pfp,
    perm, has_permission, timestamp, hash_token, public_key_open, get_challenge,
    challenges_lock, challenges
)
from .stream import member_info_changed, member_leave, channel_deleted
from db import SQLite

users_bp=Blueprint("users", __name__)

@users_bp.route("/me")
@logged_in()
@sliding_window_rate_limiter(limit=20, window=60, user_limit=10)
def me(db:SQLite, id, session_token):
    hashed_token=hash_token(session_token)
    data=db.select_data("session", ["next_challenge"], {"token_hash": hashed_token})
    if not data: return make_json_error(401, "Unauthorized")

    if data[0]["next_challenge"]<=timestamp():
        session_user_data=db.execute_raw_sql("SELECT u.public_key, s.logged_in_at FROM users u JOIN session s ON u.id=s.user WHERE s.token_hash=?", (hashed_token,))
        if not session_user_data: return make_json_error(401, "Unauthorized")
        session_user_data=session_user_data[0]
        public_key, error_resp=public_key_open(session_user_data["public_key"])
        if error_resp: return error_resp
        logged_in_at=session_user_data["logged_in_at"]
        challenge_id, challenge_hash, challenge_enc=get_challenge(public_key)
        if not db.delete_data("session", {"token_hash": hashed_token}): return make_json_error(401, "Unauthorized")
        with challenges_lock: challenges[challenge_id]={"id": id, "hashed": challenge_hash, "expire": timestamp()+60, "logged_in_at": logged_in_at}
        return jsonify({"id": challenge_id, "challenge": challenge_enc, "success": False}), 419

    user_data=db.select_data("users", ["id", "username", "pfp", "display_name AS display"], {"id": id})[0]
    return jsonify({**user_data, "success": True})

@users_bp.route("/me/logout", methods=["DELETE"])
@sliding_window_rate_limiter(limit=10, window=60, user_limit=5)
@logged_in()
def logout(db:SQLite, session_id):
    deleted_rows=db.delete_data("session", {"id": session_id})
    if deleted_rows==0: return make_json_error(404, "Session not found")
    return jsonify({"success": True})

@users_bp.route("/me", methods=["PATCH"])
@logged_in()
@sliding_window_rate_limiter(limit=20, window=60, user_limit=10)
def edit_me(db:SQLite, id):
    db.close()
    update_data={}
    errors=[]
    if "display" in request.form:
        if len(request.form["display"])>1 and len(request.form["display"])<25: update_data["display_name"]=request.form["display"] if request.form["display"] else None
        else: errors.append("Invalid display parameter, error: length")
    with SQLite() as db:
        if request.files and "pfp" in request.files:
            pfp_result=handle_pfp(error_as_text=True, db=db)
            if not isinstance(pfp_result, tuple):
                if pfp_result:
                    old_pfp_data=db.execute_raw_sql("SELECT pfp FROM users WHERE id=?", (id,))
                    old_pfp_id=old_pfp_data[0]["pfp"] if old_pfp_data and old_pfp_data[0]["pfp"] else None
                    if old_pfp_id!=pfp_result:
                        update_data["pfp"]=pfp_result
                        if old_pfp_id: old_pfp_id_for_cleanup=old_pfp_id
                        else: old_pfp_id_for_cleanup=None
                    else: errors.append("Profile picture is the same")
            else: errors.append(pfp_result[0])
        if not update_data: return jsonify({"error": "No valid parameters to update", "errors": errors, "success": False}), 400
        db.update_data("users", update_data, {"id": id})
        updated_user=db.select_data("users", ["id", "username", "display_name AS display", "pfp"], {"id": id})[0]
    if "old_pfp_id_for_cleanup" in locals() and old_pfp_id_for_cleanup:
        db_cleanup=SQLite()
        try: db_cleanup.cleanup_unused_files()
        finally: db_cleanup.close()
    member_info_changed(id, updated_user, db)
    return jsonify({"updated_user": updated_user, "errors": errors, "success": True})

@users_bp.route("/me", methods=["DELETE"])
@logged_in()
@sliding_window_rate_limiter(limit=3, window=60, user_limit=2)
def delete_account(db:SQLite, id):
    user_data=db.select_data("users", ["username", "display_name", "pfp"], {"id": id})[0]
    user_channels=db.execute_raw_sql("SELECT c.id, c.type, c.pfp, m.permissions, c.permissions as channel_permissions FROM channels c JOIN members m ON c.id=m.channel_id WHERE m.user_id=?", (id,))
    channels_to_delete=[]
    dm_channels_to_delete=[]
    for channel in user_channels:
        channel_id=channel["id"]
        channel_type=channel["type"]
        user_permissions=channel["permissions"]
        channel_permissions=channel["channel_permissions"]
        if channel_type==1:
            dm_channels_to_delete.append(channel_id)
            continue
        if has_permission(user_permissions, perm.owner, channel_permissions):
            owner_count=db.execute_raw_sql("SELECT COUNT(*) as count FROM members WHERE channel_id=? AND (permissions & 2)=2", (channel_id,))[0]["count"]
            if owner_count==1:
                total_members=db.execute_raw_sql("SELECT COUNT(*) as count FROM members WHERE channel_id=?", (channel_id,))[0]["count"]
                if total_members>1:
                    if "force" not in request.args: return make_json_error(403, "Cannot delete account as you are the last owner of non-empty channels, Use ?force to delete the channels")
                    channels_to_delete.append(channel_id)
    for channel in user_channels:
        channel_id=channel["id"]
        member_leave(channel_id, {"id": id, **user_data}, db)
    for channel_id in channels_to_delete:
        channel_deleted(channel_id, db)
        channel_pfp=db.select_data("channels", ["pfp"], {"id": channel_id})
        if channel_pfp and channel_pfp[0]["pfp"]: db.cleanup_unused_files()
        db.delete_data("channels", {"id": channel_id})
    for channel_id in dm_channels_to_delete:
        channel_deleted(channel_id, db)
        db.delete_data("channels", {"id": channel_id})
    pfp=db.select_data("users", ["pfp"], {"id": id})
    db.delete_data("users", {"id": id})
    if pfp and pfp[0]["pfp"]: db.cleanup_unused_files()
    db.cleanup_unused_files()
    db.cleanup_unused_keys()
    return jsonify({"success": True})

@users_bp.route("/me/sessions")
@sliding_window_rate_limiter(limit=50, window=60, user_limit=25)
@logged_in()
def sessions_get(db:SQLite, id, session_id):
    sessions=db.select_data("session", ["id", "device", "browser", "logged_in_at"], {"user": id}, "seq DESC")
    for session in sessions: session["current"]=session["id"]==session_id
    return jsonify(sessions)

@users_bp.route("/me/sessions", methods=["DELETE"])
@sliding_window_rate_limiter(limit=5, window=60, user_limit=3)
@logged_in()
def sessions_delete(db:SQLite, id):
    deleted_rows=db.delete_data("session", {"user": id})
    return jsonify({"success": True, "deleted_sessions": deleted_rows})

@users_bp.route("/me/session/<string:session>", methods=["DELETE"])
@sliding_window_rate_limiter(limit=20, window=60, user_limit=10)
@logged_in()
def session_delete(db:SQLite, id, session):
    deleted_rows=db.delete_data("session", {"id": session, "user": id})
    if deleted_rows==0: return make_json_error(404, "Session not found")
    return jsonify({"success": True})

@users_bp.route("/me/blocks")
@logged_in()
@sliding_window_rate_limiter(limit=100, window=60, user_limit=30)
def get_blocks(db:SQLite, id):
    blocks=db.execute_raw_sql("""
        SELECT u.username, u.display_name AS display, u.pfp, b.blocked_at
        FROM blocks b
        JOIN users u ON b.blocked_id=u.id
        WHERE b.blocker_id=?
        ORDER BY b.blocked_at DESC
        """, (id,))
    return jsonify(blocks)

@users_bp.route("/me/block/<string:username>", methods=["POST"])
@logged_in()
@sliding_window_rate_limiter(limit=50, window=60, user_limit=20)
def block_user(db:SQLite, id, username):
    user_block_data=db.execute_raw_sql("""
        SELECT u.id as target_user_id,
               EXISTS(SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=u.id) as already_blocked
        FROM users u
        WHERE u.username=?
    """, (id, username))
    if not user_block_data: return make_json_error(404, "User not found")
    data=user_block_data[0]
    target_user_id=data["target_user_id"]
    if id==target_user_id: return make_json_error(400, "Cannot block yourself")
    if data["already_blocked"]: return make_json_error(409, "User is already blocked")
    db.insert_data("blocks", {"blocker_id": id, "blocked_id": target_user_id, "blocked_at": timestamp()})
    return jsonify({"success": True})

@users_bp.route("/me/block/<string:username>", methods=["DELETE"])
@logged_in()
@sliding_window_rate_limiter(limit=50, window=60, user_limit=20)
def unblock_user(db:SQLite, id, username):
    user_block_data=db.execute_raw_sql("""
        SELECT u.id as target_user_id,
               EXISTS(SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=u.id) as is_blocked
        FROM users u
        WHERE u.username=?
    """, (id, username))
    if not user_block_data: return make_json_error(404, "User not found")
    data=user_block_data[0]
    target_user_id=data["target_user_id"]
    if not data["is_blocked"]: return make_json_error(404, "User is not blocked")
    db.delete_data("blocks", {"blocker_id": id, "blocked_id": target_user_id})
    return jsonify({"success": True})
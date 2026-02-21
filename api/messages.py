from flask import Blueprint, request, jsonify
import json
from .utils import (
    make_json_error, logged_in, sliding_window_rate_limiter,
    timestamp, perm, has_permission, validate_request_data,
    get_file_size_chunked, public_key_open, rsa_verify_signature
)
from utils import generate
from .stream import message_sent, message_edited, message_deleted, dm_unhide
from utils import config
from db import SQLite
import os
import math

max_encrypted_msg_len=math.ceil((config["messages"]["max_message_length"]+16)/3)*4

messages_bp=Blueprint("messages", __name__)

os.makedirs(config["data_dir"]["attachments"], exist_ok=True)

@messages_bp.route("/channel/<string:channel_id>/messages")
@logged_in()
@sliding_window_rate_limiter(limit=200, window=60, user_limit=100)
def channel_messages(db:SQLite, id, channel_id):
    member_channel_data=db.execute_raw_sql("""
        SELECT m.permissions, m.message_seq, c.type, c.permissions as channel_permissions
        FROM members m
        JOIN channels c ON m.channel_id=c.id
        WHERE m.user_id=? AND m.channel_id=?
    """, (id, channel_id))
    if not member_channel_data: return make_json_error(404, "Channel not found")
    data=member_channel_data[0]
    user_permissions=data["permissions"]
    member_message_seq=data["message_seq"]
    channel_permissions=data["channel_permissions"]
    hide_author=(
        data["type"]==3 and not (
            has_permission(user_permissions, perm.send_messages, channel_permissions)
            or has_permission(user_permissions, perm.manage_members, channel_permissions)
            or has_permission(user_permissions, perm.manage_permissions, channel_permissions)
        )
    )
    limit=int(request.args.get("limit", 50))
    offset=int(request.args.get("offset", 0))
    before_messages=int(request.args.get("before_messages", 0))
    if limit>100: limit=100
    if limit<1: limit=1
    if before_messages<0: before_messages=0
    if before_messages>100: before_messages=100
    if hide_author:
        sql_parts=[
            "SELECT m.content, m.id, m.key, m.iv, m.timestamp, m.edited_at, m.replied_to, m.nonce, ",
            "NULL AS user, ",
            "NULL AS signature, ",
            "NULL AS signed_timestamp, ",
            "(SELECT json_group_array(json_object(",
            "   'id', am.file_id, ",
            "   'filename', f.filename, ",
            "   'size', f.size, ",
            "   'mimetype', f.mimetype, ",
            "   'encrypted', am.encrypted, ",
            "   'iv', am.iv",
            ")) FROM attachment_message am ",
            "   JOIN files f ON am.file_id = f.id ",
            "   WHERE am.message_id = m.id) AS attachments ",
            "FROM messages m ",
            "WHERE m.channel_id = ? AND m.seq > ?"
        ]
    else:
        sql_parts=[
            "SELECT m.content, m.id, m.key, m.iv, m.timestamp, m.edited_at, m.replied_to, m.nonce, ",
            "json_object(",
            "  'username', u.username, ",
            "  'display', u.display_name, ",
            "  'pfp', u.pfp",
            ") AS user, ",
            "m.signature, ",
            "m.signed_timestamp, ",
            "(SELECT json_group_array(json_object(",
            "   'id', am.file_id, ",
            "   'filename', f.filename, ",
            "   'size', f.size, ",
            "   'mimetype', f.mimetype, ",
            "   'encrypted', am.encrypted, ",
            "   'iv', am.iv",
            ")) FROM attachment_message am ",
            "   JOIN files f ON am.file_id = f.id ",
            "   WHERE am.message_id = m.id) AS attachments ",
            "FROM messages m ",
            "JOIN users u ON m.user_id = u.id ",
            "WHERE m.channel_id = ? AND m.seq > ?"
        ]
    params=[channel_id, member_message_seq]
    if "user_id" in request.args:
        if len(request.args["user_id"])!=20: return make_json_error(400, "Invalid user_id parameter, error: length")
        sql_parts.append("AND m.user_id=?")
        params.append(request.args["user_id"])
    if "before" in request.args and "after" in request.args:
        sql_parts.append("AND m.timestamp BETWEEN ? AND ?")
        params.extend([int(request.args["after"]), int(request.args["before"])])
    elif "before" in request.args:
        sql_parts.append("AND m.timestamp < ?")
        params.append(int(request.args["before"]))
    elif "after" in request.args:
        sql_parts.append("AND m.timestamp > ?")
        params.append(int(request.args["after"]))
    if "before_message_id" in request.args and "after_message_id" in request.args:
        sql_parts.append("AND m.seq BETWEEN (SELECT seq FROM messages WHERE id=? AND channel_id=?) AND (SELECT seq FROM messages WHERE id=? AND channel_id=?)")
        params.extend([request.args["after_message_id"], channel_id, request.args["before_message_id"], channel_id])
    elif "before_message_id" in request.args:
        sql_parts.append("AND m.seq < (SELECT seq FROM messages WHERE id=? AND channel_id=?)")
        params.extend([request.args["before_message_id"], channel_id])
    elif "after_message_id" in request.args:
        sql_parts.append("AND m.seq > (SELECT seq FROM messages WHERE id=? AND channel_id=?)")
        params.extend([request.args["after_message_id"], channel_id])
    sql_parts.append("ORDER BY m.seq DESC LIMIT ? OFFSET ?")
    total_limit=limit+before_messages
    params.extend([total_limit, offset])
    messages=db.execute_raw_sql(" ".join(sql_parts), params)
    for msg in messages:
        msg["user"]=json.loads(msg["user"]) if msg["user"] else None
        msg["attachments"]=[{**a, "encrypted": bool(a["encrypted"])} for a in json.loads(msg["attachments"])]
    return jsonify(messages)

@messages_bp.route("/channel/<string:channel_id>/messages", methods=["POST"])
@logged_in()
@sliding_window_rate_limiter(limit=100, window=60, user_limit=50)
@validate_request_data({"content": {}, "timestamp": {}, "signature": {}})
def sending_messages(db:SQLite, id, channel_id):
    files=request.files.getlist("files")
    msg=request.form["content"].strip()
    has_files=any(file.filename for file in files)
    if (not has_files and not msg): return make_json_error(400, "content or files required")
    replied_to=request.form.get("replied_to")
    try: signed_timestamp=int(request.form["timestamp"])
    except ValueError: return make_json_error(400, "Invalid timestamp format")
    signature=request.form["signature"]
    current_time=timestamp()
    if abs(current_time-signed_timestamp)>config["messages"]["signature_timestamp_window"]: return make_json_error(400, "Timestamp is invalid")
    if replied_to and not db.exists("messages", {"id": replied_to, "channel_id": channel_id}): return make_json_error(400, "replied_to message not found in this channel")
    member_channel_data=db.execute_raw_sql("""
        SELECT m.permissions, c.type, c.permissions as channel_permissions
        FROM members m
        JOIN channels c ON m.channel_id=c.id
        WHERE m.user_id=? AND m.channel_id=?
    """, (id, channel_id))
    if not member_channel_data: return make_json_error(404, "Channel not found")
    data=member_channel_data[0]
    if data["type"]==1:
        other_member=db.execute_raw_sql("SELECT user_id FROM members WHERE channel_id=? AND user_id!=?", (channel_id, id))
        if other_member and db.exists("blocks", {"blocker_id": other_member[0]["user_id"], "blocked_id": id}): return make_json_error(403, "You are blocked by this user")
    member_permissions=data["permissions"]
    channel_permissions=data["channel_permissions"]
    if not has_permission(member_permissions, perm.send_messages, channel_permissions): return make_json_error(403, "No permission to send messages")
    if len(msg)>(config["messages"]["max_message_length"] if data["type"]==3 else max_encrypted_msg_len): return make_json_error(400, "Message too long")
    if data["type"]==3:
        user_public_key_data=db.execute_raw_sql("SELECT public_key FROM users WHERE id=?", (id,))
        if not user_public_key_data: return make_json_error(500, "User public key not found")
        public_key, error_resp=public_key_open(user_public_key_data[0]["public_key"])
        if error_resp: return error_resp
        signed_data=f"{msg}:{channel_id}:{signed_timestamp}"
        if not rsa_verify_signature(public_key, signature, signed_data): return make_json_error(400, "Invalid signature")
    key=None
    iv=None
    if data["type"]!=3:
        if "key" not in request.form or "iv" not in request.form: return make_json_error(400, "key and iv is required in non-broadcast channels")
        key=request.form["key"]
        latest_user_key=db.execute_raw_sql(
            "SELECT cki.key_id, expires_at FROM channels_keys_info cki "
            "WHERE cki.channel_id=? "
            "ORDER BY cki.seq DESC LIMIT 1",
            (channel_id,)
        )
        if not latest_user_key or latest_user_key[0]["expires_at"]<timestamp(True): return make_json_error(403, "No encryption key available")
        if key!=latest_user_key[0]["key_id"]: return make_json_error(400, "Invalid or outdated encryption key")
        if len(request.form["iv"])!=16: return make_json_error(400, "Invalid iv parameter, error: length")
        iv=request.form["iv"]
    nonce=request.form.get("nonce")
    attachments_meta_raw=request.form.getlist("attachments_meta")
    attachments_meta=[]
    for item in attachments_meta_raw:
        try: attachments_meta.append(json.loads(item))
        except: return make_json_error(400, "Invalid attachments_meta format")
    for idx, file in enumerate(files):
        if file.filename:
            meta=attachments_meta[idx] if idx<len(attachments_meta) else {}
            encrypted=meta.get("encrypted", False)
            attachment_iv=meta.get("iv")
            if encrypted and not attachment_iv: return make_json_error(400, "iv required when encrypted=true")
            if encrypted and len(attachment_iv)!=16: return make_json_error(400, "Invalid iv length for attachment")
    message_id=generate()
    sent_at=timestamp(True)
    db.insert_data("messages", {"id": message_id, "channel_id": channel_id, "user_id": id, "content": msg, "key": key, "iv": iv, "timestamp": sent_at, "replied_to": replied_to, "signature": signature, "signed_timestamp": signed_timestamp, "nonce": nonce})
    if db.exists("message_reads", {"user_id": id, "channel_id": channel_id}): db.update_data("message_reads", {"last_message_id": message_id, "read_at": sent_at}, {"user_id": id, "channel_id": channel_id})
    else: db.insert_data("message_reads", {"user_id": id, "channel_id": channel_id, "last_message_id": message_id, "read_at": sent_at})
    attachments=[]
    for idx, file in enumerate(files):
        if file.content_length and file.content_length>config["max_file_size"]["attachments"] and file.filename and get_file_size_chunked(file, config["max_file_size"]["attachments"])<=config["max_file_size"]["attachments"]:
            meta=attachments_meta[idx] if idx<len(attachments_meta) else {}
            encrypted=meta.get("encrypted", False)
            attachment_iv=meta.get("iv")
            temp_path=os.path.join(config["data_dir"]["attachments"], f"temp_{generate()}")
            file.save(temp_path)
            file_hash=db.calculate_file_hash(temp_path)
            file_size=os.path.getsize(temp_path)
            existing_file=db.select_data("files", ["id", "filename", "size", "mimetype"], {"hash": file_hash, "file_type": "attachment"})
            if existing_file:
                os.remove(temp_path)
                file_id=existing_file[0]["id"]
                file_info=existing_file[0]
            else:
                file_id=generate()
                final_path=os.path.join(config["data_dir"]["attachments"], file_id)
                os.rename(temp_path, final_path)
                db.insert_data("files", {"id": file_id, "filename": file.filename, "hash": file_hash, "size": file_size, "mimetype": file.content_type, "file_type": "attachment"})
                file_info={"id": file_id, "filename": file.filename, "size": file_size, "mimetype": file.content_type}
            existing_attachment=db.select_data("attachment_message", ["file_id"], {"file_id": file_id, "message_id": message_id})
            if not existing_attachment:
                db.insert_data("attachment_message", {"file_id": file_id, "message_id": message_id, "encrypted": 1 if encrypted else 0, "iv": attachment_iv})
            attachments.append({"id": file_id, "filename": file.filename, "size": file_info["size"], "mimetype": file_info["mimetype"], "encrypted": bool(encrypted), "iv": attachment_iv})
    if not msg and has_files and not attachments:
        db.delete_data("messages", {"id": message_id})
        return make_json_error(400, "Files do not meet size requirements")
    # Get user data for the emit
    user_data=db.execute_raw_sql("SELECT username, display_name AS display, pfp FROM users WHERE id=?", (id,))[0] if not (data["type"]==3 and not (has_permission(member_permissions, perm.send_messages, channel_permissions) or has_permission(member_permissions, perm.manage_members, channel_permissions) or has_permission(member_permissions, perm.manage_permissions, channel_permissions))) else None
    hide_signature=(data["type"]==3 and not (has_permission(member_permissions, perm.send_messages, channel_permissions) or has_permission(member_permissions, perm.manage_members, channel_permissions) or has_permission(member_permissions, perm.manage_permissions, channel_permissions)))
    message_data={
        "id": message_id,
        "content": msg,
        "key": key,
        "iv": iv,
        "timestamp": sent_at,
        "edited_at": None,
        "replied_to": replied_to,
        "user": user_data,
        "attachments": attachments,
        "signature": None if hide_signature else signature,
        "signed_timestamp": None if hide_signature else signed_timestamp,
        "nonce": nonce
    }
    if data["type"]==1:
        current_member=db.select_data("members", ["hidden"], {"channel_id": channel_id, "user_id": id})
        if current_member and current_member[0]["hidden"]:
            db.update_data("members", {"hidden": None}, {"user_id": id, "channel_id": channel_id})
            dm_unhide(channel_id, id, db)
        other_member=db.execute_raw_sql("SELECT user_id, hidden FROM members WHERE channel_id=? AND user_id!=?", (channel_id, id))
        if other_member and other_member[0]["hidden"]:
            other_user_id=other_member[0]["user_id"]
            db.update_data("members", {"hidden": None}, {"user_id": other_user_id, "channel_id": channel_id})
            dm_unhide(channel_id, other_user_id, db)

    message_sent(channel_id, message_data, id, db)

    return jsonify({"message_id": message_id, "attachments": attachments, "success": True}), 201

@messages_bp.route("/channel/<string:channel_id>/message/<string:message_id>", methods=["PATCH", "DELETE"])
@logged_in()
@sliding_window_rate_limiter(limit=150, window=60, user_limit=75)
def message_management(db:SQLite, id, channel_id, message_id):
    message_channel_data=db.execute_raw_sql("""
        SELECT m.user_id, m.channel_id, c.type, c.permissions as channel_permissions
        FROM messages m
        JOIN channels c ON m.channel_id=c.id
        WHERE m.id=?
    """, (message_id,))
    if not message_channel_data: return make_json_error(404, "Message not found")
    data=message_channel_data[0]
    if data["channel_id"]!=channel_id: return make_json_error(404, "Message not found")
    if request.method=="PATCH":
        if not request.form.get("content"): return make_json_error(400, "content is required")
        if not request.form.get("timestamp"): return make_json_error(400, "timestamp is required")
        if not request.form.get("signature"): return make_json_error(400, "signature is required")
        if len(request.form["content"])>(config["messages"]["max_message_length"] if data["type"]==3 else max_encrypted_msg_len): return make_json_error(400, "Message too long")
        if data["user_id"]!=id: return make_json_error(403, "Can only edit your own messages")
        try: signed_timestamp=int(request.form["timestamp"])
        except ValueError: return make_json_error(400, "Invalid timestamp format")
        signature=request.form["signature"]
        current_time=timestamp()
        if abs(current_time-signed_timestamp)>config["messages"]["signature_timestamp_window"]: return make_json_error(400, "Timestamp is invalid")
        if data["type"]==3:
            user_public_key_data=db.execute_raw_sql("SELECT public_key FROM users WHERE id=?", (id,))
            if not user_public_key_data: return make_json_error(500, "User public key not found")
            public_key, error_resp=public_key_open(user_public_key_data[0]["public_key"])
            if error_resp: return error_resp
            signed_data=f"{request.form['content']}:{channel_id}:{signed_timestamp}"
            if not rsa_verify_signature(public_key, signature, signed_data): return make_json_error(400, "Invalid signature")

        update_fields={"content": request.form["content"], "edited_at": timestamp(True), "signature": signature, "signed_timestamp": signed_timestamp}

        if data["type"]!=3:
            if "iv" not in request.form: return make_json_error(400, "iv is required in non-broadcast channels")
            if len(request.form["iv"])!=16: return make_json_error(400, "Invalid iv parameter, error: length")
            update_fields["iv"]=request.form["iv"]

        db.update_data("messages", update_fields, {"id": message_id})

        # Get updated message data for emit
        updated_message=db.execute_raw_sql("""
            SELECT m.id, m.content, m.key, m.iv, m.timestamp, m.edited_at, m.replied_to, m.signature, m.signed_timestamp, m.nonce,
            json_object('username', u.username, 'display', u.display_name, 'pfp', u.pfp) as user,
            (SELECT json_group_array(json_object('id', am.file_id, 'filename', f.filename, 'size', f.size, 'mimetype', f.mimetype, 'encrypted', am.encrypted, 'iv', am.iv))
             FROM attachment_message am JOIN files f ON am.file_id = f.id WHERE am.message_id = m.id) as attachments
            FROM messages m JOIN users u ON m.user_id = u.id WHERE m.id=?
        """, (message_id,))[0]
        updated_message["user"]=json.loads(updated_message["user"])
        updated_message["attachments"]=[{**a, "encrypted": bool(a["encrypted"])} for a in json.loads(updated_message["attachments"])] if updated_message["attachments"] else []
        message_edited(channel_id, updated_message, id, db)

        return jsonify({"success": True})
    elif request.method=="DELETE":
        if data["user_id"]!=id:
            member_perms=db.execute_raw_sql("""
                SELECT m.permissions
                FROM members m
                WHERE m.user_id=? AND m.channel_id=?
            """, (id, channel_id))
            if not member_perms: return make_json_error(404, "Channel not found")
            channel_permissions=data["channel_permissions"]
            if not has_permission(member_perms[0]["permissions"], perm.manage_messages, channel_permissions): return make_json_error(403, "Can only delete your own messages or need manage messages permission")
        db.delete_data("messages", {"id": message_id})
        db.cleanup_unused_files()
        db.cleanup_unused_keys()

        # Emit message deleted event
        message_deleted(channel_id, message_id, id)

        return jsonify({"success": True})

@messages_bp.route("/channel/<string:channel_id>/messages/ack", methods=["POST"])
@logged_in()
@sliding_window_rate_limiter(limit=60, window=60, user_limit=30)
def ack_message(db:SQLite, id, channel_id):
    if not db.exists("members", {"user_id": id, "channel_id": channel_id}): return make_json_error(404, "Channel not found")
    latest_message=db.execute_raw_sql(
        "SELECT id FROM messages WHERE channel_id=? ORDER BY seq DESC LIMIT 1",
        (channel_id,)
    )
    if not latest_message: return make_json_error(404, "No messages in channel")
    latest_message_id=latest_message[0]["id"]
    if db.exists("message_reads", {"user_id": id, "channel_id": channel_id}):
        db.update_data("message_reads", {"last_message_id": latest_message_id, "read_at": timestamp(True)}, {"user_id": id, "channel_id": channel_id})
    else: db.insert_data("message_reads", {"user_id": id, "channel_id": channel_id, "last_message_id": latest_message_id, "read_at": timestamp(True)})
    return jsonify({"success": True})
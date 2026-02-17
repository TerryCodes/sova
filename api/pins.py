from flask import Blueprint, jsonify
import json
from .utils import (
    make_json_error, logged_in, sliding_window_rate_limiter,
    get_pagination_params, has_permission, perm
)
from db import SQLite

pins_bp=Blueprint("pins", __name__)

@pins_bp.route("/channel/<string:channel_id>/pins")
@logged_in()
@sliding_window_rate_limiter(limit=60, window=60, user_limit=20)
def get_pinned_messages(db:SQLite, id, channel_id):
    if not db.exists("members", {"user_id": id, "channel_id": channel_id}):
        return make_json_error(404, "Channel not found")
    member_data=db.select_data("members", ["permissions"], {"user_id": id, "channel_id": channel_id})
    channel_data=db.select_data("channels", ["type", "permissions"], {"id": channel_id})
    if not channel_data:
        return make_json_error(404, "Channel not found")
    user_permissions=member_data[0]["permissions"]
    channel_permissions=channel_data[0]["permissions"]
    hide_author=(
        channel_data[0]["type"]==3 and not (
            has_permission(user_permissions, perm.send_messages, channel_permissions)
            or has_permission(user_permissions, perm.manage_members, channel_permissions)
            or has_permission(user_permissions, perm.manage_permissions, channel_permissions)
        )
    )
    pagination=get_pagination_params()
    if isinstance(pagination, tuple):
        return pagination
    page_size, offset = pagination["page_size"], pagination["offset"]
    if hide_author:
        sql_parts=[
            "SELECT m.content, m.id, m.key, m.iv, m.timestamp, m.edited_at, m.replied_to, m.signature, m.signed_timestamp, m.nonce, ",
            "NULL AS user, ",
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
            "JOIN message_pins mp ON m.id = mp.id ",
            "WHERE m.channel_id = ?"
        ]
    else:
        sql_parts=[
            "SELECT m.content, m.id, m.key, m.iv, m.timestamp, m.edited_at, m.replied_to, m.signature, m.signed_timestamp, m.nonce, ",
            "json_object(",
            "  'username', u.username, ",
            "  'display', u.display_name, ",
            "  'pfp', u.pfp",
            ") AS user, ",
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
            "JOIN message_pins mp ON m.id = mp.id ",
            "WHERE m.channel_id = ?"
        ]
    params=[channel_id]
    sql_parts.append("ORDER BY mp.seq DESC LIMIT ? OFFSET ?")
    params.extend([page_size, offset])
    pinned_messages=db.execute_raw_sql(" ".join(sql_parts), params)
    for msg in pinned_messages:
        msg["user"]=json.loads(msg["user"]) if msg["user"] else None
        msg["attachments"]=json.loads(msg["attachments"])
    return jsonify(pinned_messages)

@pins_bp.route("/channel/<string:channel_id>/message/<string:message_id>/pin", methods=["POST"])
@logged_in()
@sliding_window_rate_limiter(limit=50, window=60, user_limit=20)
def pin_message(db:SQLite, id, channel_id, message_id):
    user_member_data=db.select_data("members", ["permissions"], {"user_id": id, "channel_id": channel_id})
    if not user_member_data: return make_json_error(404, "Channel not found")
    user_permissions=user_member_data[0]["permissions"]
    channel_data=db.select_data("channels", ["type", "permissions"], {"id": channel_id})
    if not channel_data: return make_json_error(404, "Channel not found")
    channel_data=channel_data[0]
    if channel_data["type"]!=1 and not has_permission(user_permissions, perm.manage_messages, channel_data["permissions"]): return make_json_error(403, "You don't have manage messages permission")
    if not db.exists("messages", {"id": message_id, "channel_id": channel_id}): return make_json_error(404, "Message not found")
    if db.exists("message_pins", {"id": message_id}): return make_json_error(409, "Message is already pinned")
    try: db.insert_data("message_pins", {"id": message_id})
    except Exception as e:
        if "UNIQUE constraint failed" in str(e): return make_json_error(409, "Message is already pinned")
        raise
    return jsonify({"success": True})

@pins_bp.route("/channel/<string:channel_id>/message/<string:message_id>/pin", methods=["DELETE"])
@logged_in()
@sliding_window_rate_limiter(limit=50, window=60, user_limit=20)
def unpin_message(db:SQLite, id, channel_id, message_id):
    user_member_data=db.select_data("members", ["permissions"], {"user_id": id, "channel_id": channel_id})
    if not user_member_data: return make_json_error(404, "Channel not found")
    user_permissions=user_member_data[0]["permissions"]
    channel_data=db.select_data("channels", ["type", "permissions"], {"id": channel_id})
    if not channel_data: return make_json_error(404, "Channel not found")
    channel_data=channel_data[0]
    if channel_data["type"]!=1 and not has_permission(user_permissions, perm.manage_messages, channel_data["permissions"]): return make_json_error(403, "You don't have manage messages permission")
    if not db.exists("messages", {"id": message_id, "channel_id": channel_id}): return make_json_error(404, "Message not found")
    if db.delete_data("message_pins", {"id": message_id})>0: return make_json_error(409, "Message is not pinned")
    return jsonify({"success": True})
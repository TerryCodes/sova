import re
import json
from flask import Blueprint, request, jsonify
from .utils import (
    make_json_error, logged_in, sliding_window_rate_limiter, timestamp, handle_pfp,
    create_dm_id, perm, has_permission, validate_request_data,
    check_user_channel_limit, get_channel_last_message_seq
)
from utils import generate
from .stream import channel_added, channel_edited, channel_deleted, member_join, member_leave, emit, dm_unhide
from utils import config
from db import SQLite

channels_bp=Blueprint("channels", __name__)

@channels_bp.route("/channels")
@logged_in()
@sliding_window_rate_limiter(limit=100, window=60, user_limit=50)
def channels(db:SQLite, id):
    user_channels=db.execute_raw_sql("""
        SELECT c.id, c.type,
               CASE WHEN c.type=1 THEN COALESCE(other_u.display_name, other_u.username) ELSE c.name END as name,
               CASE WHEN c.type=1 THEN other_u.username ELSE NULL END as username,
               CASE WHEN c.type=1 THEN other_u.display_name ELSE NULL END as display_name,
               CASE WHEN c.type=1 THEN other_u.pfp ELSE c.pfp END as pfp,
               CASE WHEN m.permissions IS NULL THEN c.permissions ELSE m.permissions END as permissions,
               c.permissions as channel_permissions,
               COALESCE((
                   SELECT COUNT(*)
                   FROM messages msg
                   LEFT JOIN message_reads mr ON mr.channel_id=c.id AND mr.user_id=?
                   WHERE msg.channel_id=c.id
                   AND msg.seq>m.message_seq
                   AND (mr.last_message_id IS NULL OR msg.seq > (
                       SELECT seq FROM messages WHERE id=mr.last_message_id
                   ))
               ), 0) as unread_count,
               mr.last_message_id AS last_message_read_id,
               (SELECT COUNT(*) FROM members WHERE channel_id=c.id) as member_count,
               CASE WHEN last_msg.id IS NOT NULL AND last_msg.seq>m.message_seq THEN
                   json_object(
                       'content', last_msg.content,
                       'id', last_msg.id,
                       'key', last_msg.key,
                       'iv', last_msg.iv,
                       'timestamp', last_msg.timestamp,
                       'edited_at', last_msg.edited_at,
                       'signature', last_msg.signature,
                       'signed_timestamp', last_msg.signed_timestamp,
                       'nonce', last_msg.nonce,
                       'user',
                           json_object(
                               'username', last_msg_user.username,
                               'display', last_msg_user.display_name,
                               'pfp', last_msg_user.pfp
                           ),
                       'attachments', (
                           SELECT json_group_array(json_object(
                               'id', am.file_id,
                               'filename', f.filename,
                               'size', f.size,
                               'mimetype', f.mimetype,
                               'encrypted', am.encrypted,
                               'iv', am.iv
                           ))
                           FROM attachment_message am
                           JOIN files f ON am.file_id = f.id
                           WHERE am.message_id = last_msg.id
                       )
                   )
               ELSE NULL END as last_message
        FROM channels c
        JOIN members m ON c.id=m.channel_id
        LEFT JOIN members other_m ON c.id=other_m.channel_id AND other_m.user_id!=? AND c.type=1
        LEFT JOIN users other_u ON other_m.user_id=other_u.id
        LEFT JOIN message_reads mr ON mr.channel_id=c.id AND mr.user_id=?
        LEFT JOIN (
            SELECT channel_id, MAX(timestamp) AS last_ts, MAX(seq) AS last_seq
            FROM messages
            GROUP BY channel_id
        ) lm ON lm.channel_id=c.id
        LEFT JOIN messages last_msg ON last_msg.channel_id=c.id AND last_msg.seq=lm.last_seq
        LEFT JOIN users last_msg_user ON last_msg.user_id=last_msg_user.id
        WHERE m.user_id=? AND m.hidden IS NULL
        ORDER BY COALESCE(lm.last_ts, m.joined_at * 1000) DESC
    """, (id, id, id, id))
    for channel in user_channels:
        user_permissions=channel["permissions"]
        channel_permissions=channel["channel_permissions"]
        hide_author=(channel["type"]==3 and not (has_permission(user_permissions, perm.send_messages, channel_permissions) or has_permission(user_permissions, perm.manage_members, channel_permissions) or has_permission(user_permissions, perm.manage_permissions, channel_permissions)))
        if channel["last_message"] is not None:
            last_message_data=json.loads(channel["last_message"])
            if hide_author:
                last_message_data["user"]=None
                last_message_data["signature"]=None
                last_message_data["signed_timestamp"]=None
            channel["last_message"]=last_message_data
        if not has_permission(user_permissions, perm.manage_permissions, channel_permissions):
            del channel["channel_permissions"]
        if channel["type"]==1:
            if channel["display_name"] is None:
                del channel["username"]
            del channel["display_name"]
    return jsonify(user_channels)

@channels_bp.route("/channels", methods=["POST"])
@logged_in()
@sliding_window_rate_limiter(limit=20, window=300, user_limit=10)
def channel_creation(db:SQLite, id):
    if config["instance"]["disable_channel_creation"]: return make_json_error(403, "Channel creation is disabled")
    error_resp=check_user_channel_limit(db, id)
    if error_resp: return error_resp
    if "type" not in request.form: return make_json_error(400, "type parameter is missing")
    try:
        channel_type=int(request.form["type"])
    except ValueError:
        return make_json_error(400, "Invalid channel type format")
    if channel_type==1:
        if "target_user" not in request.form: return make_json_error(400, "target_user parameter is missing")
        if len(request.form["target_user"])<3 or len(request.form["target_user"])>20: return make_json_error(400, "Invalid target_user parameter, error: length")
        target_user=db.select_data("users", ["id"], {"username": request.form["target_user"]})
        if not target_user: return make_json_error(404, "Target user not found")
        target_id=target_user[0]["id"]
        if id==target_id: return make_json_error(400, "Cannot create DM with yourself")
        block_checks=db.batch_exists([
            {"table": "blocks", "conditions": {"blocker_id": target_id, "blocked_id": id}}
        ])
        if block_checks[0]: return make_json_error(403, "You are blocked by this user")
        dm_id=create_dm_id(id, target_id)
        existing_dm=db.execute_raw_sql("""
            SELECT c.id, m1.hidden as user1_hidden, m2.hidden as user2_hidden FROM channels c
            JOIN members m1 ON c.id=m1.channel_id AND m1.user_id=?
            JOIN members m2 ON c.id=m2.channel_id AND m2.user_id=?
            WHERE c.dm=?
            LIMIT 1
        """, (id, target_id, dm_id))
        if existing_dm:
            channel_id=existing_dm[0]["id"]
            user1_hidden=existing_dm[0]["user1_hidden"]
            user2_hidden=existing_dm[0]["user2_hidden"]

            if user1_hidden:
                db.update_data("members", {"hidden": None}, {"user_id": id, "channel_id": channel_id})
                dm_unhide(channel_id, id, db)

            if user2_hidden:
                db.update_data("members", {"hidden": None}, {"user_id": target_id, "channel_id": channel_id})
                dm_unhide(channel_id, target_id, db)

            return jsonify({"channel_id": channel_id, "success": True})
        channel_id=generate()
        pfp_result=handle_pfp()
        if isinstance(pfp_result, tuple): return pfp_result
        try:
            db.insert_data("channels", {"id": channel_id, "name": None, "pfp": pfp_result, "type": 1, "permissions": perm.send_messages, "dm": dm_id, "created_at": timestamp()})
            with db:
                message_seq=get_channel_last_message_seq(db, channel_id)
                db.insert_data("members", {"user_id": id, "channel_id": channel_id, "joined_at": timestamp(), "message_seq": message_seq})
                db.insert_data("members", {"user_id": target_id, "channel_id": channel_id, "joined_at": timestamp(), "message_seq": message_seq})

            # Get channel data for both users
            user_data_results=db.execute_raw_sql("""
                SELECT u1.username as target_username, u1.display_name as target_display, u1.pfp as target_pfp,
                       u2.username as current_username, u2.display_name as current_display, u2.pfp as current_pfp
                FROM users u1, users u2
                WHERE u1.id=? AND u2.id=?
            """, (target_id, id))[0]
            target_user_data={"username": user_data_results["target_username"], "display_name": user_data_results["target_display"], "pfp": user_data_results["target_pfp"]}
            current_user_data={"username": user_data_results["current_username"], "display_name": user_data_results["current_display"], "pfp": user_data_results["current_pfp"]}

            channel_data={
                "id": channel_id,
                "name": target_user_data["display_name"] if target_user_data["display_name"] else target_user_data["username"],
                "pfp": target_user_data["pfp"],
                "type": 1,
                "permissions": perm.send_messages,
                "member_count": 2
            }
            if target_user_data["display_name"]:
                channel_data["username"]=target_user_data["username"]

            # Emit to both users
            channel_added(id, channel_data, db)

            # For the target user, the channel name should be current user's display_name or username
            target_channel_data={
                "id": channel_id,
                "name": current_user_data["display_name"] if current_user_data["display_name"] else current_user_data["username"],
                "pfp": current_user_data["pfp"],
                "type": 1,
                "permissions": perm.send_messages,
                "member_count": 2
            }
            if current_user_data["display_name"]:
                target_channel_data["username"]=current_user_data["username"]
            channel_added(target_id, target_channel_data, db)

            return jsonify({"channel_id": channel_id, "success": True}), 201
        except Exception as e:
            if "UNIQUE constraint failed" in str(e):
                existing_dm=db.execute_raw_sql("SELECT c.id, m1.hidden as user1_hidden, m2.hidden as user2_hidden FROM channels c JOIN members m1 ON c.id=m1.channel_id AND m1.user_id=? JOIN members m2 ON c.id=m2.channel_id AND m2.user_id=? WHERE c.dm=? LIMIT 1", (id, target_id, dm_id))
                if existing_dm:
                    channel_id=existing_dm[0]["id"]
                    user1_hidden=existing_dm[0]["user1_hidden"]
                    user2_hidden=existing_dm[0]["user2_hidden"]

                    if user1_hidden:
                        db.update_data("members", {"hidden": None}, {"user_id": id, "channel_id": channel_id})
                        dm_unhide(channel_id, id, db)

                    if user2_hidden:
                        db.update_data("members", {"hidden": None}, {"user_id": target_id, "channel_id": channel_id})
                        dm_unhide(channel_id, target_id, db)

                    return jsonify({"channel_id": channel_id, "success": True})
            raise e
    elif channel_type in [2, 3]:
        if "name" not in request.form: return make_json_error(400, "name parameter is missing")
        if len(request.form["name"])<1 or len(request.form["name"])>50: return make_json_error(400, "Invalid name parameter, error: length")
        channel_id=generate()
        pfp_result=handle_pfp()
        if isinstance(pfp_result, tuple): return pfp_result
        db.insert_data("channels", {"id": channel_id, "name": request.form["name"], "pfp": pfp_result, "type": channel_type, "permissions": perm.send_messages if channel_type==2 else 0, "created_at": timestamp()})
        db.insert_data("members", {"user_id": id, "channel_id": channel_id, "joined_at": timestamp(), "permissions": perm.owner, "message_seq": 0 if channel_type==3 else get_channel_last_message_seq(db, channel_id)})

        # Emit channel added event
        channel_data={
            "id": channel_id,
            "name": request.form["name"],
            "pfp": pfp_result,
            "type": channel_type,
            "permissions": perm.owner,
            "created": True,
            "member_count": 1
        }
        channel_added(id, channel_data, db)

        return jsonify({"channel_id": channel_id, "success": True}), 201
    return make_json_error(400, "Invalid channel type")

@channels_bp.route("/channel/<string:channel_id>", methods=["DELETE", "PATCH"])
@logged_in()
@sliding_window_rate_limiter(limit=50, window=60, user_limit=20)
def channels_management(db:SQLite, id, channel_id):
    if request.method=="PATCH":
        perm_data=db.get_permission_data(id, channel_id)
        if not perm_data["channel_data"]: return make_json_error(404, "Channel not found")
        if not perm_data["admin_member"]: return make_json_error(404, "Channel not found")
        channel_data=perm_data["channel_data"]
        member_data=perm_data["admin_member"]
        if channel_data[0]["type"]==1: return make_json_error(400, "Cannot modify DM channel settings")
        channel_permissions=channel_data[0]["permissions"]
        if not has_permission(member_data[0]["permissions"], perm.manage_channel, channel_permissions): return make_json_error(403, "Manage channel permission required")
        update_data={}
        errors=[]
        if "name" in request.form:
            if len(request.form["name"])>1 and len(request.form["name"])<50: update_data["name"]=request.form["name"]
            else: errors.append("Invalid name parameter, error: length")
        if "permissions" in request.form:
            if not has_permission(member_data[0]["permissions"], perm.manage_permissions, channel_permissions): errors.append("Manage permissions permission is required to modify permissions")
            try: perms=int(request.form["permissions"])
            except ValueError: pass
            else: update_data["permissions"]=perms&perm.mask
        if request.files and "pfp" in request.files:
            pfp_result=handle_pfp(error_as_text=True)
            if not isinstance(pfp_result, tuple):
                if pfp_result:
                    old_pfp_data=db.execute_raw_sql("SELECT pfp FROM channels WHERE id=?", (channel_id,))
                    old_pfp_id=old_pfp_data[0]["pfp"] if old_pfp_data and old_pfp_data[0]["pfp"] else None
                    if old_pfp_id!=pfp_result:
                        update_data["pfp"]=pfp_result
                        if old_pfp_id: db.cleanup_unused_files()
                    else: errors.append("Profile picture is the same")
            else: errors.append(pfp_result[0])
        if not update_data: return jsonify({"error": "No valid parameters to update", "errors": errors, "success": False}), 400
        db.update_data("channels", update_data, {"id": channel_id})

        # Get updated channel data and emit event
        updated_channel=db.execute_raw_sql("SELECT id, name, pfp, type, permissions FROM channels WHERE id=?", (channel_id,))[0]
        channel_edited(channel_id, updated_channel, db)

        return jsonify({"updated_channel": updated_channel, "errors": errors, "success": True})
    elif request.method=="DELETE":
        if config["instance"]["disable_channel_creation"]: return make_json_error(403, "Channel deletion is disabled")
        perm_data=db.get_permission_data(id, channel_id)
        if not perm_data["channel_data"]: return make_json_error(404, "Channel not found")
        channel_type=perm_data["channel_data"][0]["type"]
        if channel_type==1:
            db.update_data("members", {"hidden": 1}, {"user_id": id, "channel_id": channel_id})

            # Get user data and emit member_leave event only to the user hiding the channel
            user_data=db.execute_raw_sql("SELECT id, username, display_name, pfp FROM users WHERE id=?", (id,))[0]

            # For DM channels, only emit to the user who hid the channel, not to other members
            user_event_data={k: v for k, v in user_data.items() if k!="id"}
            emit("member_leave", {
                "channel_id": channel_id,
                "user": user_event_data
            }, {"user_id": [id]})
        else:
            if not perm_data["admin_member"]: return make_json_error(404, "Channel not found")
            user_permissions=perm_data["admin_member"][0]["permissions"]
            if has_permission(user_permissions, perm.owner, perm_data["channel_data"][0]["permissions"]):
                if "delete" in request.args:
                    channel_pfp_data=db.execute_raw_sql("SELECT pfp FROM channels WHERE id=?", (channel_id,))
                    if channel_pfp_data and channel_pfp_data[0]["pfp"]: db.cleanup_unused_files()

                    # Get all channel members and emit member_leave events
                    channel_members=db.execute_raw_sql("""
                        SELECT u.id, u.username, u.display_name, u.pfp
                        FROM users u
                        JOIN members m ON u.id=m.user_id
                        WHERE m.channel_id=?
                    """, (channel_id,))

                    for member_data in channel_members:
                        member_leave(channel_id, member_data, db)

                    # Emit channel deleted event
                    channel_deleted(channel_id, db)

                    db.delete_data("channels", {"id": channel_id})

                    return jsonify({"success": True})
                owner_count=db.execute_raw_sql("SELECT COUNT(*) as count FROM members WHERE channel_id=? AND (permissions & 2)=2", (channel_id,))[0]["count"]
                if owner_count==1:
                    total_members=db.execute_raw_sql("SELECT COUNT(*) as count FROM members WHERE channel_id=?", (channel_id,))[0]["count"]
                    if total_members>1: return make_json_error(403, "Cannot leave as the last owner unless channel is empty")
            # Get user data before deletion for emit
            user_data=db.execute_raw_sql("SELECT id, username, display_name, pfp FROM users WHERE id=?", (id,))[0]

            db.delete_data("members", {"user_id": id, "channel_id": channel_id})

            # Emit member leave event
            member_leave(channel_id, user_data, db)

            if db.execute_raw_sql("""
                SELECT COUNT(*) AS count
                FROM members
                WHERE channel_id=?
                """, (channel_id,))[0]["count"]==0:
                channel_pfp_data=db.execute_raw_sql("SELECT pfp FROM channels WHERE id=?", (channel_id,))
                if channel_pfp_data and channel_pfp_data[0]["pfp"]: db.cleanup_unused_files()

                # Emit channel deleted event
                channel_deleted(channel_id, db)

                db.delete_data("channels", {"id": channel_id})
        return jsonify({"success": True})

@channels_bp.route("/channel/<string:channel_id>/invite", methods=["GET"])
@logged_in()
@sliding_window_rate_limiter(limit=30, window=60, user_limit=15)
def get_invite(db:SQLite, id, channel_id):
    member_channel_data=db.execute_raw_sql("""
        SELECT m.permissions, c.type, c.permissions as channel_permissions, c.invite_code
        FROM members m
        JOIN channels c ON m.channel_id=c.id
        WHERE m.user_id=? AND m.channel_id=?
    """, (id, channel_id))
    if not member_channel_data: return make_json_error(404, "Channel not found")
    data=member_channel_data[0]
    if data["type"]==1: return make_json_error(400, "Cannot manage invites for DM channels")
    channel_permissions=data["channel_permissions"]
    if not has_permission(data["permissions"], perm.manage_channel, channel_permissions): return make_json_error(403, "Channel management privileges required")
    if data["invite_code"]: return jsonify({"invite_code": data["invite_code"], "success": True})
    return jsonify({"invite_code": None, "success": True})

@channels_bp.route("/channel/<string:channel_id>/invite", methods=["POST", "DELETE"])
@logged_in()
@sliding_window_rate_limiter(limit=20, window=300, user_limit=10)
@validate_request_data({"invite_code": {"optional": True, "minlen": 3, "maxlen": 20, "regex": re.compile(r"[a-zA-Z0-9_-]+")}})
def manage_invite(db:SQLite, id, channel_id):
    if request.method=="POST":
        member_channel_data=db.execute_raw_sql("""
            SELECT m.permissions, c.type, c.permissions as channel_permissions, c.invite_code
            FROM members m
            JOIN channels c ON m.channel_id=c.id
            WHERE m.user_id=? AND m.channel_id=?
        """, (id, channel_id))
        if not member_channel_data: return make_json_error(404, "Channel not found")
        data=member_channel_data[0]
        if data["type"]==1: return make_json_error(400, "Cannot manage invites for DM channels")
        channel_permissions=data["channel_permissions"]
        if not has_permission(data["permissions"], perm.manage_channel, channel_permissions): return make_json_error(403, "Channel management privileges required")
        custom_code=request.form.get("invite_code", "").strip()
        if custom_code:
            existing_with_code=db.select_data("channels", ["id"], {"invite_code": custom_code})
            if existing_with_code and existing_with_code[0]["id"]!=channel_id: return make_json_error(409, "Invite code already in use")
            invite_code=custom_code
        else:
            invite_code=generate(8)
        db.update_data("channels", {"invite_code": invite_code}, {"id": channel_id})
        return jsonify({"invite_code": invite_code, "success": True}), 201
    elif request.method=="DELETE":
        member_channel_data=db.execute_raw_sql("""
            SELECT m.permissions, c.type, c.permissions as channel_permissions
            FROM members m
            JOIN channels c ON m.channel_id=c.id
            WHERE m.user_id=? AND m.channel_id=?
        """, (id, channel_id))
        if not member_channel_data: return make_json_error(404, "Channel not found")
        data=member_channel_data[0]
        if data["type"]==1: return make_json_error(400, "Cannot manage invites for DM channels")
        channel_permissions=data["channel_permissions"]
        if not has_permission(data["permissions"], perm.manage_channel, channel_permissions): return make_json_error(403, "Channel management privileges required")
        db.update_data("channels", {"invite_code": None}, {"id": channel_id})
        return jsonify({"success": True})

@channels_bp.route("/channels/invite/<string:invite_code>", methods=["GET"])
@logged_in()
@sliding_window_rate_limiter(limit=50, window=60, user_limit=25)
def get_invite_info(db:SQLite, id, invite_code):
    channel_data=db.select_data("channels", ["id", "name", "pfp", "type"], {"invite_code": invite_code})
    if not channel_data: return make_json_error(404, "Invite not found")
    channel_id=channel_data[0]["id"]
    member_count=db.execute_raw_sql("SELECT COUNT(*) as count FROM members WHERE channel_id=?", (channel_id,))[0]["count"]
    is_member=db.exists("members", {"user_id": id, "channel_id": channel_id})
    return jsonify({"channel_id": channel_id, "name": channel_data[0]["name"], "pfp": channel_data[0]["pfp"], "type": channel_data[0]["type"], "member_count": member_count, "is_member": is_member, "success": True})

@channels_bp.route("/channels/invite/<string:invite_code>", methods=["POST"])
@logged_in()
@sliding_window_rate_limiter(limit=20, window=60, user_limit=10)
def join_invite(db:SQLite, id, invite_code):
    channel_data=db.select_data("channels", ["id", "type"], {"invite_code": invite_code})
    if not channel_data: return make_json_error(404, "Invite not found")
    channel_id=channel_data[0]["id"]
    if db.exists("members", {"user_id": id, "channel_id": channel_id}): return make_json_error(400, "You are already a member of this channel")
    if db.exists("bans", {"user_id": id, "channel_id": channel_id}): return make_json_error(403, "You are banned from this channel")
    error_resp=check_user_channel_limit(db, id)
    if error_resp: return error_resp
    channel_type=channel_data[0]["type"]
    if channel_type!=3:
        member_count=db.execute_raw_sql("SELECT COUNT(*) as count FROM members WHERE channel_id=?", (channel_id,))[0]["count"]
        if member_count>=config["max_members"]["encrypted_channels"]: return make_json_error(400, "Channel has reached maximum member limit")
    db.insert_data("members", {"user_id": id, "channel_id": channel_id, "joined_at": timestamp(), "message_seq": 0 if channel_type==3 else get_channel_last_message_seq(db, channel_id)})

    # Get user and channel data and emit events
    user_channel_data=db.execute_raw_sql("""
        SELECT u.id, u.username, u.display_name, u.pfp,
               c.name, c.pfp as channel_pfp, c.type, c.permissions,
               COUNT(m.user_id) as member_count
        FROM users u, channels c
        LEFT JOIN members m ON c.id=m.channel_id
        WHERE u.id=? AND c.id=?
        GROUP BY c.id
    """, (id, channel_id))[0]
    user_data={"id": user_channel_data["id"], "username": user_channel_data["username"], "display_name": user_channel_data["display_name"], "pfp": user_channel_data["pfp"]}
    full_channel_data={"id": channel_id, "name": user_channel_data["name"], "pfp": user_channel_data["channel_pfp"], "type": user_channel_data["type"], "permissions": user_channel_data["permissions"], "member_count": user_channel_data["member_count"]}
    member_join(channel_id, user_data, db)
    channel_added(id, full_channel_data, db)

    return jsonify({"channel_id": channel_id, "success": True})

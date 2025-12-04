"""
Premium Key Verification System
Advanced Backend + Telegram Bot with Premium Features
Deploy on Render.com - 100% FREE
"""

import os
import random
import string
import json
import hashlib
from datetime import datetime, timedelta
from threading import Thread
import asyncio
import time

# Flask for web server
from flask import Flask, request, jsonify
from flask_cors import CORS

# Telegram bot
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

# Configuration from environment variables
ADMIN_USER_IDS = [int(x) for x in os.environ.get('ADMIN_USER_IDS', '123456789').split(',')]
BOT_TOKEN = os.environ.get('BOT_TOKEN', 'YOUR_BOT_TOKEN_HERE')
PORT = int(os.environ.get('PORT', 10000))

# In-memory storage
keys = {}
device_locks = {}
generated_keys = {}
premium_users = {}  # Premium users who can generate keys
user_stats = {}  # Track user statistics
key_usage_logs = []  # Detailed logs
bot_settings = {
    "public_generation": False,
    "premium_only": False,
    "max_keys_per_user": 5,
    "key_expiry_hours": 24,
    "allow_key_renewal": True,
    "require_approval": False
}

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# ============================================
# HELPER FUNCTIONS
# ============================================

def hash_key(key):
    """Generate hash for key"""
    return hashlib.sha256(key.encode()).hexdigest()

def generate_key():
    """Generate a unique random key"""
    timestamp = int(time.time())
    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    return f"KEY-{key}-{timestamp % 1000}"

def is_premium_user(user_id):
    """Check if user has premium access"""
    return user_id in premium_users and premium_users[user_id].get('active', False)

def is_admin(user_id):
    """Check if user is admin"""
    return user_id in ADMIN_USER_IDS

def can_generate_key(user_id):
    """Check if user can generate keys"""
    if is_admin(user_id):
        return True, "Admin access"
    
    if bot_settings['public_generation']:
        return True, "Public generation enabled"
    
    if bot_settings['premium_only'] and is_premium_user(user_id):
        return True, "Premium user"
    
    return False, "Access denied"

def add_user_stat(user_id, action):
    """Track user actions"""
    if user_id not in user_stats:
        user_stats[user_id] = {
            'first_seen': datetime.now().isoformat(),
            'keys_generated': 0,
            'keys_used': 0,
            'last_activity': None
        }
    
    user_stats[user_id]['last_activity'] = datetime.now().isoformat()
    
    if action == 'generate':
        user_stats[user_id]['keys_generated'] += 1
    elif action == 'use':
        user_stats[user_id]['keys_used'] += 1

def log_key_activity(action, key, user_id=None, device_id=None, details=None):
    """Log key activities"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'key': key[:15] + '...',  # Partial key for security
        'user_id': user_id,
        'device_id': device_id,
        'details': details
    }
    key_usage_logs.append(log_entry)
    
    # Keep only last 1000 logs
    if len(key_usage_logs) > 1000:
        key_usage_logs.pop(0)

def cleanup_expired():
    """Clean up expired keys and device locks"""
    now = datetime.now()
    expired_count = 0
    
    for device_id in list(device_locks.keys()):
        lock = device_locks[device_id]
        expires_at = datetime.fromisoformat(lock['expiresAt'])
        if now >= expires_at:
            del device_locks[device_id]
            expired_count += 1
            log_key_activity('expired', lock['key'], device_id=device_id)
    
    return expired_count

def get_user_keys_count(user_id):
    """Count active keys for a user"""
    count = 0
    for key_data in keys.values():
        if key_data.get('generatedByUserId') == user_id and not key_data.get('used', False):
            count += 1
    return count

# ============================================
# FLASK API ROUTES
# ============================================

@app.route('/')
def home():
    """Home page - for UptimeRobot ping"""
    cleanup_expired()
    return jsonify({
        'status': 'online',
        'service': 'Premium Key Verification System',
        'version': '2.0.0',
        'timestamp': datetime.now().isoformat(),
        'bot_status': 'running' if telegram_app else 'stopped',
        'stats': {
            'active_keys': len([k for k in keys.values() if not k.get('used', False)]),
            'active_devices': len(device_locks),
            'total_keys': len(keys),
            'premium_users': len([u for u in premium_users.values() if u.get('active', False)]),
            'total_users': len(user_stats)
        }
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    cleanup_expired()
    return jsonify({
        'status': 'OK',
        'timestamp': datetime.now().isoformat(),
        'activeKeys': len([k for k in keys.values() if not k.get('used', False)]),
        'activeDevices': len(device_locks),
        'bot_running': telegram_app is not None,
        'uptime': 'running'
    })

@app.route('/api/store-key', methods=['POST'])
def store_key():
    """Store a new key"""
    data = request.get_json()
    key = data.get('key')
    user_id = data.get('userId')
    
    if not key:
        return jsonify({'success': False, 'message': 'Key is required'}), 400
    
    key_hash = hash_key(key)
    keys[key_hash] = {
        'key': key,
        'generatedBy': data.get('generatedBy', 'unknown'),
        'generatedByUserId': user_id,
        'generatedAt': data.get('generatedAt', datetime.now().isoformat()),
        'used': False,
        'deviceId': None,
        'usedAt': None,
        'expiresAt': None,
        'renewable': bot_settings['allow_key_renewal']
    }
    
    log_key_activity('generated', key, user_id=user_id, details='New key created')
    print(f"✅ Key stored: {key}")
    return jsonify({'success': True, 'message': 'Key stored successfully', 'keyHash': key_hash})

@app.route('/verify-key', methods=['POST'])
def verify_key():
    """Verify key and lock to device"""
    data = request.get_json()
    key = data.get('key')
    device_id = data.get('deviceId')
    
    if not key or not device_id:
        return jsonify({'success': False, 'message': 'Key and deviceId are required'}), 400
    
    key_hash = hash_key(key)
    key_data = keys.get(key_hash)
    
    if not key_data:
        log_key_activity('invalid_attempt', key, device_id=device_id, details='Key not found')
        print(f"❌ Invalid key: {key}")
        return jsonify({'success': False, 'message': 'Invalid key'})
    
    if key_data['used']:
        if key_data['deviceId'] == device_id:
            now = datetime.now()
            expires_at = datetime.fromisoformat(key_data['expiresAt'])
            
            if now < expires_at:
                log_key_activity('re_verified', key, device_id=device_id, details='Existing session')
                print(f"✅ Re-verification: {device_id}")
                return jsonify({
                    'success': True,
                    'message': 'Access granted (existing session)',
                    'expiresAt': key_data['expiresAt']
                })
            else:
                log_key_activity('expired_access', key, device_id=device_id)
                print(f"⏰ Expired: {device_id}")
                return jsonify({'success': False, 'message': 'Key has expired. Please get a new key.'})
        else:
            log_key_activity('duplicate_attempt', key, device_id=device_id, details='Different device')
            print(f"❌ Already used: {key}")
            return jsonify({'success': False, 'message': 'This key has already been used on another device'})
    
    now = datetime.now()
    expiry_hours = bot_settings['key_expiry_hours']
    expires_at = now + timedelta(hours=expiry_hours)
    
    key_data['used'] = True
    key_data['deviceId'] = device_id
    key_data['usedAt'] = now.isoformat()
    key_data['expiresAt'] = expires_at.isoformat()
    
    keys[key_hash] = key_data
    
    device_locks[device_id] = {
        'key': key,
        'keyHash': key_hash,
        'lockedAt': now.isoformat(),
        'expiresAt': expires_at.isoformat(),
        'renewable': key_data.get('renewable', True)
    }
    
    log_key_activity('verified', key, device_id=device_id, details=f'Access granted for {expiry_hours}h')
    print(f"🔓 Verified: {device_id} until {expires_at}")
    return jsonify({
        'success': True, 
        'message': 'Access granted', 
        'expiresAt': expires_at.isoformat(),
        'hoursRemaining': expiry_hours
    })

@app.route('/check-access', methods=['POST'])
def check_access():
    """Check device access status"""
    data = request.get_json()
    device_id = data.get('deviceId')
    
    if not device_id:
        return jsonify({'success': False, 'message': 'deviceId is required'}), 400
    
    device_lock = device_locks.get(device_id)
    
    if not device_lock:
        return jsonify({'success': False, 'hasAccess': False, 'message': 'No active access found'})
    
    now = datetime.now()
    expires_at = datetime.fromisoformat(device_lock['expiresAt'])
    
    if now < expires_at:
        time_left = int((expires_at - now).total_seconds() / 60)
        return jsonify({
            'success': True,
            'hasAccess': True,
            'message': 'Access active',
            'expiresAt': device_lock['expiresAt'],
            'timeLeftMinutes': time_left,
            'renewable': device_lock.get('renewable', False)
        })
    else:
        del device_locks[device_id]
        return jsonify({'success': False, 'hasAccess': False, 'message': 'Access expired'})

@app.route('/renew-access', methods=['POST'])
def renew_access():
    """Renew device access (if allowed)"""
    if not bot_settings['allow_key_renewal']:
        return jsonify({'success': False, 'message': 'Key renewal is disabled'})
    
    data = request.get_json()
    device_id = data.get('deviceId')
    
    if not device_id:
        return jsonify({'success': False, 'message': 'deviceId is required'}), 400
    
    device_lock = device_locks.get(device_id)
    
    if not device_lock or not device_lock.get('renewable', False):
        return jsonify({'success': False, 'message': 'Cannot renew this access'})
    
    now = datetime.now()
    new_expiry = now + timedelta(hours=bot_settings['key_expiry_hours'])
    
    device_lock['expiresAt'] = new_expiry.isoformat()
    device_locks[device_id] = device_lock
    
    # Update key data
    key_hash = device_lock['keyHash']
    if key_hash in keys:
        keys[key_hash]['expiresAt'] = new_expiry.isoformat()
    
    log_key_activity('renewed', device_lock['key'], device_id=device_id, details='Access renewed')
    
    return jsonify({
        'success': True,
        'message': 'Access renewed',
        'expiresAt': new_expiry.isoformat()
    })

@app.route('/api/stats')
def stats():
    """Get detailed statistics"""
    cleanup_expired()
    total_keys = len(keys)
    used_keys = sum(1 for k in keys.values() if k['used'])
    active_users = len(user_stats)
    
    return jsonify({
        'success': True,
        'stats': {
            'totalKeys': total_keys,
            'usedKeys': used_keys,
            'activeKeys': total_keys - used_keys,
            'activeDevices': len(device_locks),
            'premiumUsers': len([u for u in premium_users.values() if u.get('active', False)]),
            'totalUsers': active_users,
            'settings': {
                'publicGeneration': bot_settings['public_generation'],
                'premiumOnly': bot_settings['premium_only'],
                'maxKeysPerUser': bot_settings['max_keys_per_user'],
                'keyExpiryHours': bot_settings['key_expiry_hours']
            }
        }
    })

@app.route('/api/admin/keys')
def admin_keys():
    """List all keys (admin only)"""
    all_keys = [
        {
            'key': k['key'][:20] + '...',
            'used': k['used'],
            'deviceId': k['deviceId'],
            'generatedBy': k['generatedBy'],
            'generatedAt': k['generatedAt'],
            'usedAt': k['usedAt'],
            'expiresAt': k['expiresAt']
        }
        for k in list(keys.values())[-50:]  # Last 50 keys
    ]
    return jsonify({'success': True, 'keys': all_keys, 'total': len(keys)})

@app.route('/api/admin/users')
def admin_users():
    """List all users with stats"""
    users_list = [
        {
            'userId': uid,
            'stats': stats,
            'isPremium': is_premium_user(uid),
            'isAdmin': is_admin(uid)
        }
        for uid, stats in user_stats.items()
    ]
    return jsonify({'success': True, 'users': users_list, 'total': len(users_list)})

@app.route('/api/admin/logs')
def admin_logs():
    """Get recent activity logs"""
    recent_logs = key_usage_logs[-100:]  # Last 100 logs
    return jsonify({'success': True, 'logs': recent_logs, 'total': len(key_usage_logs)})

@app.route('/api/admin/revoke-key', methods=['POST'])
def revoke_key():
    """Revoke a specific key"""
    data = request.get_json()
    key = data.get('key')
    
    if not key:
        return jsonify({'success': False, 'message': 'Key is required'}), 400
    
    key_hash = hash_key(key)
    key_data = keys.get(key_hash)
    
    if not key_data:
        return jsonify({'success': False, 'message': 'Key not found'})
    
    if key_data.get('deviceId'):
        device_locks.pop(key_data['deviceId'], None)
    
    keys.pop(key_hash, None)
    log_key_activity('revoked', key, details='Admin revoked')
    
    return jsonify({'success': True, 'message': 'Key revoked successfully'})

# ============================================
# TELEGRAM BOT HANDLERS
# ============================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command with advanced welcome"""
    user_id = update.effective_user.id
    username = update.effective_user.first_name
    is_admin_user = is_admin(user_id)
    is_premium = is_premium_user(user_id)
    
    # Track user
    if user_id not in user_stats:
        user_stats[user_id] = {
            'first_seen': datetime.now().isoformat(),
            'keys_generated': 0,
            'keys_used': 0,
            'last_activity': datetime.now().isoformat()
        }
    
    status_icon = "👑" if is_admin_user else "⭐" if is_premium else "👤"
    status_text = "Admin" if is_admin_user else "Premium" if is_premium else "User"
    
    welcome_text = f"""
{status_icon} **Welcome to Premium Key System**

Hello {username}!

**Your Status:** {status_text}
**User ID:** `{user_id}`

{'🔧 **Admin Panel Access**' if is_admin_user else '⭐ **Premium Features Active**' if is_premium else '📋 **Standard Access**'}

**Quick Actions:**
{'• Generate unlimited keys' if is_admin_user else '• Generate premium keys' if is_premium else '• Request access to generate keys'}
• View statistics
• Get help & support

**System Status:**
• Mode: {'🟢 Public' if bot_settings['public_generation'] else '🔴 Premium Only' if bot_settings['premium_only'] else '🔴 Restricted'}
• Active Devices: {len(device_locks)}
• Key Expiry: {bot_settings['key_expiry_hours']} hours

Use the buttons below or type /help for commands!
"""
    
    keyboard = []
    
    can_gen, reason = can_generate_key(user_id)
    if can_gen:
        keyboard.append([InlineKeyboardButton("🔑 Generate Key", callback_data="generate_key")])
    
    keyboard.append([InlineKeyboardButton("📊 My Statistics", callback_data="my_stats")])
    
    if is_admin_user:
        keyboard.append([
            InlineKeyboardButton("⚙️ Settings", callback_data="settings"),
            InlineKeyboardButton("👥 Users", callback_data="user_management")
        ])
        keyboard.append([
            InlineKeyboardButton("📈 System Stats", callback_data="system_stats"),
            InlineKeyboardButton("📝 Logs", callback_data="view_logs")
        ])
    
    keyboard.append([InlineKeyboardButton("❓ Help", callback_data="help")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode='Markdown')

async def generate_key_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generate key command"""
    user_id = update.effective_user.id
    username = update.effective_user.first_name
    
    can_gen, reason = can_generate_key(user_id)
    
    if not can_gen:
        await update.message.reply_text(
            f"❌ **Access Denied**\n\n{reason}\n\n"
            "Contact admin for premium access.",
            parse_mode='Markdown'
        )
        return
    
    # Check user key limit
    if not is_admin(user_id):
        user_keys = get_user_keys_count(user_id)
        if user_keys >= bot_settings['max_keys_per_user']:
            await update.message.reply_text(
                f"⚠️ **Key Limit Reached**\n\n"
                f"You have {user_keys} active keys.\n"
                f"Maximum allowed: {bot_settings['max_keys_per_user']}\n\n"
                "Use existing keys or wait for them to expire.",
                parse_mode='Markdown'
            )
            return
    
    processing_msg = await update.message.reply_text("⏳ Generating your premium key...")
    
    key = generate_key()
    timestamp = datetime.now().isoformat()
    
    # Store in memory
    generated_keys[key] = {
        "generated_by": user_id,
        "generated_at": timestamp,
        "used": False
    }
    
    # Store in backend
    key_hash = hash_key(key)
    keys[key_hash] = {
        'key': key,
        'generatedBy': f"{username} ({user_id})",
        'generatedByUserId': user_id,
        'generatedAt': timestamp,
        'used': False,
        'deviceId': None,
        'usedAt': None,
        'expiresAt': None,
        'renewable': bot_settings['allow_key_renewal']
    }
    
    add_user_stat(user_id, 'generate')
    
    user_keys = get_user_keys_count(user_id)
    
    response_text = f"""
✅ **Premium Key Generated!**

🔑 **Key:** `{key}`

📊 **Details:**
• Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
• By: {username}
• Valid: {bot_settings['key_expiry_hours']} hours after first use
• Active Keys: {user_keys}/{bot_settings['max_keys_per_user']}

📝 **Instructions:**
1. Tap the key above to copy
2. Open the website
3. Paste in verification box
4. Click "Verify Key"

⚠️ **Important:**
• One-time use only
• Locks to first device
• {bot_settings['key_expiry_hours']}h access after verification
• {'Renewable after use' if bot_settings['allow_key_renewal'] else 'Non-renewable'}

🌐 Enjoy premium access!
"""
    
    keyboard = [[InlineKeyboardButton("🔄 Generate Another", callback_data="generate_key")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await processing_msg.edit_text(response_text, reply_markup=reply_markup, parse_mode='Markdown')

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle all button callbacks"""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    username = update.effective_user.first_name
    is_admin_user = is_admin(user_id)
    
    # Generate Key
    if query.data == "generate_key":
        can_gen, reason = can_generate_key(user_id)
        
        if not can_gen:
            await query.edit_message_text(
                f"❌ **Access Denied**\n\n{reason}",
                parse_mode='Markdown'
            )
            return
        
        # Check limit
        if not is_admin_user:
            user_keys = get_user_keys_count(user_id)
            if user_keys >= bot_settings['max_keys_per_user']:
                await query.edit_message_text(
                    f"⚠️ **Limit Reached**\n\nActive: {user_keys}/{bot_settings['max_keys_per_user']}",
                    parse_mode='Markdown'
                )
                return
        
        await query.edit_message_text("⏳ Generating...")
        
        key = generate_key()
        timestamp = datetime.now().isoformat()
        
        generated_keys[key] = {"generated_by": user_id, "generated_at": timestamp, "used": False}
        
        key_hash = hash_key(key)
        keys[key_hash] = {
            'key': key,
            'generatedBy': f"{username} ({user_id})",
            'generatedByUserId': user_id,
            'generatedAt': timestamp,
            'used': False,
            'deviceId': None,
            'usedAt': None,
            'expiresAt': None,
            'renewable': bot_settings['allow_key_renewal']
        }
        
        add_user_stat(user_id, 'generate')
        user_keys = get_user_keys_count(user_id)
        
        response_text = f"""
✅ **Key Generated!**

🔑 `{key}`

⏰ {datetime.now().strftime('%H:%M:%S')}
📊 Keys: {user_keys}/{bot_settings['max_keys_per_user']}

Tap to copy → Paste on website!
"""
        
        keyboard = [
            [InlineKeyboardButton("🔄 Generate Another", callback_data="generate_key")],
            [InlineKeyboardButton("🔙 Main Menu", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(response_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    # My Statistics
    elif query.data == "my_stats":
        stats = user_stats.get(user_id, {})
        user_keys = get_user_keys_count(user_id)
        is_premium = is_premium_user(user_id)
        
        stats_text = f"""
📊 **Your Statistics**

👤 **Profile:**
• Status: {'👑 Admin' if is_admin_user else '⭐ Premium' if is_premium else '👤 User'}
• User ID: `{user_id}`
• Member Since: {stats.get('first_seen', 'Unknown')[:10]}

🔑 **Key Stats:**
• Keys Generated: {stats.get('keys_generated', 0)}
• Keys Used: {stats.get('keys_used', 0)}
• Active Keys: {user_keys}

⏰ **Activity:**
• Last Active: {stats.get('last_activity', 'Unknown')[:16]}

📈 Total: {stats.get('keys_generated', 0)} keys created
"""
        
        keyboard = [
            [InlineKeyboardButton("🔄 Refresh", callback_data="my_stats")],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(stats_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    # Settings (Admin Only)
    elif query.data == "settings":
        if not is_admin_user:
            await query.edit_message_text("❌ Admin access required.")
            return
        
        keyboard = [
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['public_generation'] else '🔴'} Public Generation",
                callback_data="toggle_public"
            )],
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['premium_only'] else '🔴'} Premium Only Mode",
                callback_data="toggle_premium_only"
            )],
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['allow_key_renewal'] else '🔴'} Allow Renewals",
                callback_data="toggle_renewal"
            )],
            [InlineKeyboardButton(
                f"⏰ Expiry: {bot_settings['key_expiry_hours']}h",
                callback_data="change_expiry"
            )],
            [InlineKeyboardButton(
                f"🔢 Max Keys: {bot_settings['max_keys_per_user']}",
                callback_data="change_max_keys"
            )],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"⚙️ **Settings Updated**\n\n"
            f"Public: {'✅' if bot_settings['public_generation'] else '❌'}\n"
            f"Premium Only: {'✅' if bot_settings['premium_only'] else '❌'}\n"
            f"Renewals: {'✅' if bot_settings['allow_key_renewal'] else '❌'}",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    # Change Expiry
    elif query.data == "change_expiry":
        if not is_admin_user:
            await query.answer("❌ Admin only", show_alert=True)
            return
        
        keyboard = [
            [InlineKeyboardButton("⏰ 6 hours", callback_data="set_expiry_6")],
            [InlineKeyboardButton("⏰ 12 hours", callback_data="set_expiry_12")],
            [InlineKeyboardButton("⏰ 24 hours", callback_data="set_expiry_24")],
            [InlineKeyboardButton("⏰ 48 hours", callback_data="set_expiry_48")],
            [InlineKeyboardButton("⏰ 72 hours", callback_data="set_expiry_72")],
            [InlineKeyboardButton("🔙 Back", callback_data="settings")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "⏰ **Select Key Expiry Time**\n\nHow long should keys remain valid after first use?",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    elif query.data.startswith("set_expiry_"):
        if not is_admin_user:
            await query.answer("❌ Admin only", show_alert=True)
            return
        
        hours = int(query.data.split("_")[-1])
        bot_settings["key_expiry_hours"] = hours
        await query.answer(f"✅ Expiry set to {hours} hours!", show_alert=True)
        
        # Go back to settings
        keyboard = [
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['public_generation'] else '🔴'} Public Generation",
                callback_data="toggle_public"
            )],
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['premium_only'] else '🔴'} Premium Only Mode",
                callback_data="toggle_premium_only"
            )],
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['allow_key_renewal'] else '🔴'} Allow Renewals",
                callback_data="toggle_renewal"
            )],
            [InlineKeyboardButton(
                f"⏰ Expiry: {bot_settings['key_expiry_hours']}h",
                callback_data="change_expiry"
            )],
            [InlineKeyboardButton(
                f"🔢 Max Keys: {bot_settings['max_keys_per_user']}",
                callback_data="change_max_keys"
            )],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "⚙️ **Settings**\n\n✅ Expiry time updated!",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    # Change Max Keys
    elif query.data == "change_max_keys":
        if not is_admin_user:
            await query.answer("❌ Admin only", show_alert=True)
            return
        
        keyboard = [
            [InlineKeyboardButton("🔢 3 keys", callback_data="set_max_3")],
            [InlineKeyboardButton("🔢 5 keys", callback_data="set_max_5")],
            [InlineKeyboardButton("🔢 10 keys", callback_data="set_max_10")],
            [InlineKeyboardButton("🔢 20 keys", callback_data="set_max_20")],
            [InlineKeyboardButton("🔢 50 keys", callback_data="set_max_50")],
            [InlineKeyboardButton("🔢 Unlimited", callback_data="set_max_999")],
            [InlineKeyboardButton("🔙 Back", callback_data="settings")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "🔢 **Select Max Keys Per User**\n\nHow many active keys can each user have?",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    elif query.data.startswith("set_max_"):
        if not is_admin_user:
            await query.answer("❌ Admin only", show_alert=True)
            return
        
        max_keys = int(query.data.split("_")[-1])
        bot_settings["max_keys_per_user"] = max_keys
        await query.answer(f"✅ Max keys set to {max_keys}!", show_alert=True)
        
        # Go back to settings
        keyboard = [
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['public_generation'] else '🔴'} Public Generation",
                callback_data="toggle_public"
            )],
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['premium_only'] else '🔴'} Premium Only Mode",
                callback_data="toggle_premium_only"
            )],
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['allow_key_renewal'] else '🔴'} Allow Renewals",
                callback_data="toggle_renewal"
            )],
            [InlineKeyboardButton(
                f"⏰ Expiry: {bot_settings['key_expiry_hours']}h",
                callback_data="change_expiry"
            )],
            [InlineKeyboardButton(
                f"🔢 Max Keys: {bot_settings['max_keys_per_user']}",
                callback_data="change_max_keys"
            )],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "⚙️ **Settings**\n\n✅ Max keys updated!",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    # User Management (Admin)
    elif query.data == "user_management":
        if not is_admin_user:
            await query.edit_message_text("❌ Admin access required.")
            return
        
        keyboard = [
            [InlineKeyboardButton("👥 View All Users", callback_data="view_all_users")],
            [InlineKeyboardButton("⭐ Manage Premium", callback_data="manage_premium")],
            [InlineKeyboardButton("🔍 Search User", callback_data="search_user")],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        total_users = len(user_stats)
        premium_count = len([u for u in premium_users.values() if u.get('active', False)])
        
        await query.edit_message_text(
            f"👥 **User Management**\n\n"
            f"Total Users: {total_users}\n"
            f"Premium Users: {premium_count}\n"
            f"Admins: {len(ADMIN_USER_IDS)}\n\n"
            "Select an option:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    # View All Users
    elif query.data == "view_all_users":
        if not is_admin_user:
            await query.answer("❌ Admin only", show_alert=True)
            return
        
        users_list = []
        for uid, stats in list(user_stats.items())[:10]:  # Show first 10
            status = "👑" if is_admin(uid) else "⭐" if is_premium_user(uid) else "👤"
            users_list.append(
                f"{status} ID: `{uid}`\n"
                f"   Keys: {stats.get('keys_generated', 0)} | "
                f"Last: {stats.get('last_activity', 'N/A')[:10]}"
            )
        
        users_text = "\n\n".join(users_list) if users_list else "No users yet"
        
        keyboard = [
            [InlineKeyboardButton("🔄 Refresh", callback_data="view_all_users")],
            [InlineKeyboardButton("🔙 Back", callback_data="user_management")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"👥 **Recent Users** (Top 10)\n\n{users_text}",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    # Manage Premium
    elif query.data == "manage_premium":
        if not is_admin_user:
            await query.answer("❌ Admin only", show_alert=True)
            return
        
        premium_list = []
        for uid, data in premium_users.items():
            if data.get('active', False):
                premium_list.append(
                    f"⭐ User: `{uid}`\n"
                    f"   Since: {data.get('granted_at', 'Unknown')[:10]}\n"
                    f"   By: {data.get('granted_by', 'Unknown')}"
                )
        
        premium_text = "\n\n".join(premium_list) if premium_list else "No premium users"
        
        keyboard = [
            [InlineKeyboardButton("➕ Add Premium User", callback_data="add_premium")],
            [InlineKeyboardButton("➖ Remove Premium", callback_data="remove_premium")],
            [InlineKeyboardButton("🔙 Back", callback_data="user_management")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"⭐ **Premium Users**\n\n{premium_text}\n\nManage premium access:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    # System Stats (Admin)
    elif query.data == "system_stats":
        if not is_admin_user:
            await query.answer("❌ Admin only", show_alert=True)
            return
        
        cleanup_expired()
        total_keys = len(keys)
        used_keys = sum(1 for k in keys.values() if k['used'])
        active_keys = total_keys - used_keys
        
        stats_text = f"""
📈 **System Statistics**

🔑 **Keys:**
• Total Generated: {total_keys}
• Currently Active: {active_keys}
• Used/Expired: {used_keys}

🌐 **Devices:**
• Active Devices: {len(device_locks)}
• Total Accesses: {sum(1 for k in keys.values() if k['used'])}

👥 **Users:**
• Total Users: {len(user_stats)}
• Premium Users: {len([u for u in premium_users.values() if u.get('active', False)])}
• Active Today: {len([s for s in user_stats.values() if s.get('last_activity', '')[:10] == datetime.now().strftime('%Y-%m-%d')])}

⚙️ **Settings:**
• Mode: {'Public' if bot_settings['public_generation'] else 'Premium' if bot_settings['premium_only'] else 'Admin Only'}
• Key Expiry: {bot_settings['key_expiry_hours']}h
• Max per User: {bot_settings['max_keys_per_user']}

📊 **Activity:**
• Total Logs: {len(key_usage_logs)}
• Uptime: Running ✅
"""
        
        keyboard = [
            [InlineKeyboardButton("🔄 Refresh", callback_data="system_stats")],
            [InlineKeyboardButton("📝 View Logs", callback_data="view_logs")],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(stats_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    # View Logs (Admin)
    elif query.data == "view_logs":
        if not is_admin_user:
            await query.answer("❌ Admin only", show_alert=True)
            return
        
        recent_logs = key_usage_logs[-10:]  # Last 10 logs
        
        logs_text = []
        for log in recent_logs:
            logs_text.append(
                f"• {log['action'].upper()}\n"
                f"  {log['timestamp'][11:16]} | {log.get('details', 'N/A')}"
            )
        
        logs_display = "\n\n".join(logs_text) if logs_text else "No logs yet"
        
        keyboard = [
            [InlineKeyboardButton("🔄 Refresh", callback_data="view_logs")],
            [InlineKeyboardButton("🗑️ Clear Logs", callback_data="clear_logs")],
            [InlineKeyboardButton("🔙 Back", callback_data="system_stats")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"📝 **Recent Activity Logs**\n\n{logs_display}\n\nTotal: {len(key_usage_logs)} entries",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    # Clear Logs
    elif query.data == "clear_logs":
        if not is_admin_user:
            await query.answer("❌ Admin only", show_alert=True)
            return
        
        key_usage_logs.clear()
        await query.answer("✅ Logs cleared!", show_alert=True)
        
        keyboard = [
            [InlineKeyboardButton("🔙 Back", callback_data="system_stats")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "📝 **Logs Cleared**\n\nAll activity logs have been cleared.",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    # Help
    elif query.data == "help":
        help_text = f"""
❓ **Help & Support**

**For Users:**
• Use /generate to create a new key
• Copy the key and use it on the website
• Each key works once and locks to your device
• Access lasts {bot_settings['key_expiry_hours']} hours

**Commands:**
• /start - Main menu
• /generate - Generate new key
• /stats - Your statistics
• /help - Show this help

**Key Features:**
• One-time use per key
• Device-specific locking
• Auto-expiry after {bot_settings['key_expiry_hours']}h
• {'Renewable access' if bot_settings['allow_key_renewal'] else 'Non-renewable'}

**Need Premium?**
Contact an admin to get premium access and generate unlimited keys!

**Having Issues?**
• Make sure you copy the full key
• Check if key has expired
• Try generating a new key
• Contact admin for support
"""
        
        keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(help_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    # Back to Main
    elif query.data == "back_to_main":
        status_icon = "👑" if is_admin_user else "⭐" if is_premium_user(user_id) else "👤"
        
        keyboard = []
        
        can_gen, _ = can_generate_key(user_id)
        if can_gen:
            keyboard.append([InlineKeyboardButton("🔑 Generate Key", callback_data="generate_key")])
        
        keyboard.append([InlineKeyboardButton("📊 My Statistics", callback_data="my_stats")])
        
        if is_admin_user:
            keyboard.append([
                InlineKeyboardButton("⚙️ Settings", callback_data="settings"),
                InlineKeyboardButton("👥 Users", callback_data="user_management")
            ])
            keyboard.append([
                InlineKeyboardButton("📈 System Stats", callback_data="system_stats"),
                InlineKeyboardButton("📝 Logs", callback_data="view_logs")
            ])
        
        keyboard.append([InlineKeyboardButton("❓ Help", callback_data="help")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"{status_icon} **Main Menu**\n\nWelcome back, {username}!\n\nChoose an option:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command"""
    await update.message.reply_text(
        "❓ **Quick Help**\n\n"
        "**Commands:**\n"
        "/start - Main menu\n"
        "/generate - Generate key\n"
        "/stats - Your stats\n"
        "/help - This message\n\n"
        "**How to use:**\n"
        "1. Generate a key\n"
        "2. Copy it\n"
        "3. Paste on website\n"
        "4. Enjoy access!\n\n"
        f"Keys valid for {bot_settings['key_expiry_hours']}h after first use.",
        parse_mode='Markdown'
    )

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Stats command"""
    user_id = update.effective_user.id
    stats = user_stats.get(user_id, {})
    user_keys = get_user_keys_count(user_id)
    
    await update.message.reply_text(
        f"📊 **Your Stats**\n\n"
        f"Generated: {stats.get('keys_generated', 0)}\n"
        f"Used: {stats.get('keys_used', 0)}\n"
        f"Active: {user_keys}\n"
        f"Member since: {stats.get('first_seen', 'Unknown')[:10]}",
        parse_mode='Markdown'
    )

async def premium_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Grant premium access (admin only)"""
    user_id = update.effective_user.id
    
    if not is_admin(user_id):
        await update.message.reply_text("❌ Admin access required.")
        return
    
    # Check if command has user ID
    if not context.args:
        await update.message.reply_text(
            "**Usage:** `/premium <user_id>`\n\n"
            "Example: `/premium 123456789`",
            parse_mode='Markdown'
        )
        return
    
    try:
        target_user_id = int(context.args[0])
        
        if target_user_id in premium_users and premium_users[target_user_id].get('active', False):
            await update.message.reply_text(f"⚠️ User `{target_user_id}` is already premium.", parse_mode='Markdown')
            return
        
        premium_users[target_user_id] = {
            'active': True,
            'granted_at': datetime.now().isoformat(),
            'granted_by': user_id
        }
        
        await update.message.reply_text(
            f"✅ **Premium Access Granted!**\n\n"
            f"User: `{target_user_id}`\n"
            f"Granted by: Admin\n"
            f"Status: ⭐ Premium Active",
            parse_mode='Markdown'
        )
        
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID. Must be a number.")

async def revoke_premium_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Revoke premium access (admin only)"""
    user_id = update.effective_user.id
    
    if not is_admin(user_id):
        await update.message.reply_text("❌ Admin access required.")
        return
    
    if not context.args:
        await update.message.reply_text(
            "**Usage:** `/revoke <user_id>`\n\n"
            "Example: `/revoke 123456789`",
            parse_mode='Markdown'
        )
        return
    
    try:
        target_user_id = int(context.args[0])
        
        if target_user_id not in premium_users or not premium_users[target_user_id].get('active', False):
            await update.message.reply_text(f"⚠️ User `{target_user_id}` is not premium.", parse_mode='Markdown')
            return
        
        premium_users[target_user_id]['active'] = False
        
        await update.message.reply_text(
            f"✅ **Premium Revoked**\n\n"
            f"User: `{target_user_id}`\n"
            f"Status: 👤 Standard User",
            parse_mode='Markdown'
        )
        
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID. Must be a number.")

async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Broadcast message to all users (admin only)"""
    user_id = update.effective_user.id
    
    if not is_admin(user_id):
        await update.message.reply_text("❌ Admin access required.")
        return
    
    if not context.args:
        await update.message.reply_text(
            "**Usage:** `/broadcast <message>`\n\n"
            "Example: `/broadcast System maintenance in 1 hour`",
            parse_mode='Markdown'
        )
        return
    
    message = ' '.join(context.args)
    
    sent_count = 0
    failed_count = 0
    
    await update.message.reply_text(f"📢 Broadcasting to {len(user_stats)} users...")
    
    for uid in user_stats.keys():
        try:
            await context.bot.send_message(
                chat_id=uid,
                text=f"📢 **System Announcement**\n\n{message}",
                parse_mode='Markdown'
            )
            sent_count += 1
        except:
            failed_count += 1
    
    await update.message.reply_text(
        f"✅ **Broadcast Complete**\n\n"
        f"Sent: {sent_count}\n"
        f"Failed: {failed_count}",
        parse_mode='Markdown'
    )

# ============================================
# TELEGRAM BOT SETUP
# ============================================

telegram_app = None

async def setup_telegram_bot():
    """Setup and run Telegram bot"""
    global telegram_app
    
    telegram_app = Application.builder().token(BOT_TOKEN).build()
    
    # Command handlers
    telegram_app.add_handler(CommandHandler("start", start))
    telegram_app.add_handler(CommandHandler("generate", generate_key_command))
    telegram_app.add_handler(CommandHandler("help", help_command))
    telegram_app.add_handler(CommandHandler("stats", stats_command))
    telegram_app.add_handler(CommandHandler("premium", premium_command))
    telegram_app.add_handler(CommandHandler("revoke", revoke_premium_command))
    telegram_app.add_handler(CommandHandler("broadcast", broadcast_command))
    
    # Button callback handler
    telegram_app.add_handler(CallbackQueryHandler(button_handler))
    
    print("🤖 Telegram bot initializing...")
    await telegram_app.initialize()
    await telegram_app.start()
    await telegram_app.updater.start_polling(drop_pending_updates=True)
    
    print("✅ Bot is running!")

def run_bot():
    """Run bot in separate thread"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(setup_telegram_bot())
    loop.run_forever()

# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Premium Key Verification System v2.0")
    print("="*60)
    print(f"📡 Port: {PORT}")
    print(f"👥 Admins: {len(ADMIN_USER_IDS)}")
    print(f"🤖 Bot: {'✅ Configured' if BOT_TOKEN != 'YOUR_BOT_TOKEN_HERE' else '❌ Not configured'}")
    print(f"⚙️  Mode: {'🟢 Public' if bot_settings['public_generation'] else '⭐ Premium' if bot_settings['premium_only'] else '👑 Admin Only'}")
    print("="*60 + "\n")
    
    # Start Telegram bot in separate thread
    bot_thread = Thread(target=run_bot, daemon=True)
    bot_thread.start()
    print("🤖 Starting Telegram bot...")
    
    # Give bot time to start
    time.sleep(2)
    
    # Start Flask server
    print("🌐 Starting web server...\n")
    app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False)'] else ''} Allow Renewals",
                callback_data="toggle_renewal"
            )],
            [InlineKeyboardButton(
                f"⏰ Expiry: {bot_settings['key_expiry_hours']}h",
                callback_data="change_expiry"
            )],
            [InlineKeyboardButton(
                f"🔢 Max Keys: {bot_settings['max_keys_per_user']}",
                callback_data="change_max_keys"
            )],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        settings_text = f"""
⚙️ **Bot Settings**

**Generation Mode:**
• Public: {'✅ Enabled' if bot_settings['public_generation'] else '❌ Disabled'}
• Premium Only: {'✅ Active' if bot_settings['premium_only'] else '❌ Inactive'}

**Key Settings:**
• Expiry Time: {bot_settings['key_expiry_hours']} hours
• Max Per User: {bot_settings['max_keys_per_user']} keys
• Renewals: {'✅ Allowed' if bot_settings['allow_key_renewal'] else '❌ Disabled'}

**Current Mode:**
{('🟢 Anyone can generate' if bot_settings['public_generation'] else '⭐ Premium users only' if bot_settings['premium_only'] else '👑 Admin only')}
"""
        
        await query.edit_message_text(settings_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    # Toggle Settings
    elif query.data.startswith("toggle_"):
        if not is_admin_user:
            await query.answer("❌ Admin only", show_alert=True)
            return
        
        if query.data == "toggle_public":
            bot_settings["public_generation"] = not bot_settings["public_generation"]
            await query.answer(f"Public generation {'enabled' if bot_settings['public_generation'] else 'disabled'}!", show_alert=True)
        elif query.data == "toggle_premium_only":
            bot_settings["premium_only"] = not bot_settings["premium_only"]
            await query.answer(f"Premium mode {'enabled' if bot_settings['premium_only'] else 'disabled'}!", show_alert=True)
        elif query.data == "toggle_renewal":
            bot_settings["allow_key_renewal"] = not bot_settings["allow_key_renewal"]
            await query.answer(f"Key renewal {'enabled' if bot_settings['allow_key_renewal'] else 'disabled'}!", show_alert=True)
        
        # Refresh settings page
        keyboard = [
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['public_generation'] else '🔴'} Public Generation",
                callback_data="toggle_public"
            )],
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['premium_only'] else '🔴'} Premium Only Mode",
                callback_data="toggle_premium_only"
            )],
            [InlineKeyboardButton(
                f"{'🟢' if bot_settings['allow_key_renewal

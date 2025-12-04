"""
Combined Server - Backend API + Telegram Bot
Perfect for Render.com free tier deployment
"""

import os
import random
import string
import json
import hashlib
from datetime import datetime, timedelta
from threading import Thread
import asyncio

# Flask for web server
from flask import Flask, request, jsonify
from flask_cors import CORS

# Telegram bot
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

# Configuration from environment variables
ADMIN_USER_IDS = [int(x) for x in os.environ.get('ADMIN_USER_IDS', '123456789').split(',')]
BOT_TOKEN = os.environ.get('BOT_TOKEN', 'YOUR_BOT_TOKEN_HERE')
PORT = int(os.environ.get('PORT', 10000))

# In-memory storage
keys = {}
device_locks = {}
generated_keys = {}
bot_settings = {"public_generation": False}

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
    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
    return f"KEY-{key}"

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
    
    return expired_count

# ============================================
# FLASK API ROUTES
# ============================================

@app.route('/')
def home():
    """Home page - for UptimeRobot ping"""
    return jsonify({
        'status': 'online',
        'service': 'Key Verification System',
        'timestamp': datetime.now().isoformat(),
        'bot_status': 'running' if telegram_app else 'stopped',
        'active_keys': len(keys),
        'active_devices': len(device_locks)
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    cleanup_expired()
    return jsonify({
        'status': 'OK',
        'timestamp': datetime.now().isoformat(),
        'activeKeys': len(keys),
        'activeDevices': len(device_locks),
        'bot_running': telegram_app is not None
    })

@app.route('/api/store-key', methods=['POST'])
def store_key():
    """Store a new key"""
    data = request.get_json()
    key = data.get('key')
    
    if not key:
        return jsonify({'success': False, 'message': 'Key is required'}), 400
    
    key_hash = hash_key(key)
    keys[key_hash] = {
        'key': key,
        'generatedBy': data.get('generatedBy', 'unknown'),
        'generatedAt': data.get('generatedAt', datetime.now().isoformat()),
        'used': False,
        'deviceId': None,
        'usedAt': None,
        'expiresAt': None
    }
    
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
        print(f"❌ Invalid key: {key}")
        return jsonify({'success': False, 'message': 'Invalid key'})
    
    if key_data['used']:
        if key_data['deviceId'] == device_id:
            now = datetime.now()
            expires_at = datetime.fromisoformat(key_data['expiresAt'])
            
            if now < expires_at:
                print(f"✅ Re-verification: {device_id}")
                return jsonify({
                    'success': True,
                    'message': 'Access granted (existing session)',
                    'expiresAt': key_data['expiresAt']
                })
            else:
                print(f"⏰ Expired: {device_id}")
                return jsonify({'success': False, 'message': 'Key has expired. Please get a new key.'})
        else:
            print(f"❌ Already used: {key}")
            return jsonify({'success': False, 'message': 'This key has already been used on another device'})
    
    now = datetime.now()
    expires_at = now + timedelta(hours=24)
    
    key_data['used'] = True
    key_data['deviceId'] = device_id
    key_data['usedAt'] = now.isoformat()
    key_data['expiresAt'] = expires_at.isoformat()
    
    keys[key_hash] = key_data
    
    device_locks[device_id] = {
        'key': key,
        'keyHash': key_hash,
        'lockedAt': now.isoformat(),
        'expiresAt': expires_at.isoformat()
    }
    
    print(f"🔓 Verified: {device_id} until {expires_at}")
    return jsonify({'success': True, 'message': 'Access granted', 'expiresAt': expires_at.isoformat()})

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
            'timeLeftMinutes': time_left
        })
    else:
        del device_locks[device_id]
        return jsonify({'success': False, 'hasAccess': False, 'message': 'Access expired'})

@app.route('/api/stats')
def stats():
    """Get statistics"""
    cleanup_expired()
    total_keys = len(keys)
    used_keys = sum(1 for k in keys.values() if k['used'])
    
    return jsonify({
        'success': True,
        'stats': {
            'totalKeys': total_keys,
            'usedKeys': used_keys,
            'activeKeys': total_keys - used_keys,
            'activeDevices': len(device_locks)
        }
    })

@app.route('/api/admin/keys')
def admin_keys():
    """List all keys (admin only)"""
    all_keys = [
        {
            'key': k['key'],
            'used': k['used'],
            'deviceId': k['deviceId'],
            'generatedAt': k['generatedAt'],
            'usedAt': k['usedAt'],
            'expiresAt': k['expiresAt']
        }
        for k in keys.values()
    ]
    return jsonify({'success': True, 'keys': all_keys})

# ============================================
# TELEGRAM BOT HANDLERS
# ============================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command"""
    user_id = update.effective_user.id
    is_admin = user_id in ADMIN_USER_IDS
    
    welcome_text = f"""
🔐 **Website Access Key Generator**

Welcome {update.effective_user.first_name}!

{'🔧 **Admin Panel**' if is_admin else '**User Panel**'}

Available Commands:
{'/generate - Generate new access key' if is_admin or bot_settings['public_generation'] else '❌ Key generation is restricted to admin'}
{'/settings - Bot settings (Admin only)' if is_admin else ''}
/help - Show this message
/stats - View statistics

Status: {'🟢 Public Mode' if bot_settings['public_generation'] else '🔴 Admin Only'}
"""
    
    keyboard = []
    if is_admin or bot_settings["public_generation"]:
        keyboard.append([InlineKeyboardButton("🔑 Generate Key", callback_data="generate_key")])
    if is_admin:
        keyboard.append([InlineKeyboardButton("⚙️ Settings", callback_data="settings")])
    keyboard.append([InlineKeyboardButton("📊 Statistics", callback_data="stats")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode='Markdown')

async def generate_key_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generate key command"""
    user_id = update.effective_user.id
    username = update.effective_user.first_name
    is_admin = user_id in ADMIN_USER_IDS
    
    if not is_admin and not bot_settings["public_generation"]:
        await update.message.reply_text("❌ Key generation is restricted to admin only.")
        return
    
    processing_msg = await update.message.reply_text("⏳ Generating key...")
    
    key = generate_key()
    timestamp = datetime.now().isoformat()
    
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
        'generatedAt': timestamp,
        'used': False,
        'deviceId': None,
        'usedAt': None,
        'expiresAt': None
    }
    
    response_text = f"""
✅ **New Key Generated!**

🔑 Key: `{key}`

⏰ Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
👤 By: {username}

📝 **Instructions:**
1. Tap to copy the key above
2. Open the website
3. Paste and verify

⚠️ One-time use only! 24-hour access.
"""
    
    await processing_msg.edit_text(response_text, parse_mode='Markdown')

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button callbacks"""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    username = update.effective_user.first_name
    is_admin = user_id in ADMIN_USER_IDS
    
    if query.data == "generate_key":
        if not is_admin and not bot_settings["public_generation"]:
            await query.edit_message_text("❌ Admin only.")
            return
        
        await query.edit_message_text("⏳ Generating...")
        
        key = generate_key()
        timestamp = datetime.now().isoformat()
        
        generated_keys[key] = {"generated_by": user_id, "generated_at": timestamp, "used": False}
        
        key_hash = hash_key(key)
        keys[key_hash] = {
            'key': key,
            'generatedBy': f"{username} ({user_id})",
            'generatedAt': timestamp,
            'used': False,
            'deviceId': None,
            'usedAt': None,
            'expiresAt': None
        }
        
        response_text = f"""
✅ **Key Generated!**

🔑 `{key}`

⏰ {datetime.now().strftime('%H:%M:%S')}

Tap to copy, paste on website!
"""
        
        keyboard = [
            [InlineKeyboardButton("🔄 Generate Another", callback_data="generate_key")],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(response_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    elif query.data == "settings":
        if not is_admin:
            await query.edit_message_text("❌ Admin only.")
            return
        
        keyboard = [
            [InlineKeyboardButton(
                f"{'🔓 Disable' if bot_settings['public_generation'] else '🔒 Enable'} Public",
                callback_data="toggle_public"
            )],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        settings_text = f"""
⚙️ **Settings**

Public Generation: {'✅ ON' if bot_settings['public_generation'] else '❌ OFF'}
"""
        await query.edit_message_text(settings_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    elif query.data == "toggle_public":
        if not is_admin:
            await query.answer("❌ Admin only", show_alert=True)
            return
        
        bot_settings["public_generation"] = not bot_settings["public_generation"]
        
        keyboard = [
            [InlineKeyboardButton(
                f"{'🔓 Disable' if bot_settings['public_generation'] else '🔒 Enable'} Public",
                callback_data="toggle_public"
            )],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"⚙️ **Settings**\n\nPublic: {'✅ ON' if bot_settings['public_generation'] else '❌ OFF'}",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    elif query.data == "stats":
        cleanup_expired()
        total = len(generated_keys)
        used = sum(1 for k in generated_keys.values() if k["used"])
        
        stats_text = f"""
📊 **Statistics**

📈 Generated: {total}
✅ Used: {used}
🔓 Active: {total - used}
🌐 Devices: {len(device_locks)}

⏰ {datetime.now().strftime('%H:%M:%S')}
"""
        
        keyboard = [
            [InlineKeyboardButton("🔄 Refresh", callback_data="stats")],
            [InlineKeyboardButton("🔙 Back", callback_data="back_to_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(stats_text, reply_markup=reply_markup, parse_mode='Markdown')
    
    elif query.data == "back_to_main":
        keyboard = []
        if is_admin or bot_settings["public_generation"]:
            keyboard.append([InlineKeyboardButton("🔑 Generate Key", callback_data="generate_key")])
        if is_admin:
            keyboard.append([InlineKeyboardButton("⚙️ Settings", callback_data="settings")])
        keyboard.append([InlineKeyboardButton("📊 Statistics", callback_data="stats")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("🔐 **Main Menu**\n\nChoose an option:", reply_markup=reply_markup, parse_mode='Markdown')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command"""
    await update.message.reply_text(
        "📖 **Help**\n\n"
        "1. Generate key\n"
        "2. Copy it\n"
        "3. Paste on website\n"
        "4. Get 24h access!\n\n"
        "⚠️ One-time use per key",
        parse_mode='Markdown'
    )

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Stats command"""
    cleanup_expired()
    total = len(generated_keys)
    used = sum(1 for k in generated_keys.values() if k["used"])
    
    await update.message.reply_text(
        f"📊 **Stats**\n\n"
        f"Generated: {total}\n"
        f"Used: {used}\n"
        f"Active: {total - used}\n"
        f"Devices: {len(device_locks)}",
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
    
    telegram_app.add_handler(CommandHandler("start", start))
    telegram_app.add_handler(CommandHandler("generate", generate_key_command))
    telegram_app.add_handler(CommandHandler("help", help_command))
    telegram_app.add_handler(CommandHandler("stats", stats_command))
    telegram_app.add_handler(CallbackQueryHandler(button_handler))
    
    print("🤖 Telegram bot starting...")
    await telegram_app.initialize()
    await telegram_app.start()
    await telegram_app.updater.start_polling()
    
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
    print("\n" + "="*50)
    print("🚀 Starting Combined Server")
    print("="*50)
    print(f"📡 Port: {PORT}")
    print(f"👥 Admin IDs: {ADMIN_USER_IDS}")
    print(f"🤖 Bot Token: {'✅ Set' if BOT_TOKEN != 'YOUR_BOT_TOKEN_HERE' else '❌ Not set'}")
    print("="*50 + "\n")
    
    # Start Telegram bot in separate thread
    bot_thread = Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    # Start Flask server
    print("🌐 Starting web server...")
    app.run(host='0.0.0.0', port=PORT, debug=False)

import logging
import os
import re
import sqlite3
import time
from datetime import datetime
from dotenv import load_dotenv
from telegram import (
    ReplyKeyboardMarkup,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    Update,
    Bot,
)
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    CallbackQueryHandler,
    filters,
)
import db

# ---------------- Config ----------------
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID", "0"))
XRAY_LOG = os.getenv("XRAY_ACCESS_LOG")
CARD_INFO = os.getenv("CARD_INFO", "xxxx-xxxx-xxxx-xxxx")
XUI_DB_PATH = os.getenv("XUI_DB_PATH")
CHANNEL_USERNAME = os.getenv("CHANNEL_USERNAME")

# تنظیمات لاگ
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    # level=logging.DEBUG
)
logger = logging.getLogger(__name__)

# تنظیمات هشدار خودکار
LOW_GB_THRESHOLD = 1.0              # اگر کمتر از ۱ گیگ بود هشدار بده
EXPIRY_THRESHOLD_DAYS = 3           # اگر کمتر از ۳ روز تا انقضا بود هشدار بده
CONCURRENCY_WINDOW_SECS = 120   # فقط IPهایی که در 2 دقیقه اخیر دیده شده‌اند
HANDOFF_GRACE_SECS = 45         # مهلت کوتاه برای سوییچ WiFi↔️Data


# متغیرهای جهانی
last_low_gb_warn_by_uuid = {}
last_expiry_warn_by_uuid = {}
last_log_pos = 0

INTERVAL_SECONDS = 180          # جاب هر 3 دقیقه یک‌بار
MAX_BYTES_PER_TICK = 512_000    # حداکثر 512KB در هر بار خواندن لاگ
RECENT_WINDOW_SECS = 10 * 60   # فقط اتصالات 10 دقیقه اخیر را حساب کن
recent_seen = {}  # { email -> { ip -> {"first": ts, "last": ts, "count": n} } }
last_ip_warn_by_email = {}     # { email -> last_warn_ts } برای جلوگیری از اسپم
WARN_COOLDOWN_SECS = 6 * 3600
CONCURRENCY_WINDOW_SECS = max(2 * INTERVAL_SECONDS, 300)  # >= 5min

# اطمینان: پنجره پاکسازی از همزمانی بزرگ‌تر باشد
if RECENT_WINDOW_SECS < CONCURRENCY_WINDOW_SECS + 120:
    RECENT_WINDOW_SECS = CONCURRENCY_WINDOW_SECS + 120


EMAIL_RE = re.compile(r'email:\s*([^\s]+)')
SRC_RE = re.compile(r'from\s+(?:tcp:)?(\[?[0-9A-Fa-f:.]+\]?)(?::\d+)')

def _extract_email(line: str) -> str | None:
    m = EMAIL_RE.search(line)
    return m.group(1) if m else None

def _extract_src_ip(line: str) -> str | None:
    m = SRC_RE.search(line)
    if not m:
        return None
    ip = m.group(1)
    # اگر با براکت بود [2001:db8::1] -> 2001:db8::1
    if ip.startswith('[') and ip.endswith(']'):
        ip = ip[1:-1]
    return ip


# لینک‌های دانلود
DOWNLOAD_LINKS = {
    "آیفون": "https://apps.apple.com/tr/app/streisand/id6450534064",
    "اندروید": "https://play.google.com/store/apps/details?id=com.v2raytun.android&pcampaignid=web_share",
    "ویندوز": "لینک در دسترس نمیباشد",
    "مک‌بوک": "https://apps.apple.com/us/app/fair-vpn/id1533873488"
}

# پیام‌های ثابت
MESSAGES = {
    "not_member": "⚠️ کاربر گرامی؛ شما عضو چنل ما نیستید\n"
            "از طریق دکمه زیر وارد کانال شده و عضو شوید\n"
            "پس از عضویت دکمه «✅ بررسی عضویت» را بزنید",
    "join_prompt": "⚠️ هنوز عضو کانال نشده‌اید.\nلطفاً ابتدا عضو شوید و سپس روی «✅ بررسی عضویت» بزنید.",
    "membership_verified": "✅ عضویت شما تایید شد. حالا می‌توانید از ربات استفاده کنید.",
    "no_subscriptions": "❌ شما هیچ سرویسی برای تمدید ندارید.",
    "send_payment": "لطفاً عکس فیش واریزی را ارسال کنید تا درخواست تمدید سرویس بررسی شود.",
    "payment_sent": "✅ فیش واریزی برای تمدید سرویس ارسال شد. لطفاً منتظر تأیید ادمین باشید.",
    "payment_error": "❌ خطا در ارسال فیش. لطفاً دوباره تلاش کنید.",
    "invalid_state": "لطفاً ابتدا گزینه‌ای از منو (مثل خرید اکانت یا تمدید سرویس) انتخاب کنید.",
    "main_menu": "منوی اصلی 👇",
    "no_account": "📌 شما هنوز در سیستم ثبت نشده‌اید.",
}

# ---------------- UI ----------------
main_menu = ReplyKeyboardMarkup(
    [["🛒 خرید اکانت"], ["🕒 تمدید سرویس", "👤 گزارش اکانت من"], ["☎️ پشتیبانی", "📖 راهنما"], ["📱 دانلود اپ"]],
    resize_keyboard=True
)

download_app_menu = ReplyKeyboardMarkup(
    [["🍎 آیفون", "🤖 اندروید"], ["🖥️ ویندوز", "💻 مک‌بوک"], ["⬅️ بازگشت"]],
    resize_keyboard=True
)

def join_keyboard() -> InlineKeyboardMarkup:
    """دکمه‌های عضویت در کانال"""
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("📢 کانال اطلاع‌رسانی", url=f"https://t.me/{CHANNEL_USERNAME.lstrip('@')}")],
            [InlineKeyboardButton("✅ بررسی عضویت", callback_data="check_membership")],
        ]
    )

user_subscription_choice = {}


# ---------------- Utility Functions ----------------
async def send_to_admin(context: ContextTypes.DEFAULT_TYPE, message: str):
    """ارسال پیام به ادمین"""
    if ADMIN_CHAT_ID:
        try:
            await context.bot.send_message(ADMIN_CHAT_ID, message)

        except Exception as e:
            logger.error(f"Failed to send message to admin: {e}")

async def delete_previous_message(query):
    """حذف پیام قبلی برای UI تمیز"""
    try:
        if query.message:
            await query.message.delete()

    except:
        pass


# ---------------- Membership Check ----------------
async def check_channel_membership(bot: Bot, user_id: int) -> bool:
    """بررسی عضویت کاربر در کانال"""
    try:
        member = await bot.get_chat_member(CHANNEL_USERNAME, user_id)
        return member.status in ("member", "administrator", "creator")
    except Exception as e:
        logger.warning(f"Membership check failed for {user_id}: {e}")
        return False

# ---------------- Handlers ----------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """فرمان شروع ربات"""
    user = update.effective_user
    is_member = await check_channel_membership(context.bot, user.id)
    if not is_member:
        await update.message.reply_text(MESSAGES["not_member"].format(CHANNEL=CHANNEL_USERNAME), reply_markup=join_keyboard())
        return
    db.add_or_update_user(user.id, user.username or "", user.full_name or "")
    db.update_last_seen(user.id)
    await update.message.reply_text("به ربات Freeline خوش آمدید ✨", reply_markup=main_menu)

async def notify_admin_user_active(context: ContextTypes.DEFAULT_TYPE, tg_id: int, fullname: str, username: str):
    """ارسال اعلان فعالیت کاربر به ادمین + ثبت آخرین اعلان برای جلوگیری از تکرار فوری"""
    await send_to_admin(
        context,
        f"🟩 کاربر جدید وارد شد\n👤 نام: {fullname}\n🌐 یوزرنیم: @{username}\n🌐 آی‌دی: {tg_id}\n"
    )
    # ثبت آخرین اعلان تا متن‌های بعدی (مثل «⬅️ بازگشت») دوباره اعلان ندهند
    db.update_last_notification(tg_id, int(time.time()))

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """مدیریت دکمه‌های inline"""
    query = update.callback_query
    user = query.from_user
    await query.answer()


    if query.data == "check_membership":
        await delete_previous_message(query)
        is_member = await check_channel_membership(context.bot, user.id)
        if is_member:
            await notify_admin_user_active(context, user.id, user.full_name or "", user.username or "ندارد")
            await context.bot.send_message(user.id, MESSAGES["membership_verified"], reply_markup=main_menu)

        else:
            await context.bot.send_message(user.id, MESSAGES["join_prompt"], reply_markup=join_keyboard())

        return

    if query.data == "back_to_main":
        context.user_data["awaiting_payment"] = False
        context.user_data.pop("renew_uuid", None)
        user_subscription_choice.pop(user.id, None)
        await delete_previous_message(query)
        await context.bot.send_message(user.id, MESSAGES["main_menu"], reply_markup=main_menu)

        return

    if query.data.startswith("renew:"):
        uuid = query.data[len("renew:"):]
        context.user_data["renew_uuid"] = uuid
        context.user_data["awaiting_payment"] = True
        await delete_previous_message(query)
        await context.bot.send_message(
            user.id, MESSAGES["send_payment"],
            reply_markup=ReplyKeyboardMarkup([["⬅️ بازگشت"]], resize_keyboard=True)
        )

        return

    logger.warning(f"Unhandled callback data: {query.data} for user {user.id}")

async def app_download(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """نمایش منوی دانلود اپ"""
    await update.message.reply_text("لطفا نوع دستگاه خود را انتخاب کنید:", reply_markup=download_app_menu)

async def buy_account(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """نمایش منوی انتخاب نوع اکانت"""
    keyboard = ReplyKeyboardMarkup([["🔑 دو کاربره", "🔑 تک کاربره"], ["⬅️ بازگشت"]], resize_keyboard=True)
    await update.message.reply_text("لطفا نوع اکانت را انتخاب کنید:", reply_markup=keyboard)

async def buy_account_one_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """نمایش منوی اکانت تک کاربره"""
    keyboard = ReplyKeyboardMarkup(
        [
            ["تک کاربره ۲۰ گیگ : ۷۰.۰۰۰ تومان", "تک کاربره ۱۰ گیگ : ۵۰.۰۰۰ تومان"],
            ["تک کاربره ۱۰۰ گیگ : ۱۵۰.۰۰۰ تومان", "تک کاربره ۵۰ گیگ : ۱۰۰.۰۰۰ تومان"],
            ["تک کاربره نامحدود گیگ : ۲۰۰.۰۰۰ تومان"], ["⬅️ بازگشت"]
        ], resize_keyboard=True
    )
    await update.message.reply_text("لطفا حجم اکانت را انتخاب کنید:", reply_markup=keyboard)

async def buy_account_two_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """نمایش منوی اکانت دو کاربره"""
    keyboard = ReplyKeyboardMarkup(
        [
            ["دو کاربره ۵۰ گیگ : ۱۲۰.۰۰۰ تومان", "دو کاربره ۲۰ گیگ : ۱۰۰.۰۰۰ تومان"],
            ["دو کاربره ۱۰۰ گیگ : ۲۰۰.۰۰۰ تومان"],
            ["دو کاربره نامحدود گیگ : ۲۰۰.۰۰۰ تومان"], ["⬅️ بازگشت"]
        ], resize_keyboard=True
    )
    await update.message.reply_text("لطفا حجم اکانت را انتخاب کنید:", reply_markup=keyboard)

async def handle_subscription_selection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """مدیریت انتخاب اشتراک"""
    text = update.message.text
    if "گیگ" in text or "نامحدود" in text:
        user_subscription_choice[update.effective_user.id] = text
        await update.message.reply_text(
            f"انتخاب شما: {text}\n\nلطفا مبلغ اشتراک را به شماره کارت\n{CARD_INFO}\nو عکس فیش واریزی را ارسال کنید."
        )
        return

async def photo_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    fullname = update.effective_user.full_name
    username = update.effective_user.username or "ندارد"

    # حالت خرید اکانت
    if user_id in user_subscription_choice:
        option_selected = user_subscription_choice[user_id]
        if ADMIN_CHAT_ID:
            await context.bot.send_photo(
                chat_id=ADMIN_CHAT_ID,
                photo=update.message.photo[-1].file_id,
                caption=f"نام: {fullname}\nیوزر تلگرام: @{username}\nآی‌دی تلگرام: {user_id}\nیک اشتراک ({option_selected}) خریداری کرد."
            )
        await update.message.reply_text("✅ عکس فیش شما دریافت شد و به ادمین ارسال شد. متشکریم!")
        user_subscription_choice.pop(user_id, None)
        return

    # حالت تمدید سرویس
    if context.user_data.get("renew_uuid"):
        uuid = context.user_data["renew_uuid"]
        if ADMIN_CHAT_ID:
            await context.bot.send_photo(
                chat_id=ADMIN_CHAT_ID,
                photo=update.message.photo[-1].file_id,
                caption=f"📸 فیش واریزی برای تمدید سرویس\nنام:  {fullname} \nیوزر تلگرام: @{username}\nآی‌دی: {user_id}\nاکانت: {uuid}"

            )
        await update.message.reply_text("✅ فیش واریزی برای تمدید سرویس دریافت شد و به ادمین ارسال شد. متشکریم!")
        context.user_data.pop("renew_uuid", None)
        context.user_data["awaiting_payment"] = False
        return

    await update.message.reply_text("لطفاً ابتدا نوع اشتراک یا سرویس را انتخاب کنید.")

async def renew_service(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """نمایش لیست سرویس‌ها برای تمدید"""
    tg_id = update.effective_user.id
    is_member = await check_channel_membership(context.bot, tg_id)
    if not is_member:
        await update.message.reply_text(MESSAGES["not_member"].format(CHANNEL=CHANNEL_USERNAME), reply_markup=join_keyboard())
        return

    uuids = db.get_user_subscriptions(tg_id)
    if not uuids:
        await update.message.reply_text(MESSAGES["no_subscriptions"], reply_markup=main_menu)
        return

    buttons = []
    for uuid in uuids:
        info = get_xui_user_info(uuid)
        if info:
            short_uuid = uuid[:15] + "..." if len(uuid) > 15 else uuid
            status = "فعال" if info["enable"] == 1 else "غیرفعال"
            buttons.append([InlineKeyboardButton(f"{short_uuid} ({status})", callback_data=f"renew:{uuid}")])
    buttons.append([InlineKeyboardButton("⬅️ بازگشت", callback_data="back_to_main")])
    keyboard = InlineKeyboardMarkup(buttons)
    await update.message.reply_text("لطفاً سرویسی که می‌خواهید تمدید کنید را انتخاب کنید:", reply_markup=keyboard)

def get_xui_user_info(uuid):
    try:
        with sqlite3.connect(XUI_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT enable, email, up, down, expiry_time, total FROM client_traffics WHERE email = ?",
                (uuid,)
            )
            row = cursor.fetchone()
            if not row:
                logger.warning(f"No data found for UUID {uuid}")
                return None
            enable, email, up, down, expiry_time, total = row
            used = (up + down) / (1024**3)
            total_gb = total // (1024**3) if total > 0 else 0
            remain = total_gb - used if total_gb > 0 else "نامحدود"
            expiry_ts_sec = expiry_time / 1000 if expiry_time and expiry_time > 0 else None
            if expiry_ts_sec:
                days_remaining = (datetime.fromtimestamp(expiry_ts_sec) - datetime.now()).days
            return {
                "uuid": uuid,
                "total": total_gb,
                "used": used,
                "remain": remain,
                "expire": days_remaining if expiry_ts_sec else -1,
                "enable": enable,
                "expiry_ts": expiry_ts_sec
            }
    except Exception as e:
        logger.error(f"Failed to fetch XUI user info for UUID {uuid}: {e}")
        return None


async def account_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """نمایش گزارش اکانت‌های کاربر"""
    tg_id = update.effective_user.id
    uuids = db.get_user_subscriptions(tg_id)
    if not uuids:
        await update.message.reply_text(MESSAGES["no_account"], reply_markup=main_menu)
        return
    messages = []
    for uuid in uuids:
        info = get_xui_user_info(uuid)
        if not info:
            messages.append(f"❌ اطلاعاتی برای UUID `{uuid}` پیدا نشد.")
            continue
        remain_text = info['remain'] if isinstance(info['remain'], str) else f"{info['remain']:.2f} گیگ"
        expiry_text = (f"⏳ تاریخ انقضا: {info['expire']} روز مانده" if info['expire'] > 0 else
                      "⏳ اکانت منقضی شده است." if info['expiry_ts'] else "⏳ تاریخ انقضا: نامشخص")
        messages.append(
            f"🔑 اکانت: `{info['uuid']}`\n"
            f"{'🟢' if info['enable'] == 1 else '🔴'} وضعیت: {'فعال' if info['enable'] == 1 else 'غیرفعال'}\n"
            f"📊 حجم کل: {info['total'] if info['total'] else 'نامحدود'} {'گیگ' if info['total'] else ''}\n"
            f"📉 مصرف شده: {info['used']:.2f} گیگ\n"
            f"📈 باقی‌مانده: {remain_text}\n"
            f"{expiry_text}\n"
        )
    await update.message.reply_text("\n\n".join(messages), parse_mode="Markdown")

async def support(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """فعال کردن حالت پشتیبانی"""
    await update.message.reply_text("📩 لطفا پیام خود را ارسال کنید. ادمین پاسخ خواهد داد.")
    context.user_data["support"] = True

async def reply_to_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """پاسخ ادمین به کاربر"""
    if update.effective_user.id != ADMIN_CHAT_ID:
        return
    if len(context.args) < 2:
        await update.message.reply_text("فرمت: /reply user_id متن پیام")
        return
    user_id = int(context.args[0])
    text = " ".join(context.args[1:])
    await context.bot.send_message(user_id, f"📩 پاسخ پشتیبانی:\n{text}")
    await update.message.reply_text("✅ پیام شما ارسال شد.")

async def link_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """لینک کردن اکانت به کاربر"""
    if update.effective_user.id != ADMIN_CHAT_ID:
        await update.message.reply_text("⛔️ فقط ادمین می‌تواند این دستور را اجرا کند.")
        return
    if len(context.args) < 3:
        await update.message.reply_text("فرمت درست: /link <telegram_id> <uuid> <allow_ip>")
        return
    tg_id = int(context.args[0])
    uuid = context.args[1]
    allow_ip = int(context.args[2])
    db.link_subscription(tg_id, uuid, allow_ip)
    await update.message.reply_text(f"✅ اکانت {uuid} برای کاربر {tg_id} با حداکثر IP {allow_ip} ثبت شد.")

async def unlink_account(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """حذف اکانت از کاربر"""
    if update.effective_user.id != ADMIN_CHAT_ID:
        await update.message.reply_text("❌ شما دسترسی لازم را ندارید.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("فرمت صحیح: /unlink <telegram_id> <xui_email>")
        return
    tg_id = int(context.args[0])
    xui_email = context.args[1]
    db.remove_subscription(tg_id, xui_email)
    await update.message.reply_text(f"✅ اکانت `{xui_email}` از کاربر `{tg_id}` حذف شد.")

async def send_connection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """ارسال لینک اتصال به کاربر"""
    if update.effective_user.id != ADMIN_CHAT_ID:
        return
    if len(context.args) < 2:
        await update.message.reply_text("فرمت: /connection user_id لینک کانکشن")
        return
    user_id = int(context.args[0])
    text = " ".join(context.args[1:])
    await context.bot.send_message(user_id, f"{text}")
    await update.message.reply_text("✅ لینک ارسال شد.")

async def check_log():
    global last_log_pos, recent_seen, last_ip_warn_by_email

    now = time.time()

    # فایل ممکن است rotate/truncate شده باشد؛ اگر کوچکتر از last_log_pos شد، از 0 شروع کن
    try:
        st = os.stat(XRAY_LOG)
        if last_log_pos > st.st_size:
            last_log_pos = 0
        # اگر اصلاً بزرگ‌تر نشده، هیچ کاری نکن (I/O صفر)
        if st.st_size == last_log_pos:
            return []
    except FileNotFoundError as e:
        logger.error(f"Xray log file not found: {e}")
        return []

    try:
        with open(XRAY_LOG, "rb") as f:
            f.seek(last_log_pos)
            to_read = min(MAX_BYTES_PER_TICK, st.st_size - last_log_pos)
            chunk = f.read(to_read)

        if not chunk:
            return []

        cut = chunk.rfind(b"\n")
        if cut == -1:
            return []

        process = chunk[:cut + 1]
        last_log_pos += cut + 1

        try:
            lines = process.decode("utf-8", errors="ignore").splitlines()
        except Exception:
            lines = process.decode(errors="ignore").splitlines()

    except Exception as e:
        logger.error(f"Failed reading XRAY_LOG: {e}")
        return []

    for line in lines:
        email = _extract_email(line)
        src_ip = _extract_src_ip(line)
        if not email or not src_ip:
            continue
        bucket = recent_seen.setdefault(email, {})
        meta = bucket.get(src_ip)
        if meta:
            meta["last"] = now
            meta["count"] += 1
        else:
            bucket[src_ip] = {"first": now, "last": now, "count": 1}

    # پاکسازی IPهایی که از پنجره زمانی بیرون افتاده‌اند
    cutoff = now - RECENT_WINDOW_SECS
    for email, ip_map in list(recent_seen.items()):
        for ip, meta in list(ip_map.items()):
            if meta["last"] < cutoff:
                del ip_map[ip]

        if not ip_map:
            del recent_seen[email]

    # بررسی نقض حد مجاز با درنظر گرفتن همزمانی واقعی و grace سوییچ
    alerts = []
    users = db.get_all_users()  # انتظار: [(tg_id, email_or_uuid, user_allow), ...]
    for tg_id, email_or_uuid, user_allow in users:
        email = email_or_uuid  # مطمئن شو کلید DB همانی‌ست که تو لاگ بعد از email: می‌آید
        ip_map = recent_seen.get(email, {})

        # فقط IPهایی که در بازه‌ی خیلی کوتاه اخیر دیده شده‌اند را «همزمان فعال» حساب کن
        active_now = [ip for ip, meta in ip_map.items() if now - meta["last"] <= CONCURRENCY_WINDOW_SECS]

        logger.debug("ip-check %s active_now=%d ips=%s", email, len(active_now), sorted(active_now))
        if len(active_now) > user_allow:
            # فقط اگر دقیقاً یک IP اضافه داریم، چند ثانیه‌ی اول را به‌عنوان سوییچ نادیده بگیر
            if len(active_now) == user_allow + 1:
                newest_first = max(ip_map[ip]["first"] for ip in active_now)
                if (now - newest_first) <= HANDOFF_GRACE_SECS:
                    continue  # احتمالاً سوییچ لحظه‌ای Wi-Fi↔︎Data

            last_warn = last_ip_warn_by_email.get(email, 0)
            if now - last_warn >= WARN_COOLDOWN_SECS:
                alerts.append((
                    tg_id,
                    "⚠️ اتصال بیش از حد مجاز شناسایی شد.\n"
                    "لطفاً فقط با تعداد دستگاه‌های مجاز متصل شوید.\n"
                    "در صورت تکرار سرویس شما به‌صورت خودکار محدود خواهد شد."
                ))
                if ADMIN_CHAT_ID:
                    msg = (
                        f"⚠️ هشدار!\n"
                        f"اکانت: {email}\n"
                        f"حدمجاز: {user_allow} | فعلی: {len(active_now)}\n"
                        f"آی‌پی‌ها (در {CONCURRENCY_WINDOW_SECS // 60} دقیقه اخیر): {', '.join(sorted(active_now))}\n"
                        f"👤 ای‌دی تلگرام: {tg_id}"
                    )
                    alerts.append((ADMIN_CHAT_ID, msg))
                last_ip_warn_by_email[email] = now

    return alerts


async def check_log_job(context: ContextTypes.DEFAULT_TYPE):
    """چک کردن دوره‌ای لاگ Xray"""
    alerts = await check_log()
    for chat_id, msg in alerts:
        try:
            await context.bot.send_message(chat_id, msg)
        except Exception as e:
            logger.warning(f"check_log_job: could not send to {chat_id}: {e}")

async def scheduled_auto_check(context: ContextTypes.DEFAULT_TYPE):
    """چک کردن دوره‌ای برای هشدار حجم و انقضا"""
    now = time.time()
    users = db.get_all_users()
    with sqlite3.connect(XUI_DB_PATH) as conn:
        for tg_id, uuid, _ in users:
            cursor = conn.cursor()
            cursor.execute("SELECT enable, email, up, down, expiry_time, total FROM client_traffics WHERE email = ?", (uuid,))
            row = cursor.fetchone()
            if not row or row[0] != 1:  # فقط اکانت‌های فعال
                continue
            _, _, up, down, expiry_time, total = row
            used = (up + down) / (1024**3)
            total_gb = total // (1024**3) if total > 0 else 0
            remain = total_gb - used if total_gb > 0 else "نامحدود"
            expiry_ts = expiry_time / 1000 if expiry_time and expiry_time > 0 else None

            if isinstance(remain, float) and remain < LOW_GB_THRESHOLD:
                last = last_low_gb_warn_by_uuid.get(uuid)
                if last is None or (now - last >= WARN_COOLDOWN_SECS):
                    await context.bot.send_message(
                        tg_id,
                        f"⚠️ هشدار: حجم باقی‌مانده اکانت `{uuid}` کمتر از {LOW_GB_THRESHOLD:.0f} گیگ است. لطفا تمدید کنید.",
                        parse_mode="Markdown"
                    )
                    last_low_gb_warn_by_uuid[uuid] = now

            if expiry_ts and (expiry_ts - now < EXPIRY_THRESHOLD_DAYS * 24 * 3600):
                last = last_expiry_warn_by_uuid.get(uuid)
                if last is None or (now - last >= WARN_COOLDOWN_SECS):
                    await context.bot.send_message(
                        tg_id,
                        f"⚠️ هشدار: اکانت `{uuid}` کمتر از {EXPIRY_THRESHOLD_DAYS} روز دیگر اعتبار دارد. لطفا تمدید کنید.",
                        parse_mode="Markdown"
                    )
                    last_expiry_warn_by_uuid[uuid] = now

async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    tg_id = update.effective_user.id
    fullname = update.effective_user.full_name
    username = update.effective_user.username or "ندارد"

    # بررسی عضویت با یوزرنیم
    is_member = await check_channel_membership(context.bot, tg_id)
    if not is_member:
        # پیام دعوت + دکمه‌ها
        await update.message.reply_text("📢 برای استفاده از ربات باید ابتدا عضو کانال شوید:")
        await update.message.reply_text(f"{CHANNEL_USERNAME}", reply_markup=join_keyboard())
        return

    db.update_last_seen(tg_id)

    if context.user_data.get("support"):
        if ADMIN_CHAT_ID:
            await context.bot.send_message(
                ADMIN_CHAT_ID,
                f"📩 پیام پشتیبانی از {fullname} (@{username}):\n🆔 ID: {tg_id}\n\n{text}"
            )
        await update.message.reply_text("✅ پیام شما ارسال شد. منتظر پاسخ بمانید.")
        context.user_data["support"] = False
        return

    if text == "⬅️ بازگشت":
        await update.message.reply_text("منوی اصلی 👇", reply_markup=main_menu)
        return

    # بقیه کدهای text_handler بدون تغییر

    if text in ["🍎 آیفون", "🤖 اندروید", "🖥️ ویندوز", "💻 مک‌بوک"]:
        link = DOWNLOAD_LINKS.get(text.replace("🍎 ", "").replace("🤖 ", "").replace("🖥️ ", "").replace("💻 ", ""))
        await update.message.reply_text(f"لینک دانلود برای {text}:\n{link}", reply_markup=download_app_menu)
        return

async def help_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """نمایش پیام راهنما"""
    await update.message.reply_text("📖 راهنما:\nبرای آموزش اتصال، به کانال ما بپیوندید:\nhttps://t.me/vpnfreeline")

async def activity_ping(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """اعلان فعالیت کاربر به ادمین، حداکثر هر ۱ ساعت یک‌بار، برای همهٔ پیام‌ها."""
    user = update.effective_user
    if not user:
        return

    tg_id = user.id
    fullname = user.full_name or ""
    username = user.username or "ندارد"

    msg = update.message
    text = (msg.text if msg and msg.text else "").strip()

    NAV_TEXTS = {"⬅️ بازگشت"}

    # اگر پیام «بازگشت» است، اعلان نساز
    if text in NAV_TEXTS:
        return

    now_ts = int(time.time())
    last_notif = db.get_last_notification(tg_id)

    if not last_notif or (now_ts - last_notif) > 3600:
        if ADMIN_CHAT_ID:
            await context.bot.send_message(
                ADMIN_CHAT_ID,
                f"🟦 کاربر فعال شد\n👤 نام: {fullname}\n🌐 یوزرنیم: @{username}\n🌐 آی‌دی: {tg_id}\n"
            )
        db.update_last_notification(tg_id, now_ts)

async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE):
    """مدیریت خطاهای عمومی"""
    logger.exception("Unhandled exception while handling update: %s", context.error)


def main():
    """نقطه ورود اصلی"""
    db.init_db()

    # --- warm start برای لاگ ---
    global last_log_pos
    try:
        last_log_pos = os.stat(XRAY_LOG).st_size
    except Exception:
        last_log_pos = 0

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex("خرید اکانت"), buy_account))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex("دانلود اپ"), app_download))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex("^🔑 تک کاربره$"), buy_account_one_user))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex("^🔑 دو کاربره$"), buy_account_two_user))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(
        "تک کاربره ۱۰ گیگ : ۵۰.۰۰۰ تومان|تک کاربره ۲۰ گیگ : ۷۰.۰۰۰ تومان|تک کاربره ۵۰ گیگ : ۱۰۰.۰۰۰ تومان|تک کاربره ۱۰۰ گیگ : ۱۵۰.۰۰۰ تومان|تک کاربره نامحدود گیگ : ۲۰۰.۰۰۰ تومان"
    ), handle_subscription_selection))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex(
        "دو کاربره ۲۰ گیگ : ۱۰۰.۰۰۰ تومان|دو کاربره ۵۰ گیگ : ۱۲۰.۰۰۰ تومان|دو کاربره ۱۰۰ گیگ : ۲۰۰.۰۰۰ تومان|دو کاربره نامحدود گیگ : ۲۰۰.۰۰۰ تومان"
    ), handle_subscription_selection))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex("گزارش اکانت من"), account_report))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex("تمدید سرویس"), renew_service))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex("پشتیبانی"), support))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex("راهنما"), help_message))
    app.add_handler(MessageHandler(filters.PHOTO, photo_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))
    app.add_handler(CommandHandler("reply", reply_to_user))
    app.add_handler(CommandHandler("connection", send_connection))
    app.add_handler(CommandHandler("link", link_command))
    app.add_handler(CommandHandler("unlink", unlink_account))
    app.add_handler(MessageHandler(filters.ALL, activity_ping, block=False), group=100)

    app.add_error_handler(on_error)

    app.job_queue.run_repeating(check_log_job, interval=INTERVAL_SECONDS, first=5)
    app.job_queue.run_repeating(scheduled_auto_check, interval=3600, first=20)

    print("✅ Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()


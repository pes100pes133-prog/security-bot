import asyncio
import hashlib
import os
import re
import sqlite3
from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)
from aiohttp import web
from openai import AsyncOpenAI

# --- الإعدادات والمفاتيح الخاصة بك ---
BOT_TOKEN = os.getenv("BOT_TOKEN", "8996552347:AAES9VVyLCvigvYiqN2SZIGopwTAzbWr01Q")
ADMIN_ID = int(os.getenv("ADMIN_ID", "8789404984"))
NVIDIA_API_KEY = os.getenv(
    "NVIDIA_API_KEY",
    "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",
)
PORT = int(os.getenv("PORT", 8080))

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# عميل الذكاء الاصطناعي من NVIDIA NIM
ai_client = AsyncOpenAI(
    base_url="https://integrate.api.nvidia.com/v1", api_key=NVIDIA_API_KEY
)

# --- إعداد وتجهيز قاعدة البيانات SQLite ---
DB_FILE = "security_bot.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # جدول المستخدمين
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # جدول سجل الفحوصات
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            scan_type TEXT,
            target_data TEXT,
            threat_detected INTEGER,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


init_db()


def add_user(user_id: int, username: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT OR IGNORE INTO users (user_id, username) VALUES (?, ?)",
        (user_id, username),
    )
    conn.commit()
    conn.close()


def log_scan(user_id: int, scan_type: str, target: str, is_threat: bool):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (user_id, scan_type, target_data, threat_detected) VALUES (?, ?, ?, ?)",
        (user_id, scan_type, target, 1 if is_threat else 0),
    )
    conn.commit()
    conn.close()


# --- وظائف الذكاء الاصطناعي للأمان ---
async def analyze_with_ai(prompt: str) -> str:
    try:
        response = await ai_client.chat.completions.create(
            model="meta/llama-3.3-70b-instruct",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "أنت خبير أمني ومحلل سيبراني متخصص في كشف البرمجيات الخبيثة، صفحات التصيد (Phishing)، "
                        "والهندسة الاجتماعية. قم بتحليل المدخلات المرفقة تحليلاً دقيقاً واكتب تقريراً موجزاً باللغة العربية.\n"
                        "يجب أن يتضمن ردك:\n"
                        "1. درجة الخطورة (آمن / مشبوه / خطير جداً).\n"
                        "2. شرح للمخاطر المكتشفة أو المؤشرات المشبوهة إن وجدت.\n"
                        "3. توصية وقائية واضحة للمستخدم."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=600,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"تعذر استكمال تحليل الذكاء الاصطناعي حالياً: {str(e)}"


# --- أزرار التسويق والحماية ---
def get_security_markup():
    markup = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🛡️ تطبيق حماية موصى به",
                    url="https://www.malwarebytes.com",
                )
            ]
        ]
    )
    return markup


# --- أوامر المستخدم العادية ---
@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    user = message.from_user
    add_user(user.id, user.username or user.first_name)

    text = (
        f"مرحباً بك يا {user.first_name} في **بوت فحص الأمان الذكي** 🛡️\n\n"
        "وظائف البوت:\n"
        "🔍 **فحص الروابط:** أرسل أي رابط مشبوه لتحليله وكشف التصيد.\n"
        "📁 **فحص الملفات:** أرسل أي ملف أو تطبيق (APK, ZIP, EXE, PDF, إلخ) حتى 60MB.\n"
        "⚡ مدعوم بمحرك ذكاء اصطناعي متطور لكشف الثغرات والملفات الملغومة."
    )
    await message.answer(text, parse_mode="Markdown")


# --- معالجة الروابط والنصوص ---
@dp.message(F.text & ~F.text.startswith("/"))
async def handle_links(message: types.Message):
    user_id = message.from_user.id
    text = message.text.strip()
    url_pattern = r"(https?://[^\s]+)"
    urls = re.findall(url_pattern, text)

    if not urls:
        await message.answer("ℹ️ أرسل رابطاً صالحاً أو ملفاً للبدء بالفحص.")
        return

    target_url = urls[0]
    wait_msg = await message.answer(
        "⏳ **جاري فحص الرابط ومطابقة قواعد الأمان ومؤشرات التصيد...**",
        parse_mode="Markdown",
    )

    prompt = (
        f"قم بفحص هذا الرابط أمنياً: {target_url}\n"
        f"النص المرافق له: {text}\n"
        "تحقق من نطاق الرابط، التلاعب بالحروف (Typosquatting)، وطلب البيانات الحساسة."
    )
    analysis = await analyze_with_ai(prompt)

    is_threat = any(
        w in analysis
        for w in ["خطر", "مشبوه", "تصيد", "احتيال", "ملغوم", "Phishing"]
    )
    log_scan(user_id, "رابط", target_url[:100], is_threat)

    result_text = f"🌐 **تقرير فحص الرابط:**\n`{target_url}`\n\n{analysis}"
    reply_markup = get_security_markup() if is_threat else None

    await wait_msg.delete()
    await message.answer(
        result_text, reply_markup=reply_markup, parse_mode="Markdown"
    )


# --- معالجة الملفات والمستندات ---
@dp.message(F.document)
async def handle_document(message: types.Message):
    user_id = message.from_user.id
    doc = message.document
    file_name = doc.file_name or "ملف_بدون_اسم"
    file_size_mb = (doc.file_size or 0) / (1024 * 1024)
    file_ext = os.path.splitext(file_name)[1].lower() or "مجهول"

    if file_size_mb > 60:
        await message.answer(
            "⚠️ عذراً، حجم الملف يتجاوز 60 ميجابايت، وهو الحد الأقصى المسموح."
        )
        return

    wait_msg = await message.answer(
        f"⏳ **جاري فحص الملف:** `{file_name}` ({file_size_mb:.2f} MB)...",
        parse_mode="Markdown",
    )

    file_hash = "غير متوفر"
    header_info = "لم يتم تنزيل الملف بسبب حدود تيليجرام السحابية"

    # إذا كان الحجم ضمن حد تحميل تيليجرام الافتراضي (20MB) يتم تنزيله واستخراج الهاش
    if file_size_mb <= 20:
        try:
            file_info = await bot.get_file(doc.file_id)
            downloaded = await bot.download_file(file_info.file_path)
            content = downloaded.read()
            file_hash = hashlib.sha256(content).hexdigest()
            header_info = str(content[:128])  # قراءة أول بايتات
        except Exception as e:
            header_info = f"فشل تحميل بايتات الملف: {str(e)}"

    prompt = (
        f"قم بتحليل المخاطر الأمنية لهذا الملف:\n"
        f"- اسم الملف: {file_name}\n"
        f"- الامتداد: {file_ext}\n"
        f"- الحجم: {file_size_mb:.2f} MB\n"
        f"- SHA-256 Hash: {file_hash}\n"
        f"- ترويسة الملف (Header preview): {header_info}\n\n"
        "بيّن إمكانية احتوائه على تروجان، برمجية خبيثة، أو سلوك غير مصرح، مع نصائح التعامل معه."
    )

    analysis = await analyze_with_ai(prompt)
    is_threat = any(
        w in analysis for w in ["خطر", "مشبوه", "برمجية خبيثة", "Malware"]
    )
    log_scan(user_id, f"ملف ({file_ext})", file_name[:50], is_threat)

    result_text = (
        f"📁 **تقرير فحص الملف:**\n"
        f"📄 **الاسم:** `{file_name}`\n"
        f"⚖️ **الحجم:** `{file_size_mb:.2f} MB`\n"
        f"🔑 **SHA-256:** `{file_hash[:16]}...`\n\n"
        f"{analysis}"
    )

    reply_markup = get_security_markup() if is_threat else None
    await wait_msg.delete()
    await message.answer(
        result_text, reply_markup=reply_markup, parse_mode="Markdown"
    )


# --- لوحة تحكم الأدمن الخاصة بك ---
@dp.message(Command("admin"))
async def admin_panel(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return  # تجاهل إذا لم يكن المطور

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # عدد المستخدمين
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]

    # إجمالي الفحوصات
    c.execute("SELECT COUNT(*) FROM scans")
    total_scans = c.fetchone()[0]

    # عدد التهديدات المكتشفة
    c.execute("SELECT COUNT(*) FROM scans WHERE threat_detected = 1")
    total_threats = c.fetchone()[0]

    # الفحوصات حسب النوع
    c.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type")
    type_breakdown = c.fetchall()
    breakdown_text = "\n".join(
        [f"▫️ {row[0]}: {row[1]}" for row in type_breakdown]
    )

    conn.close()

    admin_text = (
        f"👑 **لوحة تحكم الأدمن المركزية**\n\n"
        f"👥 **إجمالي المستخدمين:** `{total_users}`\n"
        f"📊 **إجمالي الفحوصات:** `{total_scans}`\n"
        f"🚨 **التهديدات المكتشفة:** `{total_threats}`\n\n"
        f"📁 **تفاصيل نوع الفحوصات والملفات:**\n{breakdown_text if breakdown_text else 'لا توجد فحوصات حتى الآن'}"
    )

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🔄 تحديث الإحصائيات", callback_data="refresh_admin"
                )
            ]
        ]
    )
    await message.answer(admin_text, reply_markup=kb, parse_mode="Markdown")


@dp.callback_query(F.data == "refresh_admin")
async def cb_refresh_admin(query: CallbackQuery):
    if query.from_user.id != ADMIN_ID:
        await query.answer("غير مصرح لك!", show_alert=True)
        return
    await query.message.delete()
    await admin_panel(query.message)


# --- خادم ويب لمتطلبات Render للبقاء 24/7 ---
async def ping_server(request):
    return web.Response(text="Bot & Security AI is Active 24/7!")


async def main():
    app = web.Application()
    app.router.add_get("/", ping_server)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()

    print("🚀 البوت قيد التشغيل وتم تفعيل خادم Render بنجاح...")
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())

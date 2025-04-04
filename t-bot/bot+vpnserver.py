import os
import asyncio
import uuid
import logging
import sqlite3
import json
import paramiko
import time as time_module
import fcntl
from datetime import datetime, timedelta, time as datetime_time
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler
from telegram.error import Conflict
from yoomoney import Client, Quickpay
from dotenv import load_dotenv
from logging.handlers import RotatingFileHandler


# 1. Фильтр для логгера
class ErrorOnlyFilter(logging.Filter):
    """Фильтр, пропускающий только ошибки (ERROR и выше)"""

    def filter(self, record):
        return record.levelno >= logging.ERROR


# Загрузка переменных окружения
load_dotenv()

# Конфигурация
try:
    TOKEN = os.environ['TELEGRAM_BOT_TOKEN']
    YOOMONEY_ACCESS_TOKEN = os.environ['YOOMONEY_ACCESS_TOKEN']
    YOOMONEY_RECEIVER = os.environ['YOOMONEY_RECEIVER']
    ADMINS = json.loads(os.environ.get('ADMINS'))
    VPN_CONFIGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files/vpn_configs/')
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'payments.db')
    VPN_SERVER_IP = '192.168.2.30'
    SSH_USER = 'vpnbot'
    SSH_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ssh_keys/vpnbot_private_key')
    SSH_RETRIES = 3
    SSH_TIMEOUT = 30
except KeyError as key_err:
    logging.error(f"Отсутствует обязательная переменная окружения: {key_err}")
    exit(1)
except Exception as env_error:
    logging.error(f"Ошибка загрузки конфигурации: {env_error}")
    exit(1)

PRICES = {
    '1month': 2,
    '3months': 3,
    '6months': 1000,
    '1year': 1800
}
EXPIRATION_DAYS = {
    '1month': 30,
    '3months': 90,
    '6months': 180,
    '1year': 365
}
bot_active = True  # Глобальный статус бота

# Настройка логгера
log_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s\n'
    'Traceback (most recent call last):\n%(exc_text)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
error_handler = RotatingFileHandler(
    'bot.log',
    maxBytes=5 * 1024 * 1024,  # 5 MB
    backupCount=3,
    encoding='utf-8'
)
error_handler.setLevel(logging.ERROR)
error_handler.addFilter(ErrorOnlyFilter())
error_handler.setFormatter(log_formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
logger.addHandler(error_handler)


# Вспомогательные функции
def check_admin(user_id: int) -> bool:
    """Проверка прав администратора"""
    return user_id in ADMINS


async def log_action(action: str, user_id: int, details: str = ""):
    """Логирование действий"""
    logger.info(f"[{action}] User:{user_id} {details}")


def validate_username(username: str) -> bool:
    """Валидация имени пользователя"""
    if not username or len(username) > 32:
        return False
    return all(c.isalnum() or c in '_-' for c in username)


def init_db():
    """Инициализация базы данных"""
    try:
        # Сначала устанавливаем параметры PRAGMA без транзакции
        with sqlite3.connect(DB_PATH, timeout=20, isolation_level=None) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA synchronous=NORMAL")

        # Затем создаем таблицы внутри транзакции
        with sqlite3.connect(DB_PATH, timeout=20) as conn:
            conn.execute("BEGIN")
            try:
                # Создание таблиц и индексов
                conn.execute('''CREATE TABLE IF NOT EXISTS payments
                              (id INTEGER PRIMARY KEY AUTOINCREMENT,
                              user_id INT NOT NULL,
                              username TEXT,
                              label TEXT UNIQUE NOT NULL,
                              status TEXT NOT NULL DEFAULT 'pending',
                              sum REAL NOT NULL,
                              period TEXT NOT NULL,
                              timestamp DATETIME NOT NULL,
                              config_file TEXT)''')

                conn.execute('''CREATE TABLE IF NOT EXISTS issued_configs
                              (id INTEGER PRIMARY KEY AUTOINCREMENT,
                              user_id INT NOT NULL,
                              username TEXT,
                              config_file TEXT UNIQUE NOT NULL,
                              issue_date DATETIME NOT NULL,
                              expiry_date DATETIME NOT NULL)''')

                conn.execute('''CREATE INDEX IF NOT EXISTS idx_payments_user 
                              ON payments(user_id, status, timestamp)''')
                conn.execute('''CREATE INDEX IF NOT EXISTS idx_payments_label 
                              ON payments(label)''')
                conn.execute('''CREATE INDEX IF NOT EXISTS idx_configs_expiry 
                              ON issued_configs(expiry_date)''')
                conn.execute("COMMIT")
            except sqlite3.Error:  # Ловим только ошибки SQLite
                conn.execute("ROLLBACK")
                raise

    except sqlite3.Error as db_error:
        logger.exception("Ошибка при инициализации БД")
        raise

init_db()


def ssh_execute_command(command: str, retries: int = SSH_RETRIES) -> tuple:
    """Выполнение команды на сервере через SSH"""
    last_error = None
    for attempt in range(retries):
        try:
            with paramiko.SSHClient() as ssh:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    key = paramiko.Ed25519Key.from_private_key_file(SSH_KEY_PATH)
                except paramiko.ssh_exception.SSHException as e:
                    return None, f"Invalid SSH key: {str(e)}"

                ssh.connect(VPN_SERVER_IP, username=SSH_USER, pkey=key, timeout=SSH_TIMEOUT)
                stdin, stdout, stderr = ssh.exec_command(command, timeout=SSH_TIMEOUT)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()

                if error and "already exists" not in error:
                    raise paramiko.SSHException(f"SSH error: {error}")

                return output, None

        except paramiko.SSHException as e:  # Ловим только SSH ошибки
            last_error = str(e)
            logger.error(f"SSH attempt {attempt + 1} failed: {last_error}")
            if attempt < retries - 1:
                time_module.sleep(1)

    return None, f"SSH failed after {retries} attempts. Last error: {last_error}"

async def test_vpn_config(config_path: str) -> bool:
    """Проверка валидности конфигурационного файла"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()

        required_sections = ['<ca>', '<cert>', '<key>']
        if not all(section in content for section in required_sections):
            return False

        if 'remote ' not in content or 'client' not in content:
            return False

        return True
    except Exception:
        return False


async def generate_ovpn_config(username: str, period: str) -> str:
    """Генерация конфига OpenVPN на сервере"""
    max_attempts = 3
    attempt = 0

    while attempt < max_attempts:
        try:
            timestamp = int(time_module.time())
            ovpn_username = f"user_{username}_{timestamp}"

            # Очистка старых файлов
            cleanup_cmd = f"""
            sudo rm -f /etc/openvpn/easy-rsa/pki/reqs/{ovpn_username}.req && \
            sudo rm -f /etc/openvpn/easy-rsa/pki/issued/{ovpn_username}.crt && \
            sudo rm -f /etc/openvpn/easy-rsa/pki/private/{ovpn_username}.key
            """
            ssh_execute_command(cleanup_cmd)

            # Команда генерации сертификата
            cert_cmd = f"""
            cd /etc/openvpn/easy-rsa/ && \
            sudo ./easyrsa --batch build-client-full {ovpn_username} nopass && \
            sudo ./easyrsa gen-crl && \
            sudo cp /etc/openvpn/easy-rsa/pki/issued/{ovpn_username}.crt /tmp/ && \
            sudo cp /etc/openvpn/easy-rsa/pki/private/{ovpn_username}.key /tmp/ && \
            sudo cp /etc/openvpn/easy-rsa/pki/ca.crt /tmp/ && \
            sudo chown {SSH_USER}:{SSH_USER} /tmp/{ovpn_username}.crt /tmp/{ovpn_username}.key /tmp/ca.crt
            """

            output, cert_error = ssh_execute_command(cert_cmd)
            if cert_error:
                raise Exception(cert_error)

            # Получение сертификатов
            ca_cert, ca_error = ssh_execute_command("cat /tmp/ca.crt")
            if ca_error:
                raise Exception(f"Failed to get CA cert: {ca_error}")

            client_cert, cert_error = ssh_execute_command(f"cat /tmp/{ovpn_username}.crt")
            if cert_error:
                raise Exception(f"Failed to get client cert: {cert_error}")

            client_key, key_error = ssh_execute_command(f"cat /tmp/{ovpn_username}.key")
            if key_error:
                raise Exception(f"Failed to get client key: {key_error}")

            config_content = f"""client
dev tun
proto udp
remote {VPN_SERVER_IP} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
verb 3

<ca>
{ca_cert}
</ca>
<cert>
{client_cert}
</cert>
<key>
{client_key}
</key>
"""
            # Сохранение конфига
            config_file = f"FLY3-{ovpn_username}-{period}.ovpn"
            config_path = os.path.join(VPN_CONFIGS_DIR, config_file)

            os.makedirs(VPN_CONFIGS_DIR, exist_ok=True)
            with open(config_path, 'w', encoding='utf-8') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                f.write(config_content)
                fcntl.flock(f, fcntl.LOCK_UN)

            if await test_vpn_config(config_path):
                return config_file

        except Exception as e:
            logger.error(f"Attempt {attempt + 1} failed: {str(e)}")
            attempt += 1
            if attempt < max_attempts:
                await asyncio.sleep(1)

    raise ValueError(f"Не удалось сгенерировать конфиг после {max_attempts} попыток")


async def revoke_ovpn_config(username: str) -> bool:
    """Отзыв конфига на сервере"""
    await log_action("REVOKE_CONFIG", 0, f"Starting for {username}")
    try:
        command = f"cd /etc/openvpn/easy-rsa/ && ./easyrsa revoke {username} && ./easyrsa gen-crl"
        output, error = ssh_execute_command(command)
        if error:
            raise Exception(error)

        await log_action("REVOKE_CONFIG_SUCCESS", 0, f"Revoked for {username}")
        return True
    except Exception as e:
        await log_action("REVOKE_CONFIG_FAILED", 0, f"Error for {username}: {str(e)}")
        return False


async def create_payment(user_id: int, username: str, amount: float, period: str) -> tuple:
    """Создание платежа"""
    await log_action("CREATE_PAYMENT", user_id, f"Amount: {amount}, Period: {period}")
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            conn.execute("BEGIN")
            cursor = conn.cursor()

            try:
                cursor.execute("""
                    SELECT COUNT(*) FROM payments 
                    WHERE user_id = ? AND status = 'success' AND period = ?
                    AND timestamp > datetime('now', '-1 hour')
                """, (user_id, period))

                if cursor.fetchone()[0] > 0:
                    raise ValueError("Вы уже приобрели этот тариф недавно")

                cursor.execute("""
                    SELECT COUNT(*) FROM payments 
                    WHERE user_id = ? AND status = 'pending' 
                    AND timestamp > datetime('now', '-5 minutes')
                """, (user_id,))

                if cursor.fetchone()[0] > 0:
                    raise ValueError("У вас уже есть незавершенный платеж. Пожадитесь его обработки.")

                label = str(uuid.uuid4())
                quickpay = Quickpay(
                    receiver=YOOMONEY_RECEIVER,
                    quickpay_form="shop",
                    targets="VPN доступ",
                    paymentType="SB",
                    sum=amount,
                    label=label
                )

                conn.execute(
                    """INSERT INTO payments 
                    (user_id, username, label, status, sum, period, timestamp) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (user_id, username, label, 'pending', amount, period, datetime.now())
                )

                conn.execute("COMMIT")
                await log_action("CREATE_PAYMENT_SUCCESS", user_id, f"Label: {label}")
                return quickpay.redirected_url, label

            except Exception as e:
                conn.execute("ROLLBACK")
                raise
    except Exception as e:
        await log_action("CREATE_PAYMENT_FAILED", user_id, f"Error: {str(e)}")
        raise


async def issue_config_to_user(user_id: int, username: str, period: str) -> str:
    """Выдача конфига пользователю"""
    await log_action("ISSUE_CONFIG", user_id, f"Period: {period}")
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("BEGIN")
            cursor = conn.cursor()

            try:
                cursor.execute("""
                    SELECT COUNT(*) FROM issued_configs 
                    WHERE user_id = ? AND expiry_date > datetime('now')
                """, (user_id,))
                active_configs = cursor.fetchone()[0]

                if active_configs >= 3:
                    raise ValueError("У вас уже есть 3 активных конфигурации...")

                ovpn_username = f"user_{user_id}_{int(time_module.time())}"
                config_file = await generate_ovpn_config(ovpn_username, period)

                if not config_file:
                    raise ValueError("Не удалось сгенерировать конфигурационный файл")

                issue_date = datetime.now()
                expiry_date = issue_date + timedelta(days=EXPIRATION_DAYS[period])

                conn.execute(
                    """INSERT INTO issued_configs 
                    (user_id, username, config_file, issue_date, expiry_date) 
                    VALUES (?, ?, ?, ?, ?)""",
                    (user_id, username, config_file, issue_date, expiry_date)
                )

                conn.execute("COMMIT")
                await log_action("ISSUE_CONFIG_SUCCESS", user_id, f"Config: {config_file}")
                return config_file

            except Exception as e:
                conn.execute("ROLLBACK")
                raise
    except Exception as e:
        await log_action("ISSUE_CONFIG_FAILED", user_id, f"Error: {str(e)}")
        raise ValueError(f"Не удалось создать конфиг: {str(e)}")


async def cleanup_expired_configs(context: ContextTypes.DEFAULT_TYPE):
    """Очистка устаревших конфигов"""
    await log_action("CLEANUP", 0, "Starting cleanup")
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("BEGIN")
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            try:
                cursor.execute("""
                    SELECT config_file FROM issued_configs 
                    WHERE expiry_date <= datetime('now', 'utc')
                """)

                cleaned = 0
                for row in cursor.fetchall():
                    config_file = row['config_file']
                    username = config_file.split('-')[1]

                    if await revoke_ovpn_config(username):
                        config_path = os.path.join(VPN_CONFIGS_DIR, config_file)
                        if os.path.exists(config_path):
                            os.remove(config_path)

                        cursor.execute("""
                            DELETE FROM issued_configs 
                            WHERE config_file = ?
                        """, (config_file,))
                        cleaned += 1

                        logger.info(f"Удален просроченный конфиг: {config_file}")
                    else:
                        logger.error(f"Не удалось отозвать конфиг: {config_file}")

                conn.execute("COMMIT")
                await log_action("CLEANUP_COMPLETE", 0, f"Cleaned {cleaned} configs")

            except Exception as e:
                conn.execute("ROLLBACK")
                raise
    except Exception as e:
        await log_action("CLEANUP_FAILED", 0, f"Error: {str(e)}")
        logger.exception("Ошибка очистки конфигов")


async def check_payment_status(label: str) -> str:
    """Проверка статуса платежа"""
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            client = Client(YOOMONEY_ACCESS_TOKEN)
            history = client.operation_history(label=label)

            if not history.operations:
                await asyncio.sleep(10 * (attempt + 1))
                continue

            for operation in history.operations:
                if operation.status == 'success':
                    return 'success'
                elif operation.status == 'refused':
                    return 'refused'

            return 'pending'

        except (ConnectionError, TimeoutError) as e:  # Сетевые ошибки
            logger.error(f"Network error (attempt {attempt + 1}): {e}")
            if attempt == max_attempts - 1:
                return 'error'
            await asyncio.sleep(10)
        except Exception as e:  # Все остальные ошибки
            logger.error(f"Unexpected error (attempt {attempt + 1}): {e}")
            return 'error'

    return 'error'


async def check_payment_job(context: ContextTypes.DEFAULT_TYPE):
    """Фоновая проверка платежа"""
    job = context.job
    label = job.data['label']
    user_id = job.data['user_id']
    username = job.data['username']
    period = job.data['period']

    await log_action("CHECK_PAYMENT_JOB", user_id, f"Label: {label}")

    try:
        status = await check_payment_status(label)

        if status == 'success':
            conn = sqlite3.connect(DB_PATH, timeout=20)
            try:
                conn.execute("BEGIN")
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT config_file FROM payments WHERE label=? AND status='success'",
                    (label,)
                )
                result = cursor.fetchone()

                if result and result[0]:
                    config_file = result[0]
                else:
                    config_file = await generate_ovpn_config(f"user_{user_id}", period)
                    cursor.execute(
                        "UPDATE payments SET status=?, config_file=? WHERE label=?",
                        ('success', config_file, label)
                    )
                    conn.execute("COMMIT")

                config_path = os.path.join(VPN_CONFIGS_DIR, config_file)
                if os.path.exists(config_path):
                    with open(config_path, 'rb') as config_f:
                        await context.bot.send_document(
                            chat_id=job.data['chat_id'],
                            document=InputFile(config_f),
                            caption=f"Ваш конфигурационный файл: {config_file}"
                        )
                    await context.bot.edit_message_text(
                        chat_id=job.data['chat_id'],
                        message_id=job.data['message_id'],
                        text="✅ Оплата прошла успешно! Ваш конфиг прикреплен к этому сообщению."
                    )
                else:
                    raise FileNotFoundError(f"Config file {config_file} not found")

            except Exception as e:
                conn.execute("ROLLBACK")
                await log_action("PAYMENT_SUCCESS_ERROR", user_id, f"Error: {str(e)}")
                await context.bot.edit_message_text(
                    chat_id=job.data['chat_id'],
                    message_id=job.data['message_id'],
                    text=f"✅ Оплата прошла успешно, но произошла ошибка: {str(e)}\n\nПожалуйста, свяжитесь с поддержкой."
                )
            finally:
                conn.close()

        elif status == 'pending':
            context.job_queue.run_once(
                callback=check_payment_job,
                when=30,
                data=job.data,
                name=f"payment_check_{label}"
            )
        else:
            await log_action("PAYMENT_FAILED", user_id, f"Status: {status}")
            await context.bot.edit_message_text(
                chat_id=job.data['chat_id'],
                message_id=job.data['message_id'],
                text="❌ Платеж не был подтвержден. Пожалуйста, попробуйте еще раз или свяжитесь с поддержкой."
            )

    except Exception as e:
        await log_action("CHECK_PAYMENT_JOB_ERROR", user_id, f"Error: {str(e)}")
        logger.exception("Ошибка в check_payment_job")
        context.job_queue.run_once(
            callback=check_payment_job,
            when=60,
            data=job.data,
            name=f"payment_check_retry_{label}"
        )


async def show_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Показать главное меню"""
    try:
        user = update.message.from_user if update.message else update.callback_query.from_user
        await log_action("MAIN_MENU", user.id)

        keyboard = [
            [InlineKeyboardButton("🛒 Купить доступ", callback_data='buy_access')],
            [InlineKeyboardButton("🔑 Мои ключи", callback_data='my_keys')],
            [InlineKeyboardButton("❓ Помощь", callback_data='help')],
        ]

        if check_admin(user.id):
            keyboard.append([InlineKeyboardButton("👑 Админ-панель", callback_data='admin_panel')])

        reply_markup = InlineKeyboardMarkup(keyboard)

        if update.message:
            await update.message.reply_text(
                f"🔐 Добро пожаловать, {user.first_name}!\n\n"
                "Выберите действие из меню ниже:",
                reply_markup=reply_markup
            )
        else:
            await update.callback_query.edit_message_text(
                f"🔐 Добро пожаловать, {user.first_name}!\n\n"
                "Выберите действие из меню ниже:",
                reply_markup=reply_markup
            )
    except Exception as e:
        await log_action("MAIN_MENU_ERROR", user.id, f"Error: {str(e)}")
        if update.message:
            await update.message.reply_text("❌ Произошла ошибка. Попробуйте позже.")
        else:
            await update.callback_query.edit_message_text("❌ Произошла ошибка. Попробуйте позже.")


async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик команды /admin"""
    user = update.message.from_user
    if not check_admin(user.id):
        await update.message.reply_text("❌ Недостаточно прав")
        return

    await log_action("ADMIN_COMMAND", user.id)
    await update.message.reply_text(
        "👑 Админ-панель\n\n"
        "Доступные команды:\n"
        "/on - Активировать бота\n"
        "/off - Деактивировать бота\n"
        "/vpn_status - Статус сервера\n"
        "/stats - Статистика"
    )


async def activate_bot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Активация бота"""
    user = update.message.from_user
    if not check_admin(user.id):
        await update.message.reply_text("❌ Недостаточно прав")
        return

    global bot_active
    bot_active = True
    await log_action("BOT_ACTIVATED", user.id)
    await update.message.reply_text("✅ Бот активирован")


async def deactivate_bot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Деактивация бота"""
    user = update.message.from_user
    if not check_admin(user.id):
        await update.message.reply_text("❌ Недостаточно прав")
        return

    global bot_active
    bot_active = False
    await log_action("BOT_DEACTIVATED", user.id)
    await update.message.reply_text("⛔ Бот деактивирован")


async def vpn_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Проверка состояния VPN сервера"""
    user = update.message.from_user
    if not check_admin(user.id):
        return

    await log_action("VPN_STATUS", user.id)
    try:
        active_clients, error = ssh_execute_command("cat /etc/openvpn/server/ipp.txt | wc -l")
        if error:
            raise Exception(error)

        uptime, error = ssh_execute_command("uptime -p")
        if error:
            uptime = "не удалось получить"

        await update.message.reply_text(
            f"🛜 Статус VPN сервера\n\n"
            f"IP: {VPN_SERVER_IP}\n"
            f"Аптайм: {uptime}\n"
            f"Активных подключений: {active_clients}\n"
            f"Статус бота: {'🟢 Активен' if bot_active else '🔴 Выключен'}"
        )
    except Exception as e:
        await log_action("VPN_STATUS_ERROR", user.id, f"Error: {str(e)}")
        await update.message.reply_text(f"❌ Ошибка: {str(e)}")


async def show_admin_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Показать статистику"""
    query = update.callback_query
    await query.answer()

    user = query.from_user
    if not check_admin(user.id):
        return

    await log_action("ADMIN_STATS", user.id)
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*), SUM(sum) FROM payments WHERE status='success'")
            total_payments, total_amount = cursor.fetchone()

            cursor.execute("SELECT COUNT(DISTINCT user_id) FROM issued_configs WHERE expiry_date > datetime('now')")
            active_users = cursor.fetchone()[0]

            cursor.execute("""
                SELECT strftime('%d.%m.%Y %H:%M', timestamp) as date, 
                       username, sum, period 
                FROM payments 
                WHERE status='success' 
                ORDER BY timestamp DESC 
                LIMIT 5
            """)
            last_payments = cursor.fetchall()

            payments_text = "\n".join([f"{row[0]} - {row[1]} - {row[2]} руб. ({row[3]})" for row in last_payments])

            await query.edit_message_text(
                f"📊 Статистика:\n\n"
                f"Всего платежей: {total_payments}\n"
                f"Общая сумма: {total_amount or 0} руб.\n"
                f"Активных пользователей: {active_users}\n\n"
                f"Последние платежи:\n{payments_text}",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔄 Обновить", callback_data='admin_stats')],
                    [InlineKeyboardButton("◀️ Назад", callback_data='admin_panel')]
                ])
            )
    except Exception as e:
        await log_action("ADMIN_STATS_ERROR", user.id, f"Error: {str(e)}")
        await query.edit_message_text("❌ Ошибка при получении статистики")


async def show_admin_manage(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Показать панель управления администратора"""
    query = update.callback_query
    await query.answer()

    user = query.from_user
    if not check_admin(user.id):
        await query.edit_message_text("❌ Недостаточно прав")
        return

    await log_action("ADMIN_MANAGE", user.id)

    keyboard = [
        [InlineKeyboardButton("🧹 Очистить все данные", callback_data='admin_clear_all')],
        [InlineKeyboardButton("🔄 Обновить сервер", callback_data='admin_reload_server')],
        [InlineKeyboardButton("◀️ Назад", callback_data='admin_panel')]
    ]

    await query.edit_message_text(
        "⚙️ Управление сервером\n\n"
        "Выберите действие:",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )


async def clear_all_data(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Очистка всех данных"""
    query = update.callback_query
    await query.answer()

    user = query.from_user
    if not check_admin(user.id):
        await query.edit_message_text("❌ Недостаточно прав")
        return

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("BEGIN")
            try:
                conn.execute("DELETE FROM payments")
                conn.execute("DELETE FROM issued_configs")
                conn.execute("COMMIT")
            except:
                conn.execute("ROLLBACK")
                raise

        for filename in os.listdir(VPN_CONFIGS_DIR):
            file_path = os.path.join(VPN_CONFIGS_DIR, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.exception(f"Ошибка удаления файла {file_path}")

        await query.edit_message_text("✅ Все данные успешно очищены")
        await log_action("CLEAR_ALL_DATA", user.id)
    except Exception as e:
        await query.edit_message_text(f"❌ Ошибка при очистке данных: {e}")
        await log_action("CLEAR_ALL_DATA_ERROR", user.id, f"Error: {str(e)}")


async def reload_server(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Перезагрузка сервера OpenVPN"""
    query = update.callback_query
    await query.answer()

    user = query.from_user
    if not check_admin(user.id):
        await query.edit_message_text("❌ Недостаточно прав")
        return

    try:
        time_module.sleep(1)
        output, error = ssh_execute_command("sudo systemctl restart openvpn.service")
        if error:
            raise Exception(error)

        await query.edit_message_text("✅ Сервер OpenVPN успешно перезагружен")
        await log_action("RELOAD_SERVER", user.id)
    except Exception as e:
        await query.edit_message_text(f"❌ Ошибка перезагрузки сервера: {e}")
        await log_action("RELOAD_SERVER_ERROR", user.id, f"Error: {str(e)}")


async def process_payment(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработка платежа"""
    query = update.callback_query
    await query.answer()

    user = query.from_user
    period = query.data
    amount = PRICES.get(period)

    await log_action("PROCESS_PAYMENT", user.id, f"Period: {period}")

    if amount is None:
        await query.edit_message_text("❌ Ошибка: неверный период подписки")
        return

    try:
        payment_url, label = await create_payment(user.id, user.username, amount, period)

        period_text = {
            '1month': '1 месяц',
            '3months': '3 месяца',
            '6months': '6 месяцев',
            '1year': '1 год'
        }.get(period, period)

        keyboard = [
            [InlineKeyboardButton("💳 Оплатить", url=payment_url)],
            [InlineKeyboardButton("🔍 Проверить оплату", callback_data=f'check_payment_{label}')],
            [InlineKeyboardButton("◀️ Назад", callback_data='buy_access')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        message = await query.edit_message_text(
            f"💸 Оплата {amount} руб. за {period_text}\n\n"
            "1. Нажмите кнопку 'Оплатить'\n"
            "2. Совершите платеж\n"
            "3. После успешной оплаты конфиг будет отправлен автоматически",
            reply_markup=reply_markup
        )

        context.job_queue.run_once(
            callback=check_payment_job,
            when=30,
            data={
                'chat_id': message.chat_id,
                'message_id': message.message_id,
                'label': label,
                'user_id': user.id,
                'username': user.username,
                'period': period
            },
            name=f"payment_check_{label}"
        )

    except Exception as e:
        await log_action("PROCESS_PAYMENT_ERROR", user.id, f"Error: {str(e)}")
        await query.edit_message_text("❌ Произошла ошибка. Попробуйте позже.")


async def show_buy_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Показать меню покупки"""
    query = update.callback_query
    await query.answer()

    user = query.from_user
    await log_action("SHOW_BUY_MENU", user.id)

    keyboard = [
        [InlineKeyboardButton(f"1 месяц - {PRICES['1month']} руб.", callback_data='1month')],
        [InlineKeyboardButton(f"3 месяца - {PRICES['3months']} руб.", callback_data='3months')],
        [InlineKeyboardButton(f"6 месяцев - {PRICES['6months']} руб.", callback_data='6months')],
        [InlineKeyboardButton(f"1 год - {PRICES['1year']} руб.", callback_data='1year')],
        [InlineKeyboardButton("◀️ Назад", callback_data='back_to_main')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await query.edit_message_text(
        "🛒 Выберите срок подписки:",
        reply_markup=reply_markup
    )


async def show_my_keys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Показать ключи пользователя"""
    query = update.callback_query
    await query.answer()

    user = query.from_user
    await log_action("SHOW_MY_KEYS", user.id)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT config_file, issue_date, expiry_date 
                FROM issued_configs 
                WHERE user_id = ?
                ORDER BY issue_date DESC
            """, (user.id,))
            keys = cursor.fetchall()

            if not keys:
                await query.edit_message_text(
                    "🔑 У вас пока нет активных ключей",
                    reply_markup=InlineKeyboardMarkup([
                        [InlineKeyboardButton("🛒 Купить доступ", callback_data='buy_access')],
                        [InlineKeyboardButton("◀️ Назад", callback_data='back_to_main')]
                    ])
                )
                return

            keys_text = "\n".join([
                f"🔸 {row['config_file']} (выдан {row['issue_date']}, действует до {row['expiry_date']})"
                for row in keys
            ])

            await query.edit_message_text(
                f"🔑 Ваши ключи:\n\n{keys_text}\n\n"
                "Для повторной отправки нажмите на ключ:",
                reply_markup=InlineKeyboardMarkup([
                    *[[InlineKeyboardButton(row['config_file'], callback_data=f'send_key_{row["config_file"]}')]
                      for row in keys],
                    [InlineKeyboardButton("◀️ Назад", callback_data='back_to_main')]
                ])
            )
    except Exception as e:
        await log_action("SHOW_MY_KEYS_ERROR", user.id, f"Error: {str(e)}")
        await query.edit_message_text("❌ Произошла ошибка. Попробуйте позже.")


async def show_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Показать помощь"""
    query = update.callback_query
    await query.answer()

    user = query.from_user
    await log_action("SHOW_HELP", user.id)

    await query.edit_message_text(
        "❓ Помощь\n\n"
        "Для подключения:\n"
        "1. Установите OpenVPN клиент\n"
        "2. Импортируйте полученный файл\n"
        "3. Подключитесь к серверу\n\n"
        "По вопросам: @support",
        reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("◀️ Назад", callback_data='back_to_main')]
        ])
    )


async def show_admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Показать админ-панель"""
    try:
        query = update.callback_query
        await query.answer()
        user = query.from_user

        if not check_admin(user.id):
            await query.answer("❌ Недостаточно прав", show_alert=True)
            return

        await log_action("ADMIN_PANEL_OPEN", user.id)

        keyboard = [
            [InlineKeyboardButton("📊 Статистика", callback_data='admin_stats')],
            [InlineKeyboardButton("⚙️ Управление", callback_data='admin_manage')],
            [InlineKeyboardButton("◀️ На главную", callback_data='back_to_main')]
        ]

        try:
            await query.edit_message_text(
                text="👑 Админ-панель\n\nВыберите действие:",
                reply_markup=InlineKeyboardMarkup(keyboard))
        except Exception as e:
            await context.bot.send_message(
                chat_id=user.id,
                text="👑 Админ-панель\n\nВыберите действие:",
                reply_markup=InlineKeyboardMarkup(keyboard))
    except Exception as e:
        logger.exception("Ошибка в show_admin_panel")
        await handle_admin_error(update, context, e)


async def handle_admin_error(update: Update, context: ContextTypes.DEFAULT_TYPE, error: Exception):
    """Обработчик ошибок админ-панели"""
    try:
        if update.callback_query:
            await update.callback_query.answer(f"⚠️ Ошибка: {str(error)[:200]}", show_alert=True)
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="❌ Ошибка в админ-панели. Администратор уведомлен.")
    except Exception as e:
        logger.critical("Критическая ошибка в handle_admin_error", exc_info=True)


async def check_payment_manually(update: Update, context: ContextTypes.DEFAULT_TYPE, label: str):
    """Проверка платежа вручную"""
    query = update.callback_query
    await query.answer()

    user = query.from_user
    await log_action("CHECK_PAYMENT_MANUALLY", user.id, f"Label: {label}")

    try:
        status = await check_payment_status(label)

        if status == 'success':
            await query.edit_message_text(
                "✅ Оплата прошла успешно!",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔑 Получить ключ", callback_data=f'resend_config_{label}')],
                    [InlineKeyboardButton("◀️ Назад", callback_data='my_keys')]
                ]))
        elif status == 'pending':
            await query.edit_message_text(
                "🕒 Платеж еще не обработан",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔄 Проверить снова", callback_data=f'check_payment_{label}')],
                    [InlineKeyboardButton("◀️ Назад", callback_data='buy_access')]
                ]))
        else:
            await query.edit_message_text(
                "❌ Ошибка проверки платежа",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔄 Попробовать снова", callback_data=f'check_payment_{label}')],
                    [InlineKeyboardButton("◀️ Назад", callback_data='buy_access')]
                ]))
    except Exception as e:
        await log_action("CHECK_PAYMENT_MANUALLY_ERROR", user.id, f"Error: {str(e)}")
        await query.edit_message_text("❌ Произошла ошибка. Попробуйте позже.")


async def send_config_file(update: Update, context: ContextTypes.DEFAULT_TYPE, config_file: str):
    """Отправить конфиг пользователю"""
    query = update.callback_query
    await query.answer()

    user = query.from_user
    await log_action("SEND_CONFIG_FILE", user.id, f"Config: {config_file}")

    try:
        config_path = os.path.join(VPN_CONFIGS_DIR, config_file)
        if not os.path.exists(config_path):
            raise FileNotFoundError("Файл не найден")

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM issued_configs 
                WHERE user_id = ? AND config_file = ?
            """, (user.id, config_file))

            if cursor.fetchone()[0] == 0:
                raise PermissionError("Конфиг не принадлежит пользователю")

        with open(config_path, 'rb') as f:
            await context.bot.send_document(
                chat_id=query.message.chat_id,
                document=InputFile(f),
                caption=f"🔑 Ваш конфиг: {config_file}"
            )

        await log_action("SEND_CONFIG_SUCCESS", user.id, f"Config: {config_file}")
    except Exception as e:
        await log_action("SEND_CONFIG_ERROR", user.id, f"Error: {str(e)}")
        await query.edit_message_text("❌ Не удалось отправить файл. Обратитесь в поддержку.")


async def resend_config(update: Update, context: ContextTypes.DEFAULT_TYPE, label: str):
    """Повторная отправка конфига"""
    query = update.callback_query
    await query.answer()

    user = query.from_user
    await log_action("RESEND_CONFIG", user.id, f"Label: {label}")

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT config_file FROM payments WHERE label=? AND status='success'",
                (label,)
            )
            result = cursor.fetchone()

            if not result or not result[0]:
                raise ValueError("Конфигурационный файл не найден")

            config_file = result[0]
            config_path = os.path.join(VPN_CONFIGS_DIR, config_file)

            if os.path.exists(config_path):
                with open(config_path, 'rb') as f:
                    await context.bot.send_document(
                        chat_id=query.message.chat_id,
                        document=InputFile(f),
                        caption=f"🔑 Ваш конфиг: {config_file}"
                    )
            else:
                raise FileNotFoundError("Файл конфигурации не найден")

    except Exception as e:
        await log_action("RESEND_CONFIG_ERROR", user.id, f"Error: {str(e)}")
        await query.edit_message_text("❌ Не удалось отправить конфиг. Обратитесь в поддержку.")


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Глобальный обработчик ошибок"""
    try:
        user_id = 0
        if update.message:
            user_id = update.message.from_user.id
        elif update.callback_query:
            user_id = update.callback_query.from_user.id

        await log_action("GLOBAL_ERROR", user_id, f"Error: {str(context.error)}")
        logger.exception("Исключение в обработчике")

        if update.message:
            await update.message.reply_text("❌ Произошла ошибка. Попробуйте позже.")
        elif update.callback_query:
            try:
                await update.callback_query.answer("❌ Ошибка. Попробуйте снова.")
            except Exception as e:
                logger.exception("Ошибка при ответе на callback_query")
    except Exception as e:
        logger.critical("Критическая ошибка в error_handler", exc_info=True)


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик нажатий на inline-кнопки"""
    query = update.callback_query
    await query.answer()

    data = query.data
    user = query.from_user

    try:
        if data == 'buy_access':
            await show_buy_menu(update, context)
        elif data in PRICES:
            await process_payment(update, context)
        elif data == 'my_keys':
            await show_my_keys(update, context)
        elif data == 'help':
            await show_help(update, context)
        elif data == 'admin_panel':
            await show_admin_panel(update, context)
        elif data == 'admin_stats':
            await show_admin_stats(update, context)
        elif data == 'admin_manage':
            await show_admin_manage(update, context)
        elif data == 'admin_clear_all':
            await clear_all_data(update, context)
        elif data == 'admin_reload_server':
            await reload_server(update, context)
        elif data.startswith('check_payment_'):
            label = data[14:]
            await check_payment_manually(update, context, label)
        elif data.startswith('send_key_'):
            config_file = data[9:]
            await send_config_file(update, context, config_file)
        elif data.startswith('resend_config_'):
            label = data[14:]
            await resend_config(update, context, label)
        elif data == 'back_to_main':
            await show_main_menu(update, context)
        elif data == 'back_to_admin':
            await show_admin_panel(update, context)
        else:
            await query.edit_message_text("❌ Неизвестная команда")

    except Exception as e:
        logger.exception("Ошибка в button_handler")
        try:
            await query.edit_message_text("⚠️ Произошла ошибка. Попробуйте позже.")
        except:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="⚠️ Произошла ошибка. Попробуйте позже."
            )


def main():
    """Запуск бота"""
    try:
        os.makedirs(VPN_CONFIGS_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(SSH_KEY_PATH), exist_ok=True)

        if not os.path.exists(SSH_KEY_PATH):
            logger.error(f"SSH ключ не найден по пути: {SSH_KEY_PATH}")
            logger.info("Создайте ключ командой:")
            logger.info("ssh-keygen -t ed25519 -f ssh_keys/vpnbot_private_key -N \"\"")
            exit(1)

        application = Application.builder().token(TOKEN).build()

        handlers = [
            CommandHandler('start', show_main_menu),
            CommandHandler('admin', admin_command),
            CommandHandler('on', activate_bot),
            CommandHandler('off', deactivate_bot),
            CommandHandler('vpn_status', vpn_status),
            CommandHandler('stats', show_admin_stats),
            CallbackQueryHandler(button_handler)
        ]

        for handler in handlers:
            application.add_handler(handler)

        application.add_error_handler(error_handler)

        job_queue = application.job_queue
        job_queue.run_daily(
            cleanup_expired_configs,
            time=datetime_time(3, 0),
            name="daily_cleanup"
        )

        logger.info("Запуск бота...")
        application.run_polling(
            allowed_updates=["message", "callback_query"],
            drop_pending_updates=True
        )
    except Conflict:
        logger.error("Бот уже запущен")
    except Exception as e:
        logger.critical("Критическая ошибка при запуске бота", exc_info=True)
    finally:
        logger.info("Бот остановлен")


if __name__ == '__main__':
    main()
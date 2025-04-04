from telegram import Update
from telegram.ext import ContextTypes
from services.payment import PaymentService


async def start_payment(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    payment = await PaymentService.create_payment(user.id, 100.0)

    await update.message.reply_text(
        f"Платеж на 100 RUB создан. ID: {payment.id}",
        reply_markup=payment_keyboard(payment.id)
    )
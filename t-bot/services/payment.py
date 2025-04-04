from datetime import datetime
from database import crud, models
from database.session import get_db


class PaymentService:
    @staticmethod
    async def create_payment(user_id: int, amount: float):
        async with get_db() as db:
            payment = models.Payment(
                user_id=user_id,
                amount=amount,
                status="pending",
                created_at=datetime.now()
            )
            await crud.create_payment(db, payment)
            return payment

    @staticmethod
    async def verify_payment(payment_id: int):
        async with get_db() as db:
            payment = await crud.get_payment(db, payment_id)
            # Логика проверки платежа...
            payment.status = "completed"
            await db.commit()
            return payment
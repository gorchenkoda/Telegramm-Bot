t-bot/
├── .env
├── .gitignore
├── config.py
├── main.py
├── requirements.txt
├── alembic.ini
│
├── core/
│   ├── __init__.py
│   ├── exceptions.py        # Централизованная обработка ошибок
│   ├── middlewares.py       # Промежуточное ПО
│   └── utils.py            # Общие утилиты
│
├── database/
│   ├── __init__.py
│   ├── models.py           # SQLAlchemy модели
│   ├── crud.py             # CRUD операции
│   ├── session.py          # Управление сессиями БД
│   └── migrations/         # Миграции Alembic
│       ├── versions/
│       ├── env.py
│       └── script.py.mako
│
├── handlers/
│   ├── __init__.py
│   ├── common/             # Основные команды
│   │   ├── start.py
│   │   ├── help.py
│   │   └── cancel.py
│   ├── payments/           # Платежи
│   │   ├── __init__.py
│   │   ├── handlers.py     # Обработчики
│   │   ├── keyboards.py    # Клавиатуры
│   │   └── callbacks.py    # Колбэки
│   └── admin/             # Админка
│       ├── __init__.py
│       ├── stats.py
│       └── broadcast.py
│
├── jobs/
│   ├── __init__.py
│   ├── payment_checker.py  # Проверка платежей
│   └── cleanup.py         # Очистка устаревших данных
│
├── services/
│   ├── __init__.py
│   ├── payment.py         # Логика платежей
│   ├── notification.py    # Уведомления
│   └── user.py           # Работа с пользователями
│
├── static/
│   ├── templates/        # Шаблоны сообщений
│   │   ├── payment.md
│   │   └── welcome.md
│   └── locales/          # Локализации
│       ├── en/
│       └── ru/
│
└── tests/
    ├── __init__.py
    ├── test_handlers/
    └── test_services/
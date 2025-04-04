Telegramm-Bot/
├── .env
├── .gitignore
├── config.py
├── main.py
├── requirements.txt
├── alembic.ini
│
├── core/
│   ├── __init__.py
│   ├── exceptions.py
│   ├── middlewares.py
│   └── utils.py
│
├── database/
│   ├── __init__.py
│   ├── models.py
│   ├── crud.py
│   ├── session.py
│   └── migrations/
│
├── handlers/
│   ├── __init__.py
│   ├── common/
│   │   ├── start.py
│   │   └── help.py
│   ├── payments/
│   │   ├── __init__.py
│   │   ├── handlers.py
│   │   └── keyboards.py
│   └── admin/
│       ├── __init__.py
│       └── stats.py
│
├── jobs/
│   ├── __init__.py
│   └── payment_checker.py
│
├── services/
│   ├── __init__.py
│   ├── payment.py
│   └── notification.py
│
└── static/
    ├── templates/
    └── locales/
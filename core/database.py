import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# تحديد مسار قاعدة البيانات SQLite لتبقي داخل المشروع
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "recon.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# إنشاء المحرك الخاص بقاعدة البيانات
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# إنشاء مصنع الجلسات (Session) للتعامل مع قاعدة البيانات
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# الأساس لجداول SQLAlchemy
Base = declarative_base()

def init_db():
    """تنشئ الجداول تلقائياً في قاعدة البيانات إذا لم تكن موجودة"""
    # سنقوم باستيراد النماذج هنا لتجنب التداخل الدائري (Circular Imports)
    import core.models
    Base.metadata.create_all(bind=engine)

def get_db():
    """الحصول على جلسة قاعدة البيانات للاستخدام"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
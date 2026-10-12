from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from core.database import Base

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    status = Column(String, default="active")  # active, paused, finished, failed
    stage = Column(String, default="Idle")      # مرحلة الفحص الحالية لتتبع التقدم
    
    # حقول المراقبة المستمرة الجديدة
    is_monitored = Column(Boolean, default=False)          # هل الهدف مفعل عليه المراقبة التلقائية؟
    monitoring_interval_hours = Column(Integer, default=8) # عدد الساعات بين كل فحص (مثلاً كل 8 ساعات = 3 مرات يومياً)
    last_scanned_at = Column(DateTime, nullable=True)      # تاريخ آخر فحص تم إجراؤه للمراقبة
    
    created_at = Column(DateTime, default=datetime.utcnow)

    # العلاقات لربط الهدف ببياناته المعزولة
    subdomains = relationship("Subdomain", back_populates="target", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="target", cascade="all, delete-orphan")
    js_files = relationship("JSFile", back_populates="target", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="target", cascade="all, delete-orphan")


class Subdomain(Base):
    __tablename__ = "subdomains"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    subdomain = Column(String, index=True, nullable=False)
    is_new = Column(Boolean, default=True)  # لمتابعة ما إذا كان النطاق الفرعي جديداً في آخر فحص
    first_seen = Column(DateTime, default=datetime.utcnow)

    # العلاقة مع الهدف
    target = relationship("Target", back_populates="subdomains")
    
    # التقنيات المرتبطة بهذا السب دومين
    technologies = relationship("Technology", back_populates="subdomain_rel", cascade="all, delete-orphan")


class Technology(Base):
    __tablename__ = "technologies"

    id = Column(Integer, primary_key=True, index=True)
    subdomain_id = Column(Integer, ForeignKey("subdomains.id"), nullable=False)
    tech_name = Column(String, nullable=False)  # مثل Nginx, React, WordPress
    version = Column(String, nullable=True)     # إصدار التقنية إن وجد

    # العلاقة مع السب دومين
    subdomain_rel = relationship("Subdomain", back_populates="technologies")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    url = Column(String, nullable=False)
    status_code = Column(Integer, nullable=True)  # مثل 200, 403, 404
    is_new = Column(Boolean, default=True)        # لمتابعة ما إذا كان الـ Endpoint جديداً
    first_seen = Column(DateTime, default=datetime.utcnow)

    # العلاقة مع الهدف
    target = relationship("Target", back_populates="endpoints")


class JSFile(Base):
    __tablename__ = "js_files"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    js_url = Column(String, nullable=False)
    is_new = Column(Boolean, default=True)        # لمتابعة ما إذا كان ملف الـ JS جديداً
    first_seen = Column(DateTime, default=datetime.utcnow)

    # العلاقة مع الهدف
    target = relationship("Target", back_populates="js_files")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    title = Column(String, nullable=False)       # عنوان التنبيه (مثلاً: New Subdomain Found)
    message = Column(String, nullable=False)     # تفاصيل الاكتشاف الجديد
    severity = Column(String, default="info")    # info, warning, high, critical
    created_at = Column(DateTime, default=datetime.utcnow)

    # العلاقة مع الهدف
    target = relationship("Target", back_populates="alerts")
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, jsonify, make_response, request, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()
db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc)


class Role(db.Model):
    __tablename__ = 'roles'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    users: Mapped[list['User']] = relationship(back_populates='role')


class User(db.Model):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    first_name: Mapped[str] = mapped_column(String(80), nullable=False)
    role_id: Mapped[int] = mapped_column(ForeignKey('roles.id'), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_login_count: Mapped[int] = mapped_column(default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    role: Mapped[Role] = relationship(back_populates='users')
    sessions: Mapped[list['Session']] = relationship(back_populates='user', cascade='all, delete-orphan')


class Session(db.Model):
    __tablename__ = 'sessions'
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    user: Mapped[User] = relationship(back_populates='sessions')


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'))
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


def serialize_user(user: User):
    return {'id': user.id, 'email': user.email, 'firstName': user.first_name, 'role': user.role.name}


def token_hash(token: str):
    return hashlib.sha256(token.encode()).hexdigest()


def audit(event: str, user_id=None, detail=None):
    db.session.add(AuditLog(user_id=user_id, event=event, detail=detail, ip_address=request.remote_addr))


def get_session():
    token = request.cookies.get('northstar_session')
    if not token:
        return None
    active_session = db.session.scalar(db.select(Session).where(Session.token_hash == token_hash(token)))
    if not active_session or active_session.revoked_at or active_session.expires_at <= utcnow() or not active_session.user.is_active:
        return None
    return active_session


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        active_session = get_session()
        if not active_session:
            return jsonify({'error': 'Authentication required.'}), 401
        g.current_session = active_session
        g.current_user = active_session.user
        return view(*args, **kwargs)
    return wrapped


def csrf_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get('X-XSRF-TOKEN')
        cookie = request.cookies.get('XSRF-TOKEN')
        if not header or not cookie or not secrets.compare_digest(header, cookie):
            return jsonify({'error': 'Invalid CSRF token.'}), 403
        return view(*args, **kwargs)
    return wrapped


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'development-only-change-me'),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'postgresql+psycopg://northstar:change-me@localhost:5432/northstar'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_TTL_HOURS=int(os.environ.get('SESSION_TTL_HOURS', '8')),
        COOKIE_SECURE=os.environ.get('COOKIE_SECURE', 'false').lower() == 'true'
    )
    db.init_app(app)
    CORS(app, origins=[os.environ.get('FRONTEND_ORIGIN', 'http://localhost:4200')], supports_credentials=True, allow_headers=['Content-Type', 'X-XSRF-TOKEN'])

    @app.after_request
    def security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    @app.get('/api/auth/csrf')
    def csrf():
        response = make_response({'ok': True})
        response.set_cookie('XSRF-TOKEN', secrets.token_urlsafe(32), secure=app.config['COOKIE_SECURE'], samesite='Lax', httponly=False, path='/')
        return response

    @app.post('/api/auth/login')
    @csrf_required
    def login():
        payload = request.get_json(silent=True) or {}
        email = str(payload.get('email', '')).strip().lower()
        password = str(payload.get('password', ''))
        if not email or not password:
            return jsonify({'error': 'Email and password are required.'}), 400
        user = db.session.scalar(db.select(User).where(User.email == email))
        now = utcnow()
        if not user or not check_password_hash(user.password_hash, password):
            if user:
                user.failed_login_count += 1
                if user.failed_login_count >= 5:
                    user.locked_until = now + timedelta(minutes=15)
                audit('login_failed', user.id, 'Invalid password')
                db.session.commit()
            return jsonify({'error': 'Invalid email or password.'}), 401
        if not user.is_active:
            audit('login_blocked', user.id, 'Inactive account'); db.session.commit()
            return jsonify({'error': 'This account is inactive. Contact an administrator.'}), 403
        if user.locked_until and user.locked_until > now:
            return jsonify({'error': 'Account temporarily locked. Try again later.'}), 423
        user.failed_login_count = 0; user.locked_until = None; user.last_login_at = now
        raw_token = secrets.token_urlsafe(48)
        active_session = Session(token_hash=token_hash(raw_token), user_id=user.id, expires_at=now + timedelta(hours=app.config['SESSION_TTL_HOURS']), ip_address=request.remote_addr, user_agent=request.user_agent.string[:512])
        db.session.add(active_session); audit('login_success', user.id); db.session.commit()
        response = make_response({'user': serialize_user(user)})
        response.set_cookie('northstar_session', raw_token, secure=app.config['COOKIE_SECURE'], httponly=True, samesite='Lax', max_age=app.config['SESSION_TTL_HOURS'] * 3600, path='/')
        return response

    @app.post('/api/auth/logout')
    @csrf_required
    def logout():
        active_session = get_session()
        if active_session:
            active_session.revoked_at = utcnow(); audit('logout', active_session.user_id); db.session.commit()
        response = make_response({'ok': True})
        response.delete_cookie('northstar_session', path='/')
        return response

    @app.get('/api/auth/me')
    @login_required
    def me():
        return {'user': serialize_user(g.current_user)}

    @app.get('/api/dashboard')
    @login_required
    def dashboard():
        role = g.current_user.role.name
        tasks = {'Administrator': 12, 'Manager': 8, 'Member': 5}[role]
        return {'role': role, 'openPriorities': tasks, 'onTrack': 84, 'nextMilestone': 'Sep 12'}

    @app.cli.command('init-db')
    def init_db():
        db.create_all()
        for name in ('Administrator', 'Manager', 'Member'):
            if not db.session.scalar(db.select(Role).where(Role.name == name)):
                db.session.add(Role(name=name))
        db.session.commit()
        print('Database tables and roles are ready.')

    @app.cli.command('seed-demo')
    def seed_demo():
        for role_name in ('Administrator', 'Manager', 'Member'):
            email = f'{role_name.lower()}@northstar.io'
            if not db.session.scalar(db.select(User).where(User.email == email)):
                role = db.session.scalar(db.select(Role).where(Role.name == role_name))
                db.session.add(User(email=email, first_name=role_name, role_id=role.id, password_hash=generate_password_hash('ChangeMe123!')))
        db.session.commit()
        print('Demo users created. All use ChangeMe123! — change or remove them outside development.')

    return app


app = create_app()

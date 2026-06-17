from fastapi import FastAPI, Request, Form, Depends, Response, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, String, select, Float, Text, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
import os
import shutil
from typing import Optional

# ==========================================
# 1. SECURITY & JWT CONFIGURATION
# ==========================================
SECRET_KEY = "my_super_secret_key_for_development"  # In production, keep this safe!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Directory for uploaded resumes
UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8')[:72], hashed_password.encode('utf-8'))

def get_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8')[:72], bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==========================================
# 2. DATABASE SETUP
# ==========================================
engine = create_engine("sqlite:///recruitment.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(100), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(20), default="candidate")  # "candidate" or "recruiter"

class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(150))
    company: Mapped[str] = mapped_column(String(100))
    location: Mapped[str] = mapped_column(String(100))
    job_type: Mapped[str] = mapped_column(String(50))   # Full-time, Part-time, Remote, etc.
    salary_range: Mapped[str] = mapped_column(String(50))
    description: Mapped[str] = mapped_column(String(2000))
    required_skills: Mapped[str] = mapped_column(String(500))  # comma-separated skills
    experience_level: Mapped[str] = mapped_column(String(50))  # Entry, Mid, Senior
    posted_by: Mapped[int] = mapped_column(Integer)   # recruiter user id
    posted_at: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(20), default="open")  # open / closed

class Application(Base):
    __tablename__ = "applications"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(Integer)
    candidate_id: Mapped[int] = mapped_column(Integer)
    candidate_name: Mapped[str] = mapped_column(String(100))
    candidate_email: Mapped[str] = mapped_column(String(100))
    resume_path: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    cover_letter: Mapped[str] = mapped_column(String(2000))
    skills: Mapped[str] = mapped_column(String(500))    # candidate's skills (comma-separated)
    status: Mapped[str] = mapped_column(String(30), default="Applied")  # Applied/Shortlisted/Interview/Hired/Rejected
    match_score: Mapped[str] = mapped_column(String(10), default="0")
    applied_at: Mapped[str] = mapped_column(String(30))
    interview_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    interview_notes: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

Base.metadata.create_all(bind=engine)

# ==========================================
# 3. FASTAPI SETUP & DEPENDENCIES
# ==========================================
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="Frontend")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
    except jwt.InvalidTokenError:
        return None
    user = db.scalars(select(User).where(User.email == email)).first()
    return user

def compute_match_score(job_skills: str, candidate_skills: str) -> int:
    """Simple keyword-based skill match score (0-100)."""
    job_set = set(s.strip().lower() for s in job_skills.split(",") if s.strip())
    cand_set = set(s.strip().lower() for s in candidate_skills.split(",") if s.strip())
    if not job_set:
        return 0
    matched = job_set & cand_set
    return round((len(matched) / len(job_set)) * 100)

# ==========================================
# 4. AUTH ROUTES — same logic as original
# ==========================================

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse(request=request, name="signup.html")

@app.post("/signup")
def signup_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db)
):
    existing_user = db.scalars(select(User).where(User.email == email)).first()
    if existing_user:
        return templates.TemplateResponse(request=request, name="signup.html", context={"error": "Email already registered."})

    new_user = User(name=name, email=email, hashed_password=get_password_hash(password), role=role)
    db.add(new_user)
    db.commit()

    access_token = create_access_token(data={"sub": new_user.email})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.post("/login")
def login_post(request: Request, email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.scalars(select(User).where(User.email == email)).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid email or password."})

    access_token = create_access_token(data={"sub": user.email})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response

# ==========================================
# 5. DASHBOARD (HOME)
# ==========================================

@app.get("/", response_class=HTMLResponse)
def home_page(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    jobs = db.scalars(select(Job).where(Job.status == "open")).all()
    if current_user.role == "recruiter":
        my_jobs = db.scalars(select(Job).where(Job.posted_by == current_user.id)).all()
        all_applications = db.scalars(select(Application)).all()
        # Group apps by job
        apps_by_job = {}
        for app_rec in all_applications:
            apps_by_job.setdefault(app_rec.job_id, []).append(app_rec)
        return templates.TemplateResponse(request=request, name="index.html", context={
            "current_user": current_user, "my_jobs": my_jobs, "all_jobs": jobs,
            "apps_by_job": apps_by_job, "all_applications": all_applications
        })
    else:
        # Candidate view: show open jobs with match scores
        my_applications = db.scalars(select(Application).where(Application.candidate_id == current_user.id)).all()
        applied_job_ids = {a.job_id for a in my_applications}
        return templates.TemplateResponse(request=request, name="index.html", context={
            "current_user": current_user, "jobs": jobs,
            "my_applications": my_applications, "applied_job_ids": applied_job_ids
        })

# ==========================================
# 6. JOB CRUD (Recruiters only)
# ==========================================

@app.get("/jobs/create", response_class=HTMLResponse)
def create_job_page(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user or current_user.role != "recruiter":
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request=request, name="create_job.html", context={"current_user": current_user})

@app.post("/jobs/create")
def create_job(
    title: str = Form(...),
    company: str = Form(...),
    location: str = Form(...),
    job_type: str = Form(...),
    salary_range: str = Form(...),
    description: str = Form(...),
    required_skills: str = Form(...),
    experience_level: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "recruiter":
        return RedirectResponse(url="/", status_code=303)
    new_job = Job(
        title=title, company=company, location=location, job_type=job_type,
        salary_range=salary_range, description=description, required_skills=required_skills,
        experience_level=experience_level, posted_by=current_user.id,
        posted_at=datetime.now().strftime("%Y-%m-%d %H:%M")
    )
    db.add(new_job)
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/jobs/update/{job_id}", response_class=HTMLResponse)
def update_job_page(request: Request, job_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user or current_user.role != "recruiter":
        return RedirectResponse(url="/", status_code=303)
    job = db.get(Job, job_id)
    return templates.TemplateResponse(request=request, name="update_job.html", context={"job": job, "current_user": current_user})

@app.post("/jobs/update/{job_id}")
def update_job(
    job_id: int,
    title: str = Form(...),
    company: str = Form(...),
    location: str = Form(...),
    job_type: str = Form(...),
    salary_range: str = Form(...),
    description: str = Form(...),
    required_skills: str = Form(...),
    experience_level: str = Form(...),
    status: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "recruiter":
        return RedirectResponse(url="/", status_code=303)
    job = db.get(Job, job_id)
    if job:
        job.title = title; job.company = company; job.location = location
        job.job_type = job_type; job.salary_range = salary_range
        job.description = description; job.required_skills = required_skills
        job.experience_level = experience_level; job.status = status
        db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/jobs/delete/{job_id}")
def delete_job(job_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user or current_user.role != "recruiter":
        return RedirectResponse(url="/", status_code=303)
    job = db.get(Job, job_id)
    if job:
        db.delete(job)
        db.commit()
    return RedirectResponse(url="/", status_code=303)

# ==========================================
# 7. APPLICATIONS CRUD (Candidates apply)
# ==========================================

@app.get("/jobs/{job_id}/apply", response_class=HTMLResponse)
def apply_page(request: Request, job_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user or current_user.role != "candidate":
        return RedirectResponse(url="/", status_code=303)
    job = db.get(Job, job_id)
    return templates.TemplateResponse(request=request, name="apply.html", context={"job": job, "current_user": current_user})

@app.post("/jobs/{job_id}/apply")
async def apply_post(
    job_id: int,
    cover_letter: str = Form(...),
    skills: str = Form(...),
    resume: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "candidate":
        return RedirectResponse(url="/", status_code=303)

    job = db.get(Job, job_id)
    resume_path = None
    if resume and resume.filename:
        file_extension = os.path.splitext(resume.filename)[1]
        unique_filename = f"resume_{current_user.id}_{job_id}_{datetime.now().timestamp()}{file_extension}"
        resume_path = f"uploads/{unique_filename}"
        with open(os.path.join(UPLOAD_DIR, unique_filename), "wb") as buffer:
            shutil.copyfileobj(resume.file, buffer)

    score = compute_match_score(job.required_skills if job else "", skills)

    new_app = Application(
        job_id=job_id, candidate_id=current_user.id,
        candidate_name=current_user.name, candidate_email=current_user.email,
        resume_path=resume_path, cover_letter=cover_letter, skills=skills,
        match_score=str(score), applied_at=datetime.now().strftime("%Y-%m-%d %H:%M")
    )
    db.add(new_app)
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/applications/{app_id}/update", response_class=HTMLResponse)
def update_application_page(request: Request, app_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user or current_user.role != "recruiter":
        return RedirectResponse(url="/", status_code=303)
    application = db.get(Application, app_id)
    job = db.get(Job, application.job_id) if application else None
    return templates.TemplateResponse(request=request, name="update_application.html", context={
        "application": application, "job": job, "current_user": current_user
    })

@app.post("/applications/{app_id}/update")
def update_application(
    app_id: int,
    status: str = Form(...),
    interview_date: Optional[str] = Form(None),
    interview_notes: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user or current_user.role != "recruiter":
        return RedirectResponse(url="/", status_code=303)
    application = db.get(Application, app_id)
    if application:
        application.status = status
        application.interview_date = interview_date
        application.interview_notes = interview_notes
        db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/applications/{app_id}/delete")
def delete_application(app_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    application = db.get(Application, app_id)
    if application:
        if application.resume_path:
            old_path = os.path.join("static", application.resume_path)
            if os.path.exists(old_path):
                os.remove(old_path)
        db.delete(application)
        db.commit()
    return RedirectResponse(url="/", status_code=303)

# ==========================================
# 8. JOB DETAIL / APPLICATIONS VIEW
# ==========================================

@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_detail(request: Request, job_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    job = db.get(Job, job_id)
    applications = db.scalars(select(Application).where(Application.job_id == job_id)).all()
    return templates.TemplateResponse(request=request, name="job_detail.html", context={
        "job": job, "applications": applications, "current_user": current_user
    })

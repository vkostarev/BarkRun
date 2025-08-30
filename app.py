from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from functools import wraps
from PIL import Image, ExifTags
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from sqlalchemy import or_, and_, func
import os
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
 # Use persistent volume path in production, instance path in development
if os.environ.get('RAILWAY_ENVIRONMENT'):
    # Production: Use Railway volume mount (you need to create a volume and set mount path)
    PERSISTENT_DATA_PATH = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', '/data')
else:
    # Development: Use Flask's instance path
    PERSISTENT_DATA_PATH = app.instance_path

# Ensure data directory exists
os.makedirs(PERSISTENT_DATA_PATH, exist_ok=True)

# Point DB to persistent location
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(PERSISTENT_DATA_PATH, 'barkrun.db').replace('\\', '/')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(PERSISTENT_DATA_PATH, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64MB per request

db = SQLAlchemy(app)

# Try to enable HEIC/AVIF decoding if pillow-heif is installed
try:
    import pillow_heif
    try:
        pillow_heif.register_heif_opener()
    except Exception:
        pass
    try:
        # Newer versions provide AVIF registration too
        pillow_heif.register_avif_opener()
    except Exception:
        pass
except Exception:
    # pillow-heif not installed; HEIC/AVIF may not decode
    pass

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='participant')  # admin, organizer, participant
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    organized_races = db.relationship('Race', backref='organizer', lazy=True, foreign_keys='Race.organizer_id')
    results = db.relationship('Result', backref='participant', lazy=True, foreign_keys='Result.participant_id')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_organizer(self):
        return self.role == 'organizer'
    
    def is_participant(self):
        return self.role == 'participant'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Race(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    distance = db.Column(db.Float, nullable=False)  # in kilometers
    date = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(200))
    organizer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.relationship('Result', backref='race', lazy=True)
    # New timing fields
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    participant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    race_id = db.Column(db.Integer, db.ForeignKey('race.id'), nullable=False)
    finish_time = db.Column(db.Integer, nullable=False)  # in seconds
    position = db.Column(db.Integer)
    pace = db.Column(db.Float)  # minutes per kilometer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Photo(db.Model):
    uid = db.Column('uid', db.Integer, primary_key=True)
    race_id = db.Column(db.Integer, db.ForeignKey('race.id'), nullable=False)
    # optional association; will be set later by identification flow
    user_id = db.Column('user', db.Integer, db.ForeignKey('user.id'), nullable=True)
    file_name = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=True)  # when photo was taken (from EXIF if available)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- App initialization helpers (no-shell DB bootstrap for Render) ---
def _check_db_schema_exists():
    """Check if database schema already exists by querying for tables."""
    try:
        with app.app_context():
            # Try to query the User table to see if schema exists
            db.session.execute(db.text("SELECT 1 FROM user LIMIT 1"))
            return True
    except Exception:
        # If query fails, schema doesn't exist or is incomplete
        return False

def _initialize_db_and_admin():
    """Create tables and a default admin if the DB is fresh."""
    with app.app_context():
        # Only create tables if schema doesn't exist
        if not _check_db_schema_exists():
            db.create_all()
        
        # Create default admin only if none exists
        if not User.query.filter_by(role='admin').first():
            admin = User(
                username='admin',
                email='admin@barkrun.local',
                name='Administrator',
                role='admin',
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

def _ensure_app_initialized_once():
    """Ensure instance paths exist and initialize DB on first boot.
    This runs at process start and is idempotent due to schema existence checks.
    """
    # Ensure uploads directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Always call initialization - it will check if schema exists
    _initialize_db_and_admin()

# Call after models are defined so queries work
_ensure_app_initialized_once()

# Role-based access decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('Admin access required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def organizer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (not current_user.is_admin() and not current_user.is_organizer()):
            flash('Organizer access required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash(f'Welcome back, {user.name}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        age = request.form.get('age')
        gender = request.form.get('gender')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            name=name,
            role='participant',
            age=int(age) if age else None,
            gender=gender
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/')
def index():
    # Match Results page filtering semantics
    if current_user.is_authenticated:
        if current_user.is_admin():
            results = Result.query.order_by(Result.created_at.desc()).all()
        elif current_user.is_organizer():
            organized_race_ids = [race.id for race in current_user.organized_races]
            results = (
                Result.query
                .filter(Result.race_id.in_(organized_race_ids))
                .order_by(Result.created_at.desc())
                .all()
            )
        else:
            results = (
                Result.query
                .filter_by(participant_id=current_user.id)
                .order_by(Result.created_at.desc())
                .all()
            )
    else:
        results = []
    # Race list (same as Results page) but limited to 10 most recent races
    claimed_race_ids_subq = (
        db.session.query(Photo.race_id)
        .filter(Photo.user_id == (current_user.id if current_user.is_authenticated else -1))
        .distinct()
        .subquery()
    )
    # We don't need full claimed_races list for rendering, just ids
    claimed_races_lim = (
        Race.query
        .filter(Race.id.in_(claimed_race_ids_subq))
        .order_by(Race.start_time.desc())
        .all()
    ) if current_user.is_authenticated else []
    all_races = (
        Race.query
        .order_by(Race.start_time.desc())
        .limit(10)
        .all()
    )
    claimed_race_ids = {r.id for r in claimed_races_lim}
    # Rank map only for races that are in the limited all_races and claimed
    claimed_photo_rank_by_race: dict[int, int] = {}
    if current_user.is_authenticated and claimed_races_lim:
        limited_ids = {r.id for r in all_races}
        for race in claimed_races_lim:
            if race.id not in limited_ids:
                continue
            my_photo = (
                Photo.query
                .filter_by(race_id=race.id, user_id=current_user.id)
                .order_by(Photo.uid.asc())
                .first()
            )
            if not my_photo:
                continue
            pivot_ts = my_photo.timestamp or my_photo.uploaded_at
            rank = (
                db.session.query(func.count())
                .select_from(Photo)
                .filter(
                    Photo.race_id == race.id,
                    or_(
                        func.coalesce(Photo.timestamp, Photo.uploaded_at) < pivot_ts,
                        and_(
                            func.coalesce(Photo.timestamp, Photo.uploaded_at) == pivot_ts,
                            Photo.uid <= my_photo.uid,
                        ),
                    ),
                )
                .scalar()
            )
            claimed_photo_rank_by_race[race.id] = int(rank or 0)
    total_users = User.query.count()
    total_races = Race.query.count()
    total_results = Result.query.count()
    # Last race by start_time when available, fallback to created_at
    last_started_race = Race.query.order_by(Race.start_time.desc()).first()
    
    return render_template('index.html', 
                         results=results,
                         all_races=all_races,
                         claimed_race_ids=claimed_race_ids,
                         claimed_photo_rank_by_race=claimed_photo_rank_by_race,
                         total_users=total_users,
                         total_races=total_races,
                         total_results=total_results,
                         last_started_race=last_started_race)

@app.route('/users')
@login_required
@admin_required
def users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/<int:user_id>/role', methods=['POST'])
@login_required
@admin_required
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role not in ['participant', 'organizer', 'admin']:
        flash('Invalid role selected.', 'error')
        return redirect(url_for('users'))

    # Prevent removing the last admin
    admin_count = User.query.filter_by(role='admin').count()
    if user.role == 'admin' and new_role != 'admin' and admin_count <= 1:
        flash('Cannot remove the last admin.', 'error')
        return redirect(url_for('users'))

    user.role = new_role
    db.session.commit()
    flash(f"Updated role for {user.username} to {new_role}.", 'success')
    return redirect(url_for('users'))

@app.route('/races')
@login_required
def races():
    if current_user.is_admin():
        races = Race.query.order_by(Race.start_time.desc()).all()
    elif current_user.is_organizer():
        races = Race.query.filter_by(organizer_id=current_user.id).order_by(Race.start_time.desc()).all()
    else:
        races = Race.query.order_by(Race.start_time.desc()).all()
    # Compute which races have photos uploaded by the current user
    user_photo_race_ids = set(
        r[0] for r in db.session.query(Photo.race_id).filter(Photo.user_id == current_user.id).distinct().all()
    )
    return render_template('races.html', races=races, user_photo_race_ids=user_photo_race_ids)

@app.route('/races/check_ongoing', methods=['GET'])
@login_required
@organizer_required
def check_ongoing_race():
    ongoing = Race.query.filter_by(organizer_id=current_user.id, end_time=None).order_by(Race.start_time.desc()).first()
    if ongoing:
        return jsonify({
            'ongoing': True,
            'race_id': ongoing.id,
            'start_time': ongoing.start_time.isoformat()
        })
    return jsonify({'ongoing': False})

@app.route('/races/start', methods=['POST'])
@login_required
@organizer_required
def start_race():
    force = request.form.get('force') == '1'
    now = datetime.utcnow()
    ongoing = Race.query.filter_by(organizer_id=current_user.id, end_time=None).order_by(Race.start_time.desc()).first()
    if ongoing and not force:
        # Signal client a race is ongoing
        return jsonify({'error': 'Race already ongoing', 'ongoing': True, 'race_id': ongoing.id}), 409

    if ongoing and force:
        ongoing.end_time = now
        db.session.add(ongoing)
        db.session.commit()

    # Create a new minimal race entry; name/location optional, distance default 0
    race = Race(
        name=request.form.get('name') or f"Race {now.strftime('%Y-%m-%d %H:%M:%S')}",
        distance=float(request.form.get('distance') or 0),
        date=now.date(),
        location=request.form.get('location'),
        organizer_id=current_user.id,
        start_time=now,
        end_time=None
    )
    db.session.add(race)
    db.session.commit()
    return jsonify({'ok': True, 'race_id': race.id, 'start_time': race.start_time.isoformat()})

@app.route('/races/add', methods=['GET', 'POST'])
@login_required
@organizer_required
def add_race():
    if request.method == 'POST':
        race = Race(
            name=request.form['name'],
            distance=float(request.form['distance']),
            date=datetime.strptime(request.form['date'], '%Y-%m-%d').date(),
            location=request.form['location'],
            organizer_id=current_user.id
        )
        db.session.add(race)
        db.session.commit()
        flash('Race created successfully!', 'success')
        return redirect(url_for('races'))
    return render_template('add_race.html')

@app.route('/results')
@login_required
def results():
    if current_user.is_admin():
        results = (
            Result.query
            .join(Race, Result.race_id == Race.id)
            .order_by(Race.start_time.desc(), Result.created_at.desc())
            .all()
        )
    elif current_user.is_organizer():
        # Show results for races organized by this user
        organized_race_ids = [race.id for race in current_user.organized_races]
        results = (
            Result.query
            .join(Race, Result.race_id == Race.id)
            .filter(Result.race_id.in_(organized_race_ids))
            .order_by(Race.start_time.desc(), Result.created_at.desc())
            .all()
        )
    else:
        # Show only participant's own results
        results = (
            Result.query
            .join(Race, Result.race_id == Race.id)
            .filter(Result.participant_id == current_user.id)
            .order_by(Race.start_time.desc(), Result.created_at.desc())
            .all()
        )
    # Races where the current user has claimed a photo, ordered by most recent race date
    claimed_race_ids_subq = (
        db.session.query(Photo.race_id)
        .filter(Photo.user_id == current_user.id)
        .distinct()
        .subquery()
    )
    claimed_races = (
        Race.query
        .filter(Race.id.in_(claimed_race_ids_subq))
        .order_by(Race.start_time.desc())
        .all()
    )
    # All races ordered by most recent start_time first
    all_races = Race.query.order_by(Race.start_time.desc()).all()
    # Set of claimed race ids for quick lookup in template
    claimed_race_ids = {r.id for r in claimed_races}
    # Compute rank of the current user's claimed photo within each race, using the same ordering
    # as the race photos page: ORDER BY COALESCE(timestamp, uploaded_at) ASC, uid ASC
    claimed_photo_rank_by_race: dict[int, int] = {}
    for race in claimed_races:
        # Get the user's claimed photo for this race (there should be at most one)
        my_photo = (
            Photo.query
            .filter_by(race_id=race.id, user_id=current_user.id)
            .order_by(Photo.uid.asc())
            .first()
        )
        if not my_photo:
            continue
        pivot_ts = my_photo.timestamp or my_photo.uploaded_at
        # Count how many photos come before or equal to this one in the defined ordering
        rank = (
            db.session.query(func.count())
            .select_from(Photo)
            .filter(
                Photo.race_id == race.id,
                or_(
                    func.coalesce(Photo.timestamp, Photo.uploaded_at) < pivot_ts,
                    and_(
                        func.coalesce(Photo.timestamp, Photo.uploaded_at) == pivot_ts,
                        Photo.uid <= my_photo.uid,
                    ),
                ),
            )
            .scalar()
        )
        claimed_photo_rank_by_race[race.id] = int(rank or 0)
    return render_template(
        'results.html',
        results=results,
        claimed_races=claimed_races,
        claimed_photo_rank_by_race=claimed_photo_rank_by_race,
        all_races=all_races,
        claimed_race_ids=claimed_race_ids,
    )

@app.route('/results/add', methods=['GET', 'POST'])
@login_required
@organizer_required
def add_result():
    if request.method == 'POST':
        # Convert time format (HH:MM:SS) to seconds
        time_str = request.form['finish_time']
        time_parts = time_str.split(':')
        finish_time_seconds = int(time_parts[0]) * 3600 + int(time_parts[1]) * 60 + int(time_parts[2])
        
        # Calculate pace (minutes per km)
        race = Race.query.get(request.form['race_id'])
        pace = (finish_time_seconds / 60) / race.distance
        
        result = Result(
            participant_id=int(request.form['participant_id']),
            race_id=int(request.form['race_id']),
            finish_time=finish_time_seconds,
            position=int(request.form['position']) if request.form['position'] else None,
            pace=pace
        )
        db.session.add(result)
        db.session.commit()
        flash('Result recorded successfully!', 'success')
        return redirect(url_for('results'))
    
    # Get participants and races based on user role
    if current_user.is_admin():
        participants = User.query.filter_by(role='participant').all()
        races = Race.query.all()
    else:  # organizer
        participants = User.query.filter_by(role='participant').all()
        races = Race.query.filter_by(organizer_id=current_user.id).all()
    
    return render_template('add_result.html', participants=participants, races=races)

def _ensure_upload_dir(path: str):
    os.makedirs(path, exist_ok=True)

def _allowed_file(filename: str) -> bool:
    # Include common mobile formats (HEIC/HEIF/AVIF) even if EXIF parsing may be limited
    allowed = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.heic', '.heif', '.avif', '.bmp', '.tif', '.tiff'}
    ext = os.path.splitext(filename)[1].lower()
    return ext in allowed

def _extract_exif_timestamp(file_path: str):
    try:
        with Image.open(file_path) as img:
            exif = img.getexif()
            if not exif:
                return None
            # Map EXIF tag names
            tags = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
            
            # Check for timezone offset fields (EXIF v2.31)
            timezone_offset = None
            for offset_key in ("OffsetTimeOriginal", "OffsetTimeDigitized", "OffsetTime"):
                if offset_key in tags and isinstance(tags[offset_key], str):
                    try:
                        # Format: ±HH:MM (e.g., "+02:00")
                        offset_str = tags[offset_key]
                        if len(offset_str) == 6 and offset_str[3] == ':':
                            hours = int(offset_str[1:3])
                            minutes = int(offset_str[4:6])
                            sign = 1 if offset_str[0] == '+' else -1
                            timezone_offset = sign * (hours * 60 + minutes)  # minutes from UTC
                            break
                    except Exception:
                        continue
            
            # Extract timestamp
            for key in ("DateTimeOriginal", "DateTimeDigitized", "DateTime"):
                if key in tags and isinstance(tags[key], str):
                    dt_str = tags[key]
                    try:
                        # EXIF format: YYYY:MM:DD HH:MM:SS
                        naive_dt = datetime.strptime(dt_str, "%Y:%m:%d %H:%M:%S")
                        
                        if timezone_offset is not None:
                            # Convert from photo's timezone to UTC
                            utc_dt = naive_dt - timedelta(minutes=timezone_offset)
                            return utc_dt
                        else:
                            # No timezone info - assume Paris timezone and convert to UTC
                            paris_dt = naive_dt.replace(tzinfo=PARIS_TZ)
                            return paris_dt.astimezone(UTC_TZ).replace(tzinfo=None)
                    except Exception:
                        continue
    except Exception:
        return None
    return None

@app.route('/races/<int:race_id>/photos/upload', methods=['GET', 'POST'])
@login_required
@organizer_required
def upload_race_photos(race_id):
    race = Race.query.get_or_404(race_id)
    # Only owner organizer or admin can upload
    if not (current_user.is_admin() or race.organizer_id == current_user.id):
        flash('You do not have permission to upload photos for this race.', 'error')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        files = request.files.getlist('photos')
        if not files or all(f.filename == '' for f in files):
            flash('Please select at least one image to upload.', 'error')
            return redirect(request.url)
        dest_dir = os.path.join(app.config['UPLOAD_FOLDER'], f'race_{race.id}')
        _ensure_upload_dir(dest_dir)
        saved = 0
        for f in files:
            if not f:
                continue
            if not _allowed_file(f.filename):
                app.logger.info(f"Skipped unsupported file type: {f.filename}")
                continue
            try:
                fname = secure_filename(f.filename)
                # Avoid overwriting existing files
                full = os.path.join(dest_dir, fname)
                base, ext = os.path.splitext(fname)
                i = 1
                while os.path.exists(full):
                    fname = f"{base}_{i}{ext}"
                    full = os.path.join(dest_dir, fname)
                    i += 1
                f.save(full)
                saved += 1
                # Extract EXIF timestamp or fallback to file mtime
                ts = _extract_exif_timestamp(full)
                if ts is None:
                    try:
                        ts = datetime.utcfromtimestamp(os.path.getmtime(full))
                    except Exception:
                        ts = None
                # If file is HEIC/HEIF/AVIF, convert to JPEG for browser compatibility
                ext_lower = os.path.splitext(fname)[1].lower()
                if ext_lower in {'.heic', '.heif', '.avif'}:
                    try:
                        with Image.open(full) as img:
                            if img.mode in ('RGBA', 'P'):
                                img = img.convert('RGB')
                            # Determine a non-conflicting JPEG filename
                            jpg_name = base + '.jpg'
                            jpg_full = os.path.join(dest_dir, jpg_name)
                            j = 1
                            while os.path.exists(jpg_full):
                                jpg_name = f"{base}_{j}.jpg"
                                jpg_full = os.path.join(dest_dir, jpg_name)
                                j += 1
                            img.save(jpg_full, format='JPEG', quality=90)
                            # Prefer storing the JPEG filename for web display
                            fname = jpg_name
                            full = jpg_full
                    except Exception as conv_err:
                        app.logger.warning(f"HEIC/AVIF conversion failed for {fname}: {conv_err}")
                # Record photo in DB
                photo = Photo(
                    race_id=race.id,
                    file_name=fname,
                    timestamp=ts
                )
                db.session.add(photo)
            except Exception as e:
                app.logger.exception(f"Failed to process file {f.filename}: {e}")
        if saved:
            db.session.commit()
            flash(f'Uploaded {saved} photo(s) to race "{race.name}".', 'success')
            return redirect(url_for('profile'))
        else:
            flash('No valid image files were uploaded.', 'error')
            return redirect(request.url)

    # GET
    # Ensure base upload directory exists so template can hint the path
    _ensure_upload_dir(app.config['UPLOAD_FOLDER'])
    return render_template('upload_photos.html', race=race)

@app.route('/uploads/races/<int:race_id>/<path:filename>')
@login_required
def serve_race_upload(race_id, filename):
    # Serve uploaded images from instance/uploads/race_<id>/ safely
    directory = os.path.join(app.config['UPLOAD_FOLDER'], f'race_{race_id}')
    return send_from_directory(directory, filename, as_attachment=False)

@app.route('/races/<int:race_id>/photos/mine')
@login_required
def my_race_photos(race_id):
    race = Race.query.get_or_404(race_id)
    # Order by earliest first, using uploaded_at when timestamp is missing
    photos = (
        Photo.query
        .filter_by(race_id=race_id)
        .order_by(func.coalesce(Photo.timestamp, Photo.uploaded_at).asc(), Photo.uid.asc())
        .all()
    )
    # Map user_id -> name for labels of claimed photos
    user_ids = sorted({p.user_id for p in photos if p.user_id is not None})
    users = User.query.filter(User.id.in_(user_ids)).all() if user_ids else []
    user_name_by_id = {u.id: u.name for u in users}
    return render_template('race_photos.html', race=race, photos=photos, user_name_by_id=user_name_by_id)

@app.route('/races/<int:race_id>/photos/view/<path:filename>')
@login_required
def view_race_photo(race_id, filename):
    # Serve images, converting HEIC/HEIF/AVIF to JPEG on the fly for browser compatibility
    directory = os.path.join(app.config['UPLOAD_FOLDER'], f'race_{race_id}')
    full = os.path.join(directory, filename)
    ext = os.path.splitext(filename)[1].lower()
    convertible = {'.heic', '.heif', '.avif'}
    if ext not in convertible:
        # For common web formats, reuse existing static-serving route
        return send_from_directory(directory, filename, as_attachment=False)
    # Convert to JPEG in-memory
    try:
        with Image.open(full) as img:
            if img.mode in ('RGBA', 'P'):  # ensure compatible mode
                img = img.convert('RGB')
            buf = io.BytesIO()
            img.save(buf, format='JPEG', quality=90)
            buf.seek(0)
            return send_file(buf, mimetype='image/jpeg', download_name=os.path.splitext(filename)[0] + '.jpg')
    except Exception:
        # If conversion fails, fall back to raw file (may not render in browser)
        return send_from_directory(directory, filename, as_attachment=False)

@app.route('/races/<int:race_id>/find-me', methods=['GET', 'POST'])
@login_required
def find_me(race_id):
    race = Race.query.get_or_404(race_id)
    if request.method == 'POST':
        photo_uid = request.form.get('photo_uid')
        try:
            uid_int = int(photo_uid)
        except (TypeError, ValueError):
            flash('Invalid photo selected.', 'error')
            return redirect(url_for('find_me', race_id=race_id))
        photo = Photo.query.filter_by(uid=uid_int, race_id=race_id).first()
        if not photo:
            flash('Photo not found for this race.', 'error')
            return redirect(url_for('find_me', race_id=race_id))
        # If the selected photo is already claimed by another user, block
        if photo.user_id and photo.user_id != current_user.id:
            flash('This photo is already claimed by another user.', 'error')
            return redirect(url_for('find_me', race_id=race_id))
        # Unclaim any existing photo(s) in this race linked to the current user
        existing_linked = Photo.query.filter_by(race_id=race_id, user_id=current_user.id).all()
        for p in existing_linked:
            if p.uid != photo.uid:
                p.user_id = None
                db.session.add(p)
        # Assign the current user to the newly selected photo
        photo.user_id = current_user.id
        db.session.add(photo)
        db.session.commit()
        if existing_linked and any(p.uid != photo.uid for p in existing_linked):
            flash('Replaced your previously linked photo with the new selection.', 'success')
        else:
            flash('Photo linked to your profile.', 'success')
        return redirect(url_for('find_me', race_id=race_id))

    photos = Photo.query.filter_by(race_id=race_id).order_by(Photo.timestamp.asc(), Photo.uid.asc()).all()
    return render_template('find_me.html', race=race, photos=photos)

@app.route('/profile')
@login_required
def profile():
    if current_user.is_participant():
        results = Result.query.filter_by(participant_id=current_user.id).order_by(Result.created_at.desc()).all()
        return render_template('participant_profile.html', user=current_user, results=results)
    elif current_user.is_organizer():
        organized_races = Race.query.filter_by(organizer_id=current_user.id).order_by(Race.date.desc()).all()
        return render_template('organizer_profile.html', user=current_user, races=organized_races)
    else:  # admin
        return render_template('admin_profile.html', user=current_user)

# Legacy routes removed: Runner model deprecated; results are tied to Users (participants).

@app.route('/api/stats')
def api_stats():
    stats = {
        'total_runners': User.query.filter_by(role='participant').count(),
        'total_races': Race.query.count(),
        'total_results': Result.query.count(),
        'avg_pace': db.session.query(db.func.avg(Result.pace)).scalar() or 0
    }
    return jsonify(stats)

@app.route('/health')
def health_check():
    """Lightweight health check endpoint for keep-alive pings."""
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})

# Utility functions
def format_time(seconds):
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

def format_pace(pace_minutes):
    minutes = int(pace_minutes)
    seconds = int((pace_minutes - minutes) * 60)
    return f"{minutes}:{seconds:02d}"

# Template filters
app.jinja_env.filters['format_time'] = format_time
app.jinja_env.filters['format_pace'] = format_pace

# Timezone helpers (display Europe/Paris)
PARIS_TZ = ZoneInfo("Europe/Paris")
UTC_TZ = ZoneInfo("UTC")

def to_paris(dt: datetime) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        # Treat naive timestamps as UTC (we store with datetime.utcnow)
        dt = dt.replace(tzinfo=UTC_TZ)
    return dt.astimezone(PARIS_TZ)

def format_dt_paris(dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S %Z") -> str:
    dtp = to_paris(dt)
    return dtp.strftime(fmt) if dtp else ""

app.jinja_env.filters['format_dt_paris'] = format_dt_paris

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    # Triggered when request exceeds MAX_CONTENT_LENGTH
    flash('Upload too large. Max total size per request is 64 MB.', 'error')
    # Redirect back to the referring page if available
    return redirect(request.referrer or url_for('profile')), 413

# Delta formatting: format difference between two datetimes as HH:MM:SS.ms
def since_filter(value_dt: datetime | None, start_dt: datetime | None) -> str:
    try:
        if value_dt is None or start_dt is None:
            return ""
        delta = value_dt - start_dt
        neg = delta.total_seconds() < 0
        total_ms = int(abs(delta.total_seconds()) * 1000)
        hours = total_ms // 3_600_000
        rem = total_ms % 3_600_000
        minutes = rem // 60_000
        rem = rem % 60_000
        seconds = rem // 1000
        ms = rem % 1000
        prefix = '-' if neg else ''
        return f"{prefix}{hours:02d}:{minutes:02d}:{seconds:02d}.{ms:03d}"
    except Exception:
        return ""

app.jinja_env.filters['since'] = since_filter

@app.context_processor
def inject_last_race():
    try:
        last_started_race = Race.query.order_by(Race.start_time.desc()).first()
    except Exception:
        last_started_race = None
    # Provide a display-ready string without timezone label
    display = format_dt_paris(last_started_race.start_time, '%Y-%m-%d %H:%M:%S') if last_started_race else None
    return {
        'nav_last_started_race': last_started_race,
        'nav_last_race_display': display,
    }

if __name__ == '__main__':
    with app.app_context():
        # Use the same schema-aware initialization as production
        if not _check_db_schema_exists():
            db.create_all()
        
        # Create a default admin user if none exists
        if not User.query.filter_by(role='admin').first():
            default_admin = User(
                username='admin',
                email='admin@barkrun.local',
                name='Administrator',
                role='admin'
            )
            default_admin.set_password('admin123')
            db.session.add(default_admin)
            db.session.commit()
    app.run(debug=True)

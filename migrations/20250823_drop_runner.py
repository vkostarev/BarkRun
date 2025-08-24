import os
from datetime import datetime

import sys

# Ensure project root is on sys.path so we can import app.py when running this script from migrations/
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app as flask_app, db, User, Runner, Result
from sqlalchemy import text


def ensure_backup():
    inst_dir = os.path.join(os.path.dirname(__file__), '..', 'instance')
    inst_dir = os.path.abspath(inst_dir)
    db_path = os.path.join(inst_dir, 'barkrun.db')
    if not os.path.exists(db_path):
        print(f"No database found at {db_path}. Nothing to back up.")
        return None
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = os.path.join(inst_dir, f'barkrun_backup_{ts}.db')
    with open(db_path, 'rb') as src, open(backup_path, 'wb') as dst:
        dst.write(src.read())
    print(f"Backup created: {backup_path}")
    return backup_path


def migrate_runner_results_to_users():
    moved = 0
    created_users = 0
    for res in Result.query.filter(Result.participant_id.is_(None)).filter(Result.runner_id.isnot(None)).all():
        runner = Runner.query.get(res.runner_id)
        if not runner:
            continue
        user = None
        if runner.email:
            user = User.query.filter_by(email=runner.email).first()
        if not user:
            # Create a participant user
            username_base = (runner.name or 'runner').lower().replace(' ', '') or 'runner'
            candidate = username_base
            suffix = 1
            while User.query.filter_by(username=candidate).first():
                suffix += 1
                candidate = f"{username_base}{suffix}"
            user = User(
                username=candidate,
                email=runner.email or f"{candidate}@local",
                name=runner.name or candidate,
                role='participant',
                age=runner.age,
                gender=runner.gender,
            )
            # Set a default password; ops can reset later
            user.set_password('changeme123')
            db.session.add(user)
            db.session.flush()  # get user.id
            created_users += 1
        res.participant_id = user.id
        moved += 1
    db.session.commit()
    print(f"Results updated: {moved}, Users created: {created_users}")


def drop_runner_and_column():
    # Use raw SQL to rebuild result table without runner_id and drop runner table
    engine = db.engine
    with engine.begin() as conn:
        conn.execute(text('PRAGMA foreign_keys=OFF;'))
        # Determine if result table exists
        tbls = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table';")).fetchall()
        tbl_names = {t[0] for t in tbls}
        if 'result' in tbl_names:
            conn.execute(text(
                """
                CREATE TABLE result_new (
                    id INTEGER NOT NULL, 
                    participant_id INTEGER, 
                    race_id INTEGER NOT NULL, 
                    finish_time INTEGER NOT NULL, 
                    position INTEGER, 
                    pace FLOAT, 
                    created_at DATETIME, 
                    PRIMARY KEY (id),
                    FOREIGN KEY(participant_id) REFERENCES user (id),
                    FOREIGN KEY(race_id) REFERENCES race (id)
                );
                """
            ))
            conn.execute(text(
                """
                INSERT INTO result_new (id, participant_id, race_id, finish_time, position, pace, created_at)
                SELECT id, participant_id, race_id, finish_time, position, pace, created_at FROM result;
                """
            ))
            conn.execute(text("DROP TABLE result;"))
            conn.execute(text("ALTER TABLE result_new RENAME TO result;"))
            print("Rebuilt 'result' table without runner_id")
        if 'runner' in tbl_names:
            conn.execute(text("DROP TABLE runner;"))
            print("Dropped 'runner' table")
        conn.execute(text('PRAGMA foreign_keys=ON;'))


if __name__ == '__main__':
    # All ORM access requires an application context
    with flask_app.app_context():
        ensure_backup()
        migrate_runner_results_to_users()
        drop_runner_and_column()
        print("Migration completed successfully.")

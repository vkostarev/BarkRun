from app import app, db
from sqlalchemy import text

"""
This migration makes the column photo.user nullable in SQLite by rebuilding the table.
Safe to run multiple times; it checks the current schema first.
"""

DDL = (
    "PRAGMA foreign_keys=off;\n"
    "BEGIN TRANSACTION;\n"
    "CREATE TABLE photo_new (\n"
    "    uid INTEGER NOT NULL,\n"
    "    race_id INTEGER NOT NULL,\n"
    "    \"user\" INTEGER NULL,\n"
    "    file_name VARCHAR(255) NOT NULL,\n"
    "    timestamp DATETIME NULL,\n"
    "    uploaded_at DATETIME NULL,\n"
    "    PRIMARY KEY (uid),\n"
    "    FOREIGN KEY(race_id) REFERENCES race (id),\n"
    "    FOREIGN KEY(\"user\") REFERENCES user (id)\n"
    ");\n"
    "INSERT INTO photo_new (uid, race_id, \"user\", file_name, timestamp, uploaded_at)\n"
    "SELECT uid, race_id, \"user\", file_name, timestamp, uploaded_at FROM photo;\n"
    "DROP TABLE photo;\n"
    "ALTER TABLE photo_new RENAME TO photo;\n"
    "COMMIT;\n"
    "PRAGMA foreign_keys=on;\n"
)

with app.app_context():
    eng = db.engine  # SQLAlchemy engine
    with eng.connect() as conn:
        # Check current nullability
        info = conn.execute(text('PRAGMA table_info(photo)')).all()
        by_name = {row[1]: row for row in info}
        user_col = by_name.get('user')
        if not user_col:
            print("photo table not found or column 'user' missing; nothing to do.")
        else:
            notnull_flag = user_col[3]  # 1 => NOT NULL, 0 => NULL allowed
            if notnull_flag == 0:
                print("Column photo.user is already NULLABLE; no changes made.")
            else:
                print("Rebuilding 'photo' table to make column 'user' NULLABLE...")
                conn.exec_driver_sql(DDL)
                print("Done. Column photo.user is now NULLABLE.")

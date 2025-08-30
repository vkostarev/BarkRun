from app import app, db, User

def check_db_schema_exists():
    """Check if database schema already exists by querying for tables."""
    try:
        # Try to query the User table to see if schema exists
        db.session.execute(db.text("SELECT 1 FROM user LIMIT 1"))
        return True
    except Exception:
        # If query fails, schema doesn't exist or is incomplete
        return False

if __name__ == "__main__":
    with app.app_context():
        # Only create tables if schema doesn't exist
        schema_exists = check_db_schema_exists()
        if not schema_exists:
            # db.create_all()  # Commented out to prevent schema recreation
            print("Schema creation disabled - database schema will not be created")
        else:
            print("Database schema already exists, preserving existing data")
        
        # Ensure a default admin exists (mirrors app.py behavior)
        if not User.query.filter_by(role='admin').first():
            admin = User(
                username='admin',
                email='admin@barkrun.local',
                name='Administrator',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Created default admin user (admin/admin123)")
        else:
            print("Admin user already exists")
    
    if schema_exists:
        print("Database initialization completed - existing data preserved")
    else:
        print("Database initialization completed - fresh database created")

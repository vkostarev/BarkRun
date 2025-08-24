from app import app, db, User

if __name__ == "__main__":
    with app.app_context():
        # Create all tables
        db.create_all()
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
    print("Initialized fresh barkrun.db with default admin (admin/admin123)")

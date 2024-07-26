from app import app, db

print("Starting database initialization...")

with app.app_context():
    print("Inside app context")
    try:
        db.create_all()
        print("Database tables created successfully.")
    except Exception as e:
        print(f"Error creating database tables: {e}")

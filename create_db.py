from app import db, app

with app.app_context():
    # Create the database and tables
    db.create_all()
    print("Database created successfully!") 
from app import app, db, Employee

def create_admin_user():
    with app.app_context():
        # Check if admin already exists
        admin = Employee.query.filter_by(employee_id='ADMIN001').first()
        if not admin:
            admin = Employee(
                employee_id='ADMIN001',
                name='Admin User',
                email='admin@example.com',
                password='admin123',
                department='Administration',
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
            print("Employee ID: ADMIN001")
            print("Password: admin123")
        else:
            print("Admin user already exists!")
            print("Employee ID: ADMIN001")
            print("Password: admin123")

if __name__ == '__main__':
    create_admin_user() 
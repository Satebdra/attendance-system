from app import db

def upgrade():
    # Add base_salary column to Employee table
    with db.engine.connect() as conn:
        conn.execute('ALTER TABLE employee ADD COLUMN base_salary FLOAT DEFAULT 0.0')
        conn.commit()

def downgrade():
    # Remove base_salary column from Employee table
    with db.engine.connect() as conn:
        conn.execute('ALTER TABLE employee DROP COLUMN base_salary')
        conn.commit()

if __name__ == '__main__':
    from app import app
    with app.app_context():
        upgrade() 
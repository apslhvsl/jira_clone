from flask import Blueprint, request
from database import reset_and_seed_db

setup_bp = Blueprint('setup', __name__)

@setup_bp.route('/reset-demo-db', methods=['GET'])
def reset_demo_db():
    token = request.args.get('token')
    if token != 'SECRET123':
        return {"error": "Unauthorized"}, 403

    reset_and_seed_db()
    return {"message": "✅ Demo database reset and seeded"}, 200

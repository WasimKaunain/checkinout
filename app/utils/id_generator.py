from sqlalchemy import text

def generate_custom_user_id(user_type):
    from app import db
    from app.models import UserIDCounter

    prefix_map = {
        'Student': 'S',
        'Staff': 'ST',
        'Visitor': 'V'
    }
    if user_type not in prefix_map:
        raise ValueError("Invalid user type for ID generation")

    prefix = prefix_map[user_type]

    # Lock row to prevent race conditions
    result = db.session.execute(
        text("SELECT current_number FROM user_id_counters WHERE user_type = :type FOR UPDATE"),
        {"type": user_type}
    ).first()

    if not result:
        raise Exception("User type not found in user_id_counters")

    current_number = result[0]
    new_number = current_number + 1
    new_user_id = f"{prefix}{new_number:05d}"

    # Update counter
    db.session.execute(
        text("UPDATE user_id_counters SET current_number = :new_number WHERE user_type = :type"),
        {"new_number": new_number, "type": user_type}
    )

    return new_user_id

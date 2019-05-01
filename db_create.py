from app import db
from app.models import Card, Customer, Comment, Payment, UtilityBill

db.create_all()

print("DB Created")
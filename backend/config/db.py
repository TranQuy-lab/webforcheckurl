from mongoengine import connect, get_connection
from dotenv import load_dotenv
import os

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")

# Kết nối MongoDB Atlas
connect(alias="default", host=MONGODB_URI)

# Kiểm tra thử kết nối
try:
    conn = get_connection()
    print("✅ MongoEngine đã kết nối thành công tới MongoDB Atlas!")
except Exception as e:
    print("❌ Lỗi kết nối MongoDB:", e)

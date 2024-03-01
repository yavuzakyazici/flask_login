from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Integer, String
from app import db

class User(db.Model):
    __tablename__ = "users"

    UserId: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    FullName:Mapped[str] = mapped_column(String(40), nullable=True)
    Email:Mapped[str] = mapped_column(String(50), unique=True, index=False)
    UserPassword:Mapped[str] = mapped_column(String(255))

    def __str__(self):
        return self.Email
    
    @property
    def serialize(self):
        return {
            "UserId": self.UserId,
            "FullName": self.FullName,
            "Email": self.Email,
        }



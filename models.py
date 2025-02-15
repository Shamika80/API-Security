from sqlalchemy import Column, Integer, String
from sqlalchemy import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String,   
 unique=True, nullable=False)
    password = Column(String, nullable=False) 
    role = Column(String, nullable=False)   


    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"

    def check_password(self, password):
        pass  
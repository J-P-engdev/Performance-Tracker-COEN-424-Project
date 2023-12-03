from pydantic import BaseModel, Field
from .AppModels import Category
from typing import Dict

class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None
    categories: Dict[str, Category] = Field(default={})

class SignupData(BaseModel):
    username: str
    email: str
    password: str
    full_name: str

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
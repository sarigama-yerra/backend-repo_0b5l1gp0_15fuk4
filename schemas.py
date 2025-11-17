"""
Database Schemas for the SaaS app

Each Pydantic model represents a collection in MongoDB.
Class name lowercased = collection name (e.g., User -> "user").
"""

from typing import Optional, List, Literal
from pydantic import BaseModel, Field, EmailStr

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user"
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="Password hash (bcrypt)")
    role: Literal["admin", "manager", "user"] = Field("user", description="Role for RBAC")
    avatar_url: Optional[str] = Field(None, description="Avatar image URL")
    is_active: bool = Field(True, description="Whether the user is active")
    reset_token: Optional[str] = Field(None, description="Password reset token (short-lived)")

class Metric(BaseModel):
    """
    Simple metrics collection for dashboard examples
    Collection name: "metric"
    """
    key: str
    value: float
    label: Optional[str] = None

class Notification(BaseModel):
    """
    Notifications delivered to users
    Collection name: "notification"
    """
    user_id: str
    title: str
    message: str
    type: Literal["info", "success", "warning", "error"] = "info"
    is_read: bool = False

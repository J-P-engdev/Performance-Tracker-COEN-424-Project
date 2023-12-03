from Models.AuthModels import *
from datetime import datetime
from typing import Dict

#Example: studied 2 hours for final exam
class Worklog(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    name: str    # Must be unique otherwise it will replace existing objects
    duration: float
    location: str

#Example: Final exam, assignmnent 1
class Workload(BaseModel):
    name: str
    type: str #ex: assignment, midterm, final, etc...
    deadline: datetime
    result : int    # Results should be out of 100
    worklogs: Dict[str, Worklog] = Field(default={})

#Activity: COEN424, COEN490
class Activity(BaseModel):
    name: str
    description: str
    workloads: Dict[str, Workload] = Field(default={})

#Example: School, Work, Sports
class Category(BaseModel):
    Name: str = Field(...)
    activities: Dict[str, Activity] = Field(default={})

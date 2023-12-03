from bson import ObjectId
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pymongo import MongoClient
from Models.AppModels import *
from Models.AuthModels import *
from typing import Annotated
from fastapi import Depends, HTTPException, status, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Dict, Union
import boto3
import pandas as pd
from bson import json_util
import json
from fastapi import UploadFile, File
import time
import os


s3 = boto3.client('s3',
                    aws_access_key_id = "Secret Key",
                    aws_secret_access_key = "Secret Key"
                  )

aws_access_key_id = 'Secret Key'
aws_secret_access_key = 'Secret Key'
forecast_role_arn = 'Secret Key'

BUCKET_NAME = 'Secret Key'

KB = 1024
MB  = 1024*KB


app = FastAPI()
app.client = MongoClient("Secret Key")
app.db = app.client["COEN424"]
app.collection = app.db["users"]

#Send a ping to confirm a successful connection
try:
    app.client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "Hash key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# S3 Configuration
s3_bucket_name = 'coen424bucket'
s3_prefix = 'worklog_data/'

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    user = app.db["users"].find_one({"username": username})
    if user:
        return UserInDB.model_validate(user)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

@app.post("/api/auth/register")
async def signup(user_data: SignupData):
    collection = app.db["users"]
    # Check if username or email already exists
    existing_user = collection.find_one({"$or": [{"username": user_data.username}, {"email": user_data.email}]})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    # Insert user data into MongoDB
    user = UserInDB(username=user_data.username,email=user_data.email, full_name=user_data.full_name, hashed_password=get_password_hash(user_data.password),)
    collection.insert_one(user.model_dump())
    return {"message": "User signed up successfully"}

@app.post("/api/categories/")
async def PostCategory(category: Category,current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username":current_user.username})
    if document:
        user = User(**document)
        user.categories[category.Name] = category
        result = app.collection.update_one({"_id": ObjectId(document["_id"])}, {"$set": user.model_dump()})
        return {"message": "POST request was successfull."}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/api/categories/")
async def GetAllCategories(current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        return user.categories
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/api/categories/{name}")
async def GetAllCategories(name: str, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        return user.categories[name]
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.put("/api/categories/")
async def UpdateCategory(category: Category, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        user.categories[category.name] = category
        result = app.collection.update_one({"_id": ObjectId(document["_id"])}, {"$set": user.model_dump()})
        return {"message": "PUT request was successfull."}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )
@app.delete("/api/categories/{category_name}")
async def DeleteCategory(category_name: str, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user= User(**document)
        result = user.categories.pop(category_name)
        app.collection.update_one({"_id": ObjectId(document["_id"])}, {"$set": user.model_dump()})
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/api/activities/{category_name}")
async def GetAllCategoryActivities(category_name: str, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        result = user.categories[category_name].activities
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/api/activities/{category_name}/{activity_name}")
async def GetActivity(activity_name:str, category_name:str, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        result = user.categories[category_name].activities[activity_name]
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.post("/api/activities/{category_name}")
async def PostActivity(category_name: str, activity: Activity, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    print(document)
    if document:
        user= User(**document)
        print(user)
        user.categories[category_name].activities[activity.name] = activity
        result = app.collection.update_one({"_id": ObjectId(document["_id"])}, {"$set": user.model_dump()})
        return {"message": "POST request was successfull."}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.put("/api/activities/{category_name}")
async def GetActivity(category_name: str, activity: Activity, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        user.categories[category_name].activities[activity.name] = activity
        result = app.collection.update_one({"_id": ObjectId(document["_id"])}, {"$set": user.model_dump()})
        return {"message": "PUT request was successfull."}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.delete("/api/activities/{category_name}/{activity_name}")
async def DeleteActivity(category_name: str, activity_name: str, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        result = user.categories[category_name].activities.pop(activity_name)
        app.collection.update_one({"_id": ObjectId(document["_id"])}, {"$set": user.model_dump()})
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/api/workloads/{category_name}/{activity_name}")
async def GetAllWorkloads(category_name: str, activity_name: str, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        return user.categories[category_name].activities[activity_name].workloads
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/api/workloads/{category_name}/{activity_name}/{workload_name}")
async def GetWorkload(category_name: str, activity_name: str, workload_name: str, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        return user.categories[category_name].activities[activity_name].workloads[workload_name]
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.post("/api/workloads/{category_name}/{activity_name}")
async def PostWorkload(category_name: str, activity_name: str, workload: Workload, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        user.categories[category_name].activities[activity_name].workloads[workload.name] = workload
        result = app.collection.update_one({"_id": ObjectId(document["_id"])}, {"$set": user.model_dump()})
        return {"message": "POST request was successfull."}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.put("/api/workloads/{category_name}/{activity_name}")
async def UpdateWorkload(category_name: str, activity_name: str, workload: Workload, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        user.categories[category_name].activities[activity_name].workloads[workload.name] = workload
        result = app.collection.update_one({"_id": ObjectId(document["_id"])}, {"$set": user.model_dump()})
        return {"message": "PUT request was successfull."}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.delete("/api/workloads/{category_name}/{activity_name}/{workload_name}")
async def DeleteWorkload(category_name: str, activity_name: str, workload_name: str,current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        result = user.categories[category_name].activities[activity_name].workloads.pop(workload_name)
        app.collection.update_one({"_id": ObjectId(document["_id"])}, {"$set": user.model_dump()})
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/api/worklogs/{category_name}/{activity_name}/{workload_name}")
async def GetAllWorklogs(category_name: str, activity_name: str, workload_name: str,current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        result = user.categories[category_name].activities[activity_name].workloads[workload_name].worklogs
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/api/worklogs/{category_name}/{activity_name}/{workload_name}/{worklog_name}")
async def GetWorklog(category_name: str, activity_name: str, workload_name: str, worklog_name: str,current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        result = user.categories[category_name].activities[activity_name].workloads[workload_name].worklogs[workload_name]
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.post("/api/worklogs/{category_name}/{activity_name}/{workload_name}")
async def PostWorklog(category_name: str, activity_name: str, workload_name: str, worklog: Worklog, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        user.categories[category_name].activities[activity_name].workloads[workload_name].worklogs[worklog.name] = worklog
        result = app.collection.update_one({"_id": ObjectId(document["_id"])}, {"$set": user.model_dump()})
        return {"message": "POST request was successfull."}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.put("/api/worklogs/{category_name}/{activity_name}/{workload_name}")
async def PutWorklog(category_name: str, activity_name: str, workload_name: str, worklog: Worklog, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        worklog.timestamp = datetime.now()
        user = User(**document)
        result = user.categories[category_name].activities[activity_name].workloads[workload_name].worklogs[worklog.name] = worklog
        return {"message": "PUT request was successfull."}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.delete("/api/workloads/{category_name}/{activity_name}/{workload_name}/{worklog_name}")
async def DeleteWorkload(category_name: str, activity_name: str, workload_name: str, worklog_name: str, current_user: Annotated[User, Depends(get_current_active_user)]):
    document = app.collection.find_one({"username": current_user.username})
    if document:
        user = User(**document)
        result = user.categories[category_name].activities[activity_name].workloads[workload_name].pop(worklog_name)
        app.collection.update_one({"_id": ObjectId(document["_id"])}, {"$set": user.model_dump()})
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.post("/api/upload-to-S3")
async def upload(file: UploadFile = File(...)):
    if file:
        print(file.filename)
        s3.upload_fileobj(file.file, BUCKET_NAME, file.filename)
        return "File Uploaded!"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='No File Found!'
        )
    
    contents = await file.read() 

region_name = "us-east-2"

###############################################################################################################

def upload_data_to_forecast(file_path: str):
    forecast = boto3.client('forecast', 
                            aws_access_key_id=aws_access_key_id,
                            aws_secret_access_key=aws_secret_access_key,
                            region_name=region_name)

    # Create a dataset import job
    response = forecast.create_dataset_import_job(
        DatasetImportJobName=f'dataset-import-job-{int(time.time())}',
        DatasetArn=f'arn:aws:forecast:us-east-2:947522399409:dataset-group/my_coen424_forecast_datasetgroup',
        DataSource={
            'S3Config': {
                'Path': f's3://fastapifiles123/{file_path}',
                'RoleArn': forecast_role_arn
            }
        },
        TimestampFormat='yyyy-MM-dd HH:mm:ss'
    )

    import_job_arn = response['DatasetImportJobArn']
    print(f'Import job ARN: {import_job_arn}')

    while True:
        status = forecast.describe_dataset_import_job(DatasetImportJobArn=import_job_arn)['Status']
        print(f'Import job status: {status}')
        if status in ['ACTIVE', 'CREATE_FAILED']:
            break
        time.sleep(60)


@app.post("/uploadfile/")
async def create_upload_file(file: UploadFile = File(...)):
    try:

        with open(file.filename, "wb") as f:
            f.write(file.file.read())
        

        upload_data_to_forecast(file.filename)


        return JSONResponse(content={"message": "File uploaded successfully"}, status_code=200)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:

        if os.path.exists(file.filename):
            os.remove(file.filename)


@app.get("/get-forecast/")
async def get_forecast():
    try:
        forecast = boto3.client('forecast', 
                                aws_access_key_id=aws_access_key_id,
                                aws_secret_access_key=aws_secret_access_key,
                                region_name=region_name)


        response = forecast.create_forecast(
            ForecastName=f'forecast_job_1',
            PredictorArn=f'arn:aws:forecast:us-east-2:947522399409:predictor/my_worklog_predictor_01HGH8S92SD7P8YNFBG0F6DP1A'
        )

        forecast_arn = response['ForecastArn']
        print(f'Forecast ARN: {forecast_arn}')


        while True:
            status = forecast.describe_forecast(ForecastArn=forecast_arn)['Status']
            print(f'Forecast status: {status}')
            if status in ['ACTIVE', 'CREATE_FAILED']:
                break
            time.sleep(60)

        return JSONResponse(content={"message": "Forecast created successfully."}, status_code=200)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

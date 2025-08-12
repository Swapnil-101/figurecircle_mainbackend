from flask import Flask, request, jsonify, redirect, url_for
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Column, Integer, String, ForeignKey, Text, DateTime, Boolean,UniqueConstraint,Date, func, or_
from sqlalchemy import create_engine, and_, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy import Table, ForeignKey
from sqlalchemy.exc import IntegrityError
from flask_mail import Mail, Message
from oauthlib.oauth2 import WebApplicationClient
import requests
import json
import os
from dotenv import load_dotenv
from sqlalchemy import LargeBinary,JSON
import base64
from datetime import datetime
from flask_socketio import emit
from flask_socketio import SocketIO
from flask_socketio import join_room
from sqlalchemy.dialects.postgresql import JSONB
import stripe
import razorpay
from razorpay import Client
from datetime import datetime, timedelta
from fuzzywuzzy import process
from flasgger import Swagger
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy import PickleType

CALENDLY_API_KEY = '5LMFYDPIVF5ADVOCQYFW437GGWJZOSDT'



load_dotenv()

connection_string = "postgresql://neondb_owner:Pl8cWUu0iLHn@ep-tiny-haze-a1w7wrrg.ap-southeast-1.aws.neon.tech/figure_circle"


engine = create_engine(connection_string,connect_args={'connect_timeout': 10})

Base = declarative_base()

user_mentor_association = Table('user_mentor_association', Base.metadata,
                                Column('user_id', Integer, ForeignKey('users.id')),
                                Column('mentor_id', Integer, ForeignKey('mentors.id'))
                                )
                                
razorpay_client = razorpay.Client(auth=("rzp_test_D4OC2CLZNTebD7", "jMZ25X4tiMwrtmYIXxDGPVbb"))

class Admin(Base):
    __tablename__ = 'admins'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)


class Stream(Base):
    __tablename__ = 'streams'

    name = Column(String, primary_key=True, nullable=False)

class Degree(Base):
    __tablename__ = 'degrees'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    courses = Column(Text, nullable=True) 
    competitions = Column(Text, nullable=True) 
    certifications = Column(Text, nullable=True)


#new assign mentor
class UserMentorAssignment(Base):
    __tablename__ = 'user_mentor_assignments'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    mentor_id = Column(Integer, ForeignKey('Newmentortable.mentor_id', ondelete='CASCADE'), nullable=False)
    assigned_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint('user_id', 'mentor_id', name='_user_mentor_uc'),)

    # Relationships (optional)
    user = relationship('User', back_populates='assignments')
    mentor = relationship('Newmentor', back_populates='assignments') 
    
#new basic info table
class BasicInfo(Base):
    __tablename__ = 'basic_info'

    id = Column(Integer, primary_key=True)
    emailid = Column(String(255), nullable=False)
    useruniqid = Column(String(100), nullable=False)
    firstname = Column(String(100))
    lastname = Column(String(100))
    high_education = Column(String(150))
    interested_stream = Column(String(150))
    data_filed = Column(Boolean, default=False)
    role_based = Column(String(150))
    work_experience = Column(String(255), nullable=True)

# new mentor table
class Newmentor(Base):
    __tablename__ = 'Newmentortable'

    mentor_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, unique=True)
    phone = Column(String(20))
    linkedin = Column(String(255), nullable=False)
    work_experience = Column(String(255), nullable=False)
    current_role = Column(String(255), nullable=False)
    interested_field = Column(String(255), nullable=False)
    expertise = Column(String(255), nullable=False)
    degree = Column(String(255), nullable=False)
    background = Column(Text, nullable=False)
    fee = Column(String(255))
    milestones = Column(Integer, nullable=False)
    profile_picture = Column(String(500))
    resume = Column(String(500))
    availability = Column(JSON)  # New column to store availability as JSON
    created_at = Column(DateTime, default=datetime.utcnow)
    current_role = Column('current_role', None)
    assignments = relationship('UserMentorAssignment', back_populates='mentor')

class Review(Base):
    __tablename__ = 'Review'

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(Date)
    ReviewIndetail = Column(String)
    userDetails = Column(JSON)
    valid = Column(Boolean)

#contact us table
class ContactUs(Base):
    __tablename__ = 'ContactUs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    fullname = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    phone_number = Column(String(20), nullable=True)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
class Information(Base):
    __tablename__ = 'information'

    id = Column(Integer, primary_key=True, autoincrement=True)  # Add this line
    primary_expertise_area = Column(String(255), nullable=True)
    highest_degree_achieved = Column(String(255), nullable=True)

class education(Base):
    __tablename__ = 'education_data'

    id = Column(Integer, primary_key=True, autoincrement=True)
    role = Column(String(255), nullable=False)
    stream = Column(String(255), nullable=False)
    bachelors_degree = Column(String(255), nullable=True)
    masters_degree = Column(String(255), nullable=True)
    certifications = Column(Text, nullable=True)
    competitions = Column(Text, nullable=True)
    courses = Column(Text, nullable=True)

    
# class education(Base):
#     __tablename__ = 'education_data'

#     id = Column(Integer, primary_key=True, autoincrement=True)
#     role = Column(String(255), nullable=False)
#     stream = Column(String(255), nullable=False)
#     bachelors_degree = Column(String(255), nullable=True)
#     masters_degree = Column(String(255), nullable=True)
#     certifications = Column(Text, nullable=True)
    
class Mentor(Base):
    __tablename__ = 'mentors'

    id = Column(Integer, primary_key=True)
    mentor_name = Column(String)
    username = Column(String, unique=True)
    profile_photo = Column(LargeBinary)
    description = Column(String)
    highest_degree = Column(String)
    expertise = Column(String)
    recent_project = Column(String)
    meeting_time = Column(String)
    fees = Column(String)
    stream_name = Column(String, ForeignKey('streams.name'))
    country = Column(String)
    verified = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey('users.id'))

    users = relationship("User", secondary=user_mentor_association, back_populates="mentors")
    stream = relationship("Stream", backref="mentors")

    
class Feedback(Base):
    __tablename__ = 'feedback'

    feedback_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    mentor_id = Column(Integer, nullable=False)
    milestone = Column(String(255), nullable=False)
    milestone_achieved = Column(Boolean, nullable=False)
    next_steps_identified = Column(Boolean, nullable=False)
    progress_rating = Column(Integer, nullable=False)
    mentor_responsibility = Column(Boolean, nullable=False)
    user_responsibility = Column(Boolean, nullable=False)
    check_id = Column(Integer, nullable=True)  # New field
    check_meeting_id = Column(Integer, nullable=True)  # New field
    created_at = Column(DateTime, default=datetime.utcnow)
    
class UserMentorship(Base):
    __tablename__ = 'milestone'

    serial_number = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False)
    mentor_id = Column(Integer, nullable=False)
    milestone = Column(MutableList.as_mutable(JSONB), nullable=False)
    check_id = Column(Integer, nullable=True)  # New field
    check_meeting_id = Column(Integer, nullable=True)  # New field
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    google_id = Column(String)
    # email = Column(String, unique=True)
    # Establishing a One-to-One relationship with UserDetails
    details = relationship("UserDetails", back_populates="user", uselist=False)

    # Establishing a Many-to-Many relationship with Mentor
    mentors = relationship("Mentor", secondary=user_mentor_association)
    assignments = relationship('UserMentorAssignment', back_populates='user')


class UserDetails(Base):
    __tablename__ = 'user_details'

    id = Column(Integer, primary_key=True)
    username = Column(String, ForeignKey('users.username'), unique=True)
    first_name = Column(String)
    last_name = Column(String)
    school_name = Column(String)
    bachelors_degree = Column(String)
    masters_degree = Column(String)
    certification = Column(String)
    activity = Column(String)
    country = Column(String)
    data_filled = Column(Boolean, default=False)
    stream_name = Column(String, ForeignKey('streams.name')) 

    user = relationship("User", back_populates="details")
    stream = relationship("Stream", backref="user_details") 
    
class Msg(Base):
    __tablename__ = 'messagesdata'

    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    receiver_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    sender = relationship("User", foreign_keys=[sender_id], backref="sent_messages")
    receiver = relationship("User", foreign_keys=[receiver_id], backref="received_messages")
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)



# class Notification(Base):
#     __tablename__ = 'notifications'

#     id = Column(Integer, primary_key=True)
#     user_id = Column(Integer, ForeignKey('users.id'))
#     mentor_id = Column(Integer, ForeignKey('mentors.id'))
#     message = Column(String)
#     timestamp = Column(DateTime, default=datetime.utcnow)
#     is_read = Column(Boolean, default=False)

#     # Relationships to User and Mentor
#     user = relationship("User", backref="notifications")
#     mentor = relationship("Mentor", backref="notifications")

# mileston table 

     
    
class Notification(Base):
    __tablename__ = 'notifications'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))  # The user ID for both users and mentors
    message = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False)
    
    
    
#meeting class
class Schedule(Base):
    __tablename__ = 'schedules'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    start_datetime = Column(DateTime, nullable=False)
    end_datetime = Column(DateTime, nullable=False)
    link = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # New field
    timezone = Column(String, nullable=False)  # e.g., 'UTC', 'Asia/Kolkata'

    # Mentor details
    mentor_id = Column(Integer, nullable=False)
    mentor_name = Column(String, nullable=False)
    mentor_email = Column(String, nullable=False)
    user_id = Column(Integer, nullable=False)
    duration = Column(Integer, nullable=False)

#trail meeting
class Schedule(Base):
    __tablename__ = 'trial_schedules'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    start_datetime = Column(DateTime, nullable=False)
    end_datetime = Column(DateTime, nullable=False)
    link = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # New field
    timezone = Column(String, nullable=False)  # e.g., 'UTC', 'Asia/Kolkata'

    # Mentor details
    mentor_id = Column(Integer, nullable=False)
    mentor_name = Column(String, nullable=False)
    mentor_email = Column(String, nullable=False)
    user_id = Column(Integer, nullable=False)
    duration = Column(Integer, nullable=False)


#intent table 
class Intent(Base):
    __tablename__ = 'intent'

    id = Column(Integer, primary_key=True, autoincrement=True)
    useruniqid = Column(String(100), nullable=False)
    email = Column(String(255), nullable=False)
    area_exploring = Column(String(255), nullable=True)
    goal_challenge = Column(String(255), nullable=True)
    support_types = Column(JSON, nullable=True)  # Store as JSON array
    created_at = Column(DateTime, default=datetime.utcnow)

    
Session = sessionmaker(bind=engine)

app = Flask(__name__)
swagger = Swagger(app)
CORS(app, support_credentials=False,origins="*")
app.config['JWT_SECRET_KEY'] = "123456"

app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'figurecircle2024@gmail.com'
app.config['MAIL_PASSWORD'] = 'xcodehmmdifkilyw'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False


stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_SECRET_KEY= os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
google_client_id = os.getenv('GOOGLE_CLIENT_ID')
google_client_secret = os.getenv('GOOGLE_CLIENT_SECRET')

app.config['GOOGLE_CLIENT_ID'] = google_client_id
app.config['GOOGLE_CLIENT_SECRET'] = google_client_secret

app.config['GOOGLE_DISCOVERY_URL'] = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")
jwt = JWTManager(app)

client = WebApplicationClient(app.config['GOOGLE_CLIENT_ID'])


@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Recommendation API!"})


@app.route('/google_login')
def google_login():
    google_provider_cfg = requests.get(app.config['GOOGLE_DISCOVERY_URL']).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route('/google_login/callback')
def google_callback():
    code = request.args.get("code")
    token_endpoint = requests.get(app.config['GOOGLE_DISCOVERY_URL']).json()["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(app.config['GOOGLE_CLIENT_ID'], app.config['GOOGLE_CLIENT_SECRET']),
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = requests.get(app.config['GOOGLE_DISCOVERY_URL']).json()["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        user_name = userinfo_response.json()["given_name"]

        session = Session()

        user = session.query(User).filter_by(google_id=unique_id).first()
        if not user:
            # Create a new user account if not existing
            user = User(username=users_email, google_id=unique_id)
            session.add(user)
            session.commit()

        data_fill = user.details.data_filled if user.details else False

        access_token = create_access_token(identity=user.username, expires_delta=False)
        session.close()
        return jsonify({"access_token": access_token, "data_fill": data_fill}), 200
    else:
        return jsonify({"error": "User email not available or not verified by Google"}), 400

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    session = Session()

    # Check if the username already exists
    if session.query(User).filter_by(username=username).first():
        session.close()
        return jsonify({"message": "Username already exists"}), 400

    # Create a new user
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)
    session.add(new_user)

    # Create empty user details for the new user
    new_user_details = UserDetails(user=new_user)
    session.add(new_user_details)

    session.commit()
    session.close()

    return jsonify({
        "message": "User registered successfully",
        "register": True
    }), 201



@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    session = Session()

    # Retrieve the user by username
    user = session.query(User).filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        session.close()
        return jsonify({"message": "Invalid username or password"}), 401

    # Check if user details are filled
    data_fill = True
    user_id = user.id

    # Check if user is a mentor in Newmentortable
    is_mentor = session.query(Newmentor).filter_by(user_id=user_id).first() is not None

    access_token = create_access_token(identity=username, expires_delta=False)

    session.close()

    return jsonify({
        "access_token": access_token,
        "data_fill": data_fill,
        "user_id": user_id,
        "is_mentor": is_mentor
    }), 200



@app.route('/register_admin', methods=['POST'])
def register_admin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    hashed_password = generate_password_hash(password)
    new_admin = Admin(username=username, password=hashed_password)

    session = Session()
    session.add(new_admin)
    session.commit()
    session.close()

    return jsonify({"message": "Admin registered successfully"}), 201

@app.route('/admin_login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    session = Session()
    admin = session.query(Admin).filter_by(username=username).first()

    if not admin or not check_password_hash(admin.password, password):
        session.close()
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=username, expires_delta=False)
    session.close()
    return jsonify({"access_token": access_token}), 200

@app.route('/user_details', methods=['GET', 'POST', 'PUT'])
@jwt_required()
def user_details():
    current_user = get_jwt_identity()
    session = Session()

    user = session.query(User).filter_by(username=current_user).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    if request.method == 'GET':
        user_details = user.details
        session.close()
        if user_details:
            user_details_dict = {
                "user_id": user_details.id,
                "first_name": user_details.first_name,
                "last_name": user_details.last_name,
                "school_name": user_details.school_name,
                "bachelors_degree": user_details.bachelors_degree,
                "masters_degree": user_details.masters_degree,
                "certification": user_details.certification,
                "activity": user_details.activity,
                "country": user_details.country,
                "stream_name": user_details.stream_name,
                "data_filled": user_details.data_filled
            }
            return jsonify(user_details_dict), 200
        else:
            return jsonify({"message": "User details not found"}), 200

    elif request.method == 'POST':
        data = request.get_json()

        if user.details and user.details.data_filled:
            session.close()
            return jsonify({"message": "User details already exist. Use PUT to update."}), 400

        if not user.details:
            user.details = UserDetails(user=user)

        user.details.first_name = data.get('first_name', user.details.first_name)
        user.details.last_name = data.get('last_name', user.details.last_name)
        user.details.school_name = data.get('school_name', user.details.school_name)
        user.details.bachelors_degree = data.get('bachelors_degree', user.details.bachelors_degree)
        user.details.masters_degree = data.get('masters_degree', user.details.masters_degree)
        user.details.certification = data.get('certification', user.details.certification)
        user.details.country = data.get('country', user.details.country)
        user.details.activity = data.get('activity', user.details.activity)
        user.details.stream_name = data.get('stream_name', user.details.stream_name)

        user.details.data_filled = True

        try:
            session.commit()
            session.close()
            return jsonify({"message": "User details added successfully"}), 200
        except Exception as e:
            session.rollback()
            session.close()
            return jsonify({"message": f"Failed to add user details: {str(e)}"}), 500

    elif request.method == 'PUT':
        data = request.get_json()

        if not user.details:
            session.close()
            return jsonify({"message": "User details not found. Use POST to create."}), 400

        user.details.first_name = data.get('first_name', user.details.first_name)
        user.details.last_name = data.get('last_name', user.details.last_name)
        user.details.school_name = data.get('school_name', user.details.school_name)
        user.details.bachelors_degree = data.get('bachelors_degree', user.details.bachelors_degree)
        user.details.masters_degree = data.get('masters_degree', user.details.masters_degree)
        user.details.certification = data.get('certification', user.details.certification)
        user.details.country = data.get('country', user.details.country)
        user.details.activity = data.get('activity', user.details.activity)
        user.details.stream_name = data.get('stream_name', user.details.stream_name)

        try:
            session.commit()
            session.close()
            return jsonify({"message": "User details updated successfully"}), 200
        except Exception as e:
            session.rollback()
            session.close()
            return jsonify({"message": f"Failed to update user details: {str(e)}"}), 500

@app.route('/api/mentor/details', methods=['GET'])
def get_mentor_details():
    session = Session()
    try:
        user_id = request.args.get('user_id')
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400
        mentor = session.query(Newmentor).filter(Newmentor.user_id == user_id).first()
        if not mentor:
            return jsonify({"error": "No mentor found for the given user_id"}), 404
        return jsonify({
            "mentor_id": mentor.mentor_id,
            "user_id": mentor.user_id,
            "name": mentor.name,
            "email": mentor.email,
            "phone": mentor.phone,
            "linkedin": mentor.linkedin,
            "expertise": mentor.expertise,
            "degree": mentor.degree,
            "background": mentor.background,
            "fee": mentor.fee,
            "milestones": mentor.milestones,
            "profile_picture": mentor.profile_picture,
            "resume": mentor.resume,
            "created_at": mentor.created_at.isoformat() if mentor.created_at else None
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()

@app.route('/api/mentors', methods=['GET'])
def get_all_mentors():
    session = Session()
    try:
        mentors = session.query(Newmentor).all()
        mentor_list = []
        for mentor in mentors:
            mentor_list.append({
                "mentor_id": mentor.mentor_id,
                "user_id": mentor.user_id,
                "name": mentor.name,
                "email": mentor.email,
                "phone": mentor.phone,
                "linkedin": mentor.linkedin,
                "expertise": mentor.expertise,
                "degree": mentor.degree,
                "background": mentor.background,
                "fee": mentor.fee,
                "milestones": mentor.milestones,
                "profile_picture": mentor.profile_picture,
                "resume": mentor.resume,
                "created_at": mentor.created_at.isoformat() if mentor.created_at else None
            })
        return jsonify(mentor_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()

# check mentor 
@app.route('/api/check_user', methods=['GET'])
def check_user():
    user_id = request.args.get('user_id')  # Get user_id from query params

    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    try:
        user_id = int(user_id)  # Convert to integer
    except ValueError:
        return jsonify({"error": "Invalid user_id"}), 400

    # Check if user_id exists in the table
    mentor = Newmentor.query.filter_by(user_id=user_id).first()

    if mentor:
        return jsonify({"exists": True, "message": "User ID found in the database"}), 200
    else:
        return jsonify({"exists": False, "message": "User ID not found"}), 404
    
    

@app.route('/update_user_details_diff', methods=['POST'])
@jwt_required()
def update_user_details_diff():
    current_user = get_jwt_identity()
    session = Session()

    user = session.query(User).filter_by(username=current_user).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    data = request.get_json()

    updates = {}
    if 'first_name' in data and data['first_name'] != user.details.first_name:
        updates['first_name'] = data['first_name']
    if 'last_name' in data and data['last_name'] != user.details.last_name:
        updates['last_name'] = data['last_name']
    if 'school_name' in data and data['school_name'] != user.details.school_name:
        updates['school_name'] = data['school_name']
    if 'bachelors_degree' in data and data['bachelors_degree'] != user.details.bachelors_degree:
        updates['bachelors_degree'] = data['bachelors_degree']
    if 'masters_degree' in data and data['masters_degree'] != user.details.masters_degree:
        updates['masters_degree'] = data['masters_degree']
    if 'certification' in data and data['certification'] != user.details.certification:
        updates['certification'] = data['certification']
    if 'activity' in data and data['activity'] != user.details.activity:
        updates['activity'] = data['activity']
    if 'country' in data and data['country'] != user.details.country:
        updates['country'] = data['country']
    if 'stream_name' in data and data['stream_name'] != user.details.stream_name:
        updates['stream_name'] = data['stream_name']

    if not updates:
        session.close()
        return jsonify({"message": "No changes detected"}), 200

    for key, value in updates.items():
        setattr(user.details, key, value)

    try:
        session.commit()
        session.close()
        return jsonify({"message": "User details updated successfully"}), 200
    except Exception as e:
        session.rollback()
        session.close()
        return jsonify({"message": f"Failed to update user details: {str(e)}"}), 500

# new api for get the futureprofile
@app.route('/get_roles_by_stream', methods=['POST']) 
@jwt_required()
def get_roles_by_stream():
    data = request.json
    role = data.get('role')
    highest_degree = data.get('highestdegree')  # Accept 'bachelors_degree' or 'masters_degree'

    session = Session()
    try:
        if role:
            # Step 1: Find the stream for the provided role
            stream_result = session.query(education.stream).filter_by(role=role).first()

            if not stream_result:
                return jsonify({"error": "Role not found"}), 404

            stream = stream_result[0]

        elif highest_degree:
            # Step 1 (alternate): Find the stream for the provided highest degree
            stream_result = session.query(education.stream).filter(
                (education.bachelors_degree == highest_degree) |
                (education.masters_degree == highest_degree)
            ).first()

            if not stream_result:
                return jsonify({"error": "Degree not found"}), 404

            stream = stream_result[0]

        else:
            return jsonify({"error": "Either role or highestdegree is required"}), 400

        # Step 2: Find all roles with the same stream
        roles_result = session.query(education.role).filter_by(stream=stream).distinct().all()
        roles = list(set(role for (role,) in roles_result))

        return jsonify({
            "stream": stream,
            "related_roles": roles
        }), 200

    except Exception as e:
        app.logger.error(f"Error fetching roles by stream: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

    finally:
        session.close()



def get_all_degrees():
    session = Session()
    
    degrees = session.query(Degree).all()
    return {degree.name.lower(): degree for degree in degrees}

degree_data = get_all_degrees()


@app.route('/search-degree', methods=['GET'])
def search_degree():
    query = request.args.get('degree', '').strip().lower()

    if not query:
        return jsonify({"error": "Please provide a degree name"}), 400

    session = Session()

    # Fetch all education entries
    education_entries = session.query(education).all()

    # Create a map of role -> entry
    role_map = {entry.role.strip().lower(): entry for entry in education_entries}

    # Try exact match first
    if query in role_map:
        edu = role_map[query]
        return jsonify({
            "matched_role": edu.role,
            "degree": edu.bachelors_degree or edu.masters_degree,
            "courses": edu.courses.split(", ") if edu.courses else [],
            "competitions": edu.competitions.split(", ") if edu.competitions else [],
            "certifications": edu.certifications.split(", ") if edu.certifications else [],
            "match_type": "exact"
        })

    # If no exact match, do fuzzy matching
    best_match, score = process.extractOne(query, role_map.keys())

    if best_match:
        edu = role_map[best_match]
        return jsonify({
            "matched_role": edu.role,
            "degree": edu.bachelors_degree or edu.masters_degree,
            "courses": edu.courses.split(", ") if edu.courses else [],
            "competitions": edu.competitions.split(", ") if edu.competitions else [],
            "certifications": edu.certifications.split(", ") if edu.certifications else [],
            "match_type": "fuzzy",
            "confidence": score
        })

    # Fallback - shouldn't be needed due to "always return" logic
    return jsonify({"error": "No relevant role found"}), 404


@app.route('/dream-list', methods=['GET'])
def dream_list():
    query = request.args.get('degree', '').strip().lower()

    if not query:
        return jsonify({"error": "Please provide a degree name"}), 400

    session = Session()

    # Fetch all education entries
    education_entries = session.query(education).all()

    # Create a map of role -> entry
    role_map = {entry.role.strip().lower(): entry for entry in education_entries}

    matched_roles = []

    # If exact match exists, include it first
    if query in role_map:
        exact_edu = role_map[query]
        matched_roles.append({
            "matched_role": exact_edu.role,
            "match_type": "exact",
            "confidence": 100
        })
        # Add up to 3 more fuzzy matches excluding the exact match
        candidates = [role for role in role_map.keys() if role != query]
        fuzzy_matches = process.extract(query, candidates, limit=3)
    else:
        # No exact match; get top 4 fuzzy matches
        fuzzy_matches = process.extract(query, role_map.keys(), limit=4)

    # Append fuzzy matches
    for best_match, score in (fuzzy_matches or []):
        edu = role_map[best_match]
        matched_roles.append({
            "matched_role": edu.role,
            "match_type": "fuzzy",
            "confidence": score
        })

    if matched_roles:
        return jsonify({"matched_roles": matched_roles}), 200

    # Fallback - shouldn't be needed due to "always return" logic
    return jsonify({"error": "No relevant role found"}), 404

@app.route('/streams', methods=['POST'])
@jwt_required()
def create_stream():
    data = request.get_json()
    stream_name = data.get('name')

    if not stream_name:
        return jsonify({"message": "Stream name is required"}), 400

    session = Session()
    new_stream = Stream(name=stream_name)

    try:
        session.add(new_stream)
        session.commit()
        session.close()
        return jsonify({"message": "Stream created successfully"}), 201
    except IntegrityError:
        session.rollback()
        session.close()
        return jsonify({"message": "Stream name already exists"}), 400

@app.route('/streams/<string:stream_name>', methods=['PUT'])
@jwt_required()
def update_stream(stream_name):
    session = Session()

    stream = session.query(Stream).filter_by(name=stream_name).first()
    if not stream:
        session.close()
        return jsonify({"message": "Stream not found"}), 404

    data = request.get_json()
    new_name = data.get('name')

    if not new_name:
        session.close()
        return jsonify({"message": "New stream name is required"}), 400

    stream.name = new_name

    try:
        session.commit()
        session.close()
        return jsonify({"message": "Stream updated successfully"}), 200
    except IntegrityError:
        session.rollback()
        session.close()
        return jsonify({"message": "New stream name already exists"}), 400

@app.route('/streams/<string:stream_name>', methods=['DELETE'])
@jwt_required()
def delete_stream(stream_name):
    session = Session()

    stream = session.query(Stream).filter_by(name=stream_name).first()
    if not stream:
        session.close()
        return jsonify({"message": "Stream not found"}), 404

    session.delete(stream)
    session.commit()
    session.close()

    return jsonify({"message": "Stream deleted successfully"}), 200

@app.route('/streams/<string:stream_name>', methods=['GET'])
@jwt_required()
def get_stream(stream_name):
    session = Session()

    stream = session.query(Stream).filter_by(name=stream_name).first()
    if not stream:
        session.close()
        return jsonify({"message": "Stream not found"}), 404

    stream_info = {
        "name": stream.name
    }

    session.close()
    return jsonify(stream_info), 200

@app.route('/streams', methods=['GET'])
@jwt_required()
def list_streams():
    session = Session()

    streams = session.query(Stream).all()

    stream_list = [stream.name for stream in streams]

    session.close()
    return jsonify({"streams": stream_list}), 200

@app.route('/add_mentor', methods=['POST'])
@jwt_required()
def add_mentor():
    current_user = get_jwt_identity()  # This assumes `get_jwt_identity` returns the user ID
    session = Session()

    data = request.get_json()
    mentor_name = data.get('mentor_name')
    username = data.get('username')
    profile_photo_base64 = data.get('profile_photo')  # profile photo is sent as base64-encoded string
    description = data.get('description')
    highest_degree = data.get('highest_degree')
    expertise = data.get('expertise')
    recent_project = data.get('recent_project')
    meeting_time = data.get('meeting_time')
    fees = data.get('fees')
    stream_name = data.get('stream')  
    country = data.get('country')
    sender_email = data.get('sender_email')
    user_id=data.get('user_id')

    # Check if all required fields are present
    if not all([mentor_name, username, profile_photo_base64, description, highest_degree, expertise, recent_project, meeting_time, fees, stream_name, country,user_id]):
        session.close()
        return jsonify({"message": "Missing mentor details"}), 400

    # Check if username already exists
    existing_mentor = session.query(Mentor).filter_by(username=username).first()
    if existing_mentor:
        session.close()
        return jsonify({"message": "Username already exists or data is already exists"}), 400

    # Decode profile photo
    profile_photo_binary = base64.b64decode(profile_photo_base64)

    # Check if stream exists
    stream = session.query(Stream).filter_by(name=stream_name).first()
    if not stream:
        session.close()
        return jsonify({"message": "Stream does not exist"}), 404

    # Create a new mentor with the provided details
    new_mentor = Mentor(
        mentor_name=mentor_name,
        username=username,
        profile_photo=profile_photo_binary,
        description=description,
        highest_degree=highest_degree,
        expertise=expertise,
        recent_project=recent_project,
        meeting_time=meeting_time,
        fees=fees,
        stream_name=stream_name,
        country=country,
        verified=False,
        user_id=user_id  # Associate with the current logged-in user
    )
    session.add(new_mentor)
    session.commit()
    print("mentor added")

    # Send verification email to admin
    msg = Message('New Mentor Verification', sender=sender_email, recipients=['admin_email@example.com'])
    msg.body = f"Please verify the new mentor:\n\nID: {new_mentor.id}\nName: {mentor_name}\nStream: {stream_name}\nCountry: {country}"
    mail.send(msg)

    session.close()
    return jsonify({"message": "Mentor added successfully. Verification email sent to admin."}), 201



@app.route('/update_mentor/<int:mentor_id>', methods=['PUT'])
@jwt_required()
def update_mentor(mentor_id):
    session = Session()

    # Query the mentor by mentor_id
    mentor = session.query(Mentor).filter_by(id=mentor_id).first()

    if not mentor:
        session.close()
        return jsonify({"message": "Mentor not found"}), 404

    # Get updated data from request body
    data = request.get_json()
    mentor_name = data.get('mentor_name')
    username = data.get('username')
    description = data.get('description')
    highest_degree = data.get('highest_degree')
    expertise = data.get('expertise')
    recent_project = data.get('recent_project')
    meeting_time = data.get('meeting_time')
    fees = data.get('fees')
    stream_name = data.get('stream')
    country = data.get('country')

    # Update mentor details
    if mentor_name:
        mentor.mentor_name = mentor_name
    if username:
        mentor.username = username
    if description:
        mentor.description = description
    if highest_degree:
        mentor.highest_degree = highest_degree
    if expertise:
        mentor.expertise = expertise
    if recent_project:
        mentor.recent_project = recent_project
    if meeting_time:
        mentor.meeting_time = meeting_time
    if fees:
        mentor.fees = fees
    if stream_name:
        mentor.stream_name = stream_name
    if country:
        mentor.country = country

    session.commit()
    session.close()

    return jsonify({"message": "Mentor details updated successfully"}), 200


#Calendly APIs
@app.route('/api/schedule', methods=['POST'])
def create_schedule():
    session = Session()
    data = request.json

    try:
        # Extract data from the request
        name = data.get('name')
        email = data.get('email')
        start_datetime = datetime.fromisoformat(data.get('start_datetime'))
        end_datetime = datetime.fromisoformat(data.get('end_datetime'))
        link = data.get('link')
        timezone = data.get('timezone')  # New
        user_id = data.get('user_id')
        mentor_id = data.get('mentor_id')
        mentor_name = data.get('mentor_name')
        mentor_email = data.get('mentor_email')
        duration = data.get('duration')

        # Validate required fields
        if not all([user_id, mentor_id, mentor_name, mentor_email, start_datetime, end_datetime, duration, timezone]):
            return jsonify({"error": "Missing required fields"}), 400

        # Prevent overlapping meetings for either the user or the mentor
        overlapping = (
            session.query(Schedule)
            .filter(
                or_(Schedule.user_id == user_id, Schedule.mentor_id == mentor_id),
                Schedule.start_datetime < end_datetime,
                Schedule.end_datetime > start_datetime,
            )
            .first()
        )

        if overlapping:
            return jsonify({
                "error": "Overlapping meeting exists for the user or mentor in the selected time range"
            }), 409

        # Create a new schedule entry
        schedule = Schedule(
            name=name,
            email=email,
            start_datetime=start_datetime,
            end_datetime=end_datetime,
            link=link,
            timezone=timezone,  # Add here
            user_id=user_id,
            mentor_id=mentor_id,
            mentor_name=mentor_name,
            mentor_email=mentor_email,
            duration=duration
        )
        session.add(schedule)
        session.commit()

        return jsonify({"message": "Schedule created successfully!", "id": schedule.id}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 400
    finally:
        session.close()

@app.route('/api/trial_ schedule', methods=['POST'])
def create_trial_schedule():
    session = Session()
    data = request.json

    try:
        # Extract data from the request
        name = data.get('name')
        email = data.get('email')
        start_datetime = datetime.fromisoformat(data.get('start_datetime'))
        end_datetime = datetime.fromisoformat(data.get('end_datetime'))
        link = data.get('link')
        timezone = data.get('timezone')  # New
        user_id = data.get('user_id')
        mentor_id = data.get('mentor_id')
        mentor_name = data.get('mentor_name')
        mentor_email = data.get('mentor_email')
        duration = data.get('duration')

        # Validate required fields
        if not all([user_id, mentor_id, mentor_name, mentor_email, start_datetime, end_datetime, duration, timezone]):
            return jsonify({"error": "Missing required fields"}), 400

        # Prevent overlapping meetings for either the user or the mentor
        overlapping = (
            session.query(Schedule)
            .filter(
                or_(Schedule.user_id == user_id, Schedule.mentor_id == mentor_id),
                Schedule.start_datetime < end_datetime,
                Schedule.end_datetime > start_datetime,
            )
            .first()
        )

        if overlapping:
            return jsonify({
                "error": "Overlapping meeting exists for the user or mentor in the selected time range"
            }), 409

        # Create a new schedule entry
        schedule = Schedule(
            name=name,
            email=email,
            start_datetime=start_datetime,
            end_datetime=end_datetime,
            link=link,
            timezone=timezone,  # Add here
            user_id=user_id,
            mentor_id=mentor_id,
            mentor_name=mentor_name,
            mentor_email=mentor_email,
            duration=duration
        )
        session.add(schedule)
        session.commit()

        return jsonify({"message": "trial Schedule created successfully!", "id": schedule.id}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 400
    finally:
        session.close()



  
@app.route('/api/schedules', methods=['GET'])
def get_schedules():
    session = Session()

    try:
        # Get user_id and mentor_id from query parameters
        user_id = request.args.get('user_id')
        mentor_id = request.args.get('mentor_id')

        if not user_id and not mentor_id:
            return jsonify({"error": "Either user_id or mentor_id is required"}), 400

        # Retrieve schedules with user_id first
        schedules = []
        if user_id:
            schedules = session.query(Schedule).filter(Schedule.user_id == user_id).all()

        # If no schedules are found, search with mentor_id
        if not schedules and mentor_id:
            schedules = session.query(Schedule).filter(Schedule.mentor_id == mentor_id).all()

        # Return the results
        return jsonify([{
            "id": s.id,
            "name": s.name,
            "email": s.email,
            "start_datetime": s.start_datetime.isoformat(),
            "end_datetime": s.end_datetime.isoformat(),
            "link": s.link,
            "created_at": s.created_at.isoformat(),
            "mentor_id": s.mentor_id,
            "mentor_name": s.mentor_name,
            "mentor_email": s.mentor_email,
            "user_id": s.user_id,
            "duration": s.duration
        } for s in schedules]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        session.close()


# check user api meeting after meeting
@app.route('/api/validMeeting/<int:schedule_id>', methods=['GET'])
def get_schedule(schedule_id):
    session = Session()
    
    # Search for the schedule where the link contains "/v2/meetingcall/<schedule_id>"
    schedule = session.query(Schedule).filter(Schedule.link.contains(f"/v2/meetingcall/{schedule_id}")).first()
    session.close()
    
    print("checking--->",schedule)

    if not schedule:
        return jsonify({"error": "Schedule not found"}), 404

    try:
        # Convert duration to an integer
        duration_minutes = int(schedule.duration)
    except ValueError:
        return jsonify({"error": "Invalid duration format. Duration should be a number."}), 400

    # Calculate meeting expiration time (start_datetime + duration + 30 minutes)
    meeting_end_time = schedule.start_datetime + timedelta(minutes=duration_minutes + 30)
    current_time = datetime.utcnow()

    if current_time > meeting_end_time:
        return jsonify({"error": "Sorry, you can't submit the form. The submit time has expired. please contact to admin"}), 403

    return jsonify({
        "id": schedule.id,
        "name": schedule.name,
        "email": schedule.email,
        "start_datetime": schedule.start_datetime.isoformat(),
        "end_datetime": schedule.end_datetime.isoformat(),
        "link": schedule.link,
        "created_at": schedule.created_at.isoformat(),
        "mentor_id": schedule.mentor_id,
        "mentor_name": schedule.mentor_name,
        "mentor_email": schedule.mentor_email,
        "user_id": schedule.user_id,
        "duration": schedule.duration,
        "start_param": schedule.link,
        "timezone": schedule.timezone 
    })


@app.route('/api/milestonevalidMeeting/<int:schedule_id>', methods=['GET'])
def get_schedule_milestone(schedule_id):
    session = Session()
    schedule = session.query(Schedule).filter(Schedule.link.contains(f"/v2/meetingcall/{schedule_id}")).first()
    session.close()

    if not schedule:
        return jsonify({"error": "Schedule not found"}), 404

    return jsonify({
        "id": schedule.id,
        "name": schedule.name,
        "email": schedule.email,
        "start_datetime": schedule.start_datetime.isoformat(),
        "end_datetime": schedule.end_datetime.isoformat(),
        "link": schedule.link,
        "created_at": schedule.created_at.isoformat(),
        "mentor_id": schedule.mentor_id,
        "mentor_name": schedule.mentor_name,
        "mentor_email": schedule.mentor_email,
        "user_id": schedule.user_id,
        "duration": schedule.duration,
        "start_param": schedule.link 
    })

# check with link and get the meeting detials
@app.route('/api/validMeeting', methods=['GET'])
def get_schedule_by_link():
    session = Session()
    link = request.args.get('link')

    if not link:
        return jsonify({"error": "link is required"}), 400

    schedule = session.query(Schedule).filter_by(link=link).first()
    session.close()

    if not schedule:
        return jsonify({"error": "Schedule not found"}), 404

    return jsonify({
        "id": schedule.id,
        "name": schedule.name,
        "email": schedule.email,
        "start_datetime": schedule.start_datetime.isoformat(),
        "end_datetime": schedule.end_datetime.isoformat(),
        "link": schedule.link,
        "created_at": schedule.created_at.isoformat(),
        "mentor_id": schedule.mentor_id,
        "mentor_name": schedule.mentor_name,
        "mentor_email": schedule.mentor_email,
        "user_id": schedule.user_id,
        "duration": schedule.duration,
        "timezone": schedule.timezone
    })
    
# GET all feedback
@app.route('/feedback', methods=['GET'])
def get_feedback():
    user_id = request.args.get('user_id')  # Get user_id from query params
    mentor_id = request.args.get('mentor_id')  # Get mentor_id from query params
    session = Session()

    # Ensure at least one identifier is provided
    if not user_id and not mentor_id:
        return jsonify({'error': 'Missing user_id or mentor_id parameter'}), 400

    # Query feedback based on either user_id or mentor_id
    feedback_list = session.query(Feedback).filter(
        (Feedback.user_id == user_id) | (Feedback.mentor_id == mentor_id)
    ).all()

    feedback_data = [
        {
            'feedback_id': f.feedback_id,
            'user_id': f.user_id,
            'mentor_id': f.mentor_id,
            'milestone': f.milestone,
            'milestone_achieved': f.milestone_achieved,
            'next_steps_identified': f.next_steps_identified,
            'progress_rating': f.progress_rating,
            'mentor_responsibility': f.mentor_responsibility,
            'user_responsibility': f.user_responsibility,
            'check_id': f.check_id,
            'check_meeting_id': f.check_meeting_id,
            'created_at': f.created_at
        } for f in feedback_list
    ]

    return jsonify(feedback_data), 200

# POST new feedback
@app.route('/feedback', methods=['POST'])
def add_feedback():
    session = Session()
    data = request.json

    # Validate request data
    required_fields = ['user_id', 'mentor_id', 'milestone', 'milestone_achieved', 
                       'next_steps_identified', 'progress_rating', 'mentor_responsibility', 
                       'user_responsibility', 'check_id', 'check_meeting_id']

    missing_fields = [field for field in required_fields if data.get(field) is None]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    try:
        # Check if feedback already exists for the given check_id and check_meeting_id
        existing_feedback = session.query(Feedback).filter_by(
            check_id=data['check_id'], 
            check_meeting_id=data['check_meeting_id']
        ).first()

        if existing_feedback:
            return jsonify({'error': 'Feedback already submitted for this check_id and check_meeting_id'}), 400

        # Create new feedback entry
        new_feedback = Feedback(
            user_id=data['user_id'],
            mentor_id=data['mentor_id'],
            milestone=data['milestone'],
            milestone_achieved=data['milestone_achieved'],
            next_steps_identified=data['next_steps_identified'],
            progress_rating=data['progress_rating'],
            mentor_responsibility=data['mentor_responsibility'],
            user_responsibility=data['user_responsibility'],
            check_id=data['check_id'],  # New field
            check_meeting_id=data['check_meeting_id']  # New field
        )

        session.add(new_feedback)
        session.commit()
        return jsonify({'message': 'Feedback added successfully', 'feedback_id': new_feedback.feedback_id}), 201
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()





# @app.route('/mentors_by_stream', methods=['GET'])
# @jwt_required()
# def mentors_by_stream():
#     current_user = get_jwt_identity()
#     session = Session()

#     user = session.query(User).filter_by(username=current_user).first()

#     if not user:
#         session.close()
#         return jsonify({"message": "User not found"}), 404

#     user_details = user.details
    
#     if not user_details or not user_details.stream_name:
#         session.close()
#         return jsonify({"message": "User stream not found"}), 404

#     stream_name = user_details.stream_name

#     try:
#         # Assuming Mentor has a relationship 'stream' and Stream has an attribute 'name'
#         mentors = session.query(Mentor).filter(Mentor.stream.has(name=stream_name)).all()
#         app.logger.debug(f"checking: {mentors}")
#         mentor_list = []
#         for mentor in mentors:
#             mentor_info = {
#                 "mentor_id": mentor.id,
#                 "username": mentor.username,
#                 "mentor_name": mentor.mentor_name,
#                 # "profile_photo": mentor.profile_photo.decode('utf-8', 'ignore'),  
#                 "description": mentor.description,
#                 "highest_degree": mentor.highest_degree,
#                 "expertise": mentor.expertise,
#                 "recent_project": mentor.recent_project,
#                 "meeting_time": mentor.meeting_time,
#                 "fees": mentor.fees,
#                 "stream": mentor.stream.name,
#                 "country": mentor.country,
#                 "verified": mentor.verified
#             }
#             mentor_list.append(mentor_info)

#         session.close()
#         return jsonify({"mentors_with_same_stream": mentor_list}), 200
#     except Exception as e:
#         session.close()
#         return jsonify({"message": f"Failed to retrieve mentors: {str(e)}"}), 500

@app.route('/mentors_by_stream', methods=['GET'])
@jwt_required()
def mentors_by_stream():
    current_user = get_jwt_identity()
    session = Session()

    user = session.query(User).filter_by(username=current_user).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    user_details = user.details

    if not user_details or not user_details.stream_name:
        session.close()
        return jsonify({"message": "User stream not found"}), 404

    stream_name = user_details.stream_name

    try:
        # Step 1: Retrieve mentors with the same stream as the user
        mentors_in_same_stream = session.query(Mentor).filter(Mentor.stream.has(name=stream_name)).all()

        if not mentors_in_same_stream:
            session.close()
            return jsonify({"message": "No mentors found in the user's stream"}), 404

        # Format the mentors of the same stream
        mentors_list_same_stream = []
        mentor_ids_same_stream = []

        for mentor in mentors_in_same_stream:
            mentor_info = {
                "mentor_id": mentor.id,
                "username": mentor.username,
                "mentor_name": mentor.mentor_name,
                # "profile_photo": mentor.profile_photo.decode('utf-8', 'ignore'),  
                "description": mentor.description,
                "highest_degree": mentor.highest_degree,
                "expertise": mentor.expertise,
                "recent_project": mentor.recent_project,
                "meeting_time": mentor.meeting_time,
                "fees": mentor.fees,
                "stream": mentor.stream.name,
                "country": mentor.country,
                "verified": mentor.verified
            }
            mentors_list_same_stream.append(mentor_info)
            mentor_ids_same_stream.append(mentor.id)  

        
        related_mentors = session.query(Mentor).filter(
            Mentor.users.any(User.mentors.any(Mentor.id.in_(mentor_ids_same_stream))),
            ~Mentor.id.in_(mentor_ids_same_stream)  
        ).all()

        mentors_list_related = []

        for related_mentor in related_mentors:
            related_mentor_info = {
                "mentor_id": related_mentor.id,
                "username": related_mentor.username,
                "mentor_name": related_mentor.mentor_name,
                # "profile_photo": related_mentor.profile_photo.decode('utf-8', 'ignore'),  
                "description": related_mentor.description,
                "highest_degree": related_mentor.highest_degree,
                "expertise": related_mentor.expertise,
                "recent_project": related_mentor.recent_project,
                "meeting_time": related_mentor.meeting_time,
                "fees": related_mentor.fees,
                "stream": related_mentor.stream.name,
                "country": related_mentor.country,
                "verified": related_mentor.verified
            }
            mentors_list_related.append(related_mentor_info)

        session.close()

        return jsonify({
            "mentors_with_same_stream": mentors_list_same_stream,
            "related_mentors": mentors_list_related
        }), 200

    except Exception as e:
        session.close()
        return jsonify({"message": f"Failed to retrieve mentors: {str(e)}"}), 500

    
@app.route('/mentors_by_similar_stream', methods=['GET'])
@jwt_required()
def mentors_by_similar_stream():
    current_user = get_jwt_identity()
    session = Session()

    user = session.query(User).filter_by(username=current_user).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    user_details = user.details

    if not user_details or not user_details.stream_name:
        session.close()
        return jsonify({"message": "User stream not found"}), 404

    stream_name = user_details.stream_name

    try:
        # Assuming Mentor has a relationship 'stream' and Stream has an attribute 'name'
        # Using SQLAlchemy 'like' for partial match, case-insensitive
        similar_streams = f"%{stream_name}%"  # Matches any stream containing the user's stream name
        mentors = session.query(Mentor).filter(Mentor.stream.has(Stream.name.ilike(similar_streams))).all()
        
        app.logger.debug(f"Partial match mentors: {mentors}")

        mentor_list = []
        for mentor in mentors:
            mentor_info = {
                "mentor_id": mentor.id,
                "username": mentor.username,
                "mentor_name": mentor.mentor_name,
                # "profile_photo": mentor.profile_photo.decode('utf-8', 'ignore'),  
                "description": mentor.description,
                "highest_degree": mentor.highest_degree,
                "expertise": mentor.expertise,
                "recent_project": mentor.recent_project,
                "meeting_time": mentor.meeting_time,
                "fees": mentor.fees,
                "stream": mentor.stream.name,
                "country": mentor.country,
                "verified": mentor.verified
            }
            mentor_list.append(mentor_info)

        session.close()
        return jsonify({"mentors_with_similar_stream": mentor_list}), 200

    except Exception as e:
        session.close()
        return jsonify({"message": f"Failed to retrieve mentors: {str(e)}"}), 500
    

@app.route('/all_mentors', methods=['GET'])
@jwt_required()
def all_mentors():
    current_user = get_jwt_identity()
    session = Session()

    user = session.query(User).filter_by(username=current_user).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    try:
        assigned_mentor_ids = {mentor.id for mentor in user.mentors}

        # Fetch all mentors excluding those already assigned to the user
        mentors = (
            session.query(Mentor)
            .filter(Mentor.id.notin_(assigned_mentor_ids))
            .filter(Mentor.user_id != user.id)
            .all()
        )
        
        
        # Fetch all mentors without filtering by stream
        # mentors = session.query(Mentor).all()

        app.logger.debug(f"All mentors: {mentors}")

        mentor_list = []
        for mentor in mentors:
            mentor_info = {
                "mentor_id": mentor.id,
                "username": mentor.username,
                "mentor_name": mentor.mentor_name,
                # "profile_photo": mentor.profile_photo.decode('utf-8', 'ignore'),  
                "description": mentor.description,
                "highest_degree": mentor.highest_degree,
                "expertise": mentor.expertise,
                "recent_project": mentor.recent_project,
                "meeting_time": mentor.meeting_time,
                "fees": mentor.fees,
                "stream": mentor.stream.name,
                "country": mentor.country,
                "verified": mentor.verified,
                "user_id":mentor.user_id
            }
            mentor_list.append(mentor_info)

        session.close()
        return jsonify({"all_mentors": mentor_list}), 200

    except Exception as e:
        session.close()
        return jsonify({"message": f"Failed to retrieve mentors: {str(e)}"}), 500




@app.route('/admin/verify_mentor/<int:mentor_id>', methods=['PUT'])
@jwt_required()
def admin_verify_mentor(mentor_id):
    current_user = get_jwt_identity()

    session = Session()
    admin = session.query(Admin).filter_by(username=current_user).first()

    if not admin:
        session.close()
        return jsonify({"message": "Unauthorized"}), 401

    mentor = session.query(Mentor).filter_by(id=mentor_id).first()

    if not mentor:
        session.close()
        return jsonify({"message": "Mentor not found"}), 404

    mentor.verified = True
    session.commit()
    session.close()

    return jsonify({"message": "Mentor verified successfully"}), 200


@app.route('/verified_mentors', methods=['GET'])
@jwt_required()
def get_verified_mentors():
    current_user = get_jwt_identity()

    # Check if current_user is an admin
    if not is_admin(current_user):
        return jsonify({"message": "Unauthorized"}), 401

    session = Session()

    # Query verified mentors
    verified_mentors = session.query(Mentor).filter_by(verified=True).all()

    mentor_list = []
    for mentor in verified_mentors:
        mentor_info = {
            "id": mentor.id,
            "mentor_name": mentor.mentor_name,
            "username": mentor.username,
            "profile_photo": mentor.profile_photo.decode('utf-8', 'ignore'),  # Decode binary photo to string
            "description": mentor.description,
            "highest_degree": mentor.highest_degree,
            "expertise": mentor.expertise,
            "recent_project": mentor.recent_project,
            "meeting_time": mentor.meeting_time,
            "fees": mentor.fees,
            "stream_name": mentor.stream_name,
            "country": mentor.country,
            "verified": mentor.verified
        }
        mentor_list.append(mentor_info)

    session.close()

    return jsonify({"verified_mentors": mentor_list}), 200

def is_admin(username):
    session = Session()
    admin = session.query(Admin).filter_by(username=username).first()
    session.close()
    return admin is not None

@app.route('/unverified_mentors', methods=['GET'])
@jwt_required()
def get_unverified_mentors():
    current_user = get_jwt_identity()

    # Check if current_user is an admin
    if not is_admin(current_user):
        return jsonify({"message": "Unauthorized"}), 401

    session = Session()

    # Query unverified mentors
    unverified_mentors = session.query(Mentor).filter_by(verified=False).all()

    mentor_list = []
    for mentor in unverified_mentors:
        mentor_info = {
            "id": mentor.id,
            "mentor_name": mentor.mentor_name,
            "username": mentor.username,  
            "profile_photo": mentor.profile_photo.decode('utf-8', 'ignore'),  # Decode binary photo to string
            "description": mentor.description,
            "highest_degree": mentor.highest_degree,
            "expertise": mentor.expertise,
            "recent_project": mentor.recent_project,
            "meeting_time": mentor.meeting_time,
            "fees": mentor.fees,
            "stream_name": mentor.stream_name,
            "country": mentor.country,
            "verified": mentor.verified
        }
        mentor_list.append(mentor_info)

    session.close()

    return jsonify({"unverified_mentors": mentor_list}), 200


#inforamtion apis
@app.route('/get_information', methods=['POST']) 
@jwt_required()
def get_information():
    """
    Fetches and returns filtered information based on user input.
    
    The request body should be a dictionary with column names as keys and 
    boolean values (true/false) to indicate which columns to retrieve.
    """
    data = request.json

    if not data or not isinstance(data, dict):
        return jsonify({"message": "Invalid request format. Expected a JSON object with boolean values."}), 400

    # Define fields separately
    info_fields = {
        "primary_expertise_area": Information.primary_expertise_area,
        "highest_degree_achieved": Information.highest_degree_achieved
    }

    edu_fields = {
        "bachelors_degree": education.bachelors_degree,
        "masters_degree": education.masters_degree,
        "certifications": education.certifications
    }

    selected_info_fields = [field for field, include in data.items() if include and field in info_fields]
    selected_edu_fields = [field for field, include in data.items() if include and field in edu_fields]

    session = Session()
    try:
        response_data = {}

        # Fetch from Information table
        if selected_info_fields:
            info_columns = [info_fields[field] for field in selected_info_fields]
            info_rows = session.query(*info_columns).all()
            for i, field in enumerate(selected_info_fields):
                response_data[field] = [getattr(row, field) for row in info_rows]

        # Fetch from education_data table
        if selected_edu_fields:
            edu_columns = [edu_fields[field] for field in selected_edu_fields]
            edu_rows = session.query(*edu_columns).all()
            for i, field in enumerate(selected_edu_fields):
                response_data[field] = [getattr(row, field) for row in edu_rows]

        if not response_data:
            return jsonify({"message": "No valid fields selected"}), 400

        return jsonify(response_data), 200

    except Exception as e:
        app.logger.error(f"Error fetching information: {str(e)}")
        return jsonify({"error": "An internal server error occurred"}), 500

    finally:
        session.close()


# post api
@app.route('/update_information', methods=['POST'])
@jwt_required()
def update_information():
    """
    Updates an existing record in the 'Information' table if a NULL field exists.
    If no such row exists, a new record is inserted.

    Example request body:
    {
        "masters_degree": "MCA",
        "certifications": "AWS Certified",
        "primary_expertise_area": "AI & ML",
        "highest_degree_achieved": "PhD"
    }

    Logic:
    - If a row with NULL in any of the provided fields exists, update it.
    - Otherwise, insert a new record.
    """
    data = request.json
    if not data or not isinstance(data, dict):
        return jsonify({"message": "Invalid request format. Expected a JSON object."}), 400

    session = Session()
    try:
        # Validate if all fields exist in the model
        valid_fields = ["bachelors_degree", "masters_degree", "certifications", "primary_expertise_area", "highest_degree_achieved"]
        update_fields = {key: value for key, value in data.items() if key in valid_fields}

        if not update_fields:
            return jsonify({"message": "No valid fields provided"}), 400

        # Find the first row where ANY of these fields is NULL
        existing_entry = session.query(Information).filter(
            or_(*[getattr(Information, field).is_(None) for field in update_fields])
        ).first()

        if existing_entry:
            # Update only the fields provided in the request
            for field, value in update_fields.items():
                setattr(existing_entry, field, value)

            session.commit()
            return jsonify({"message": "Record updated successfully"}), 200
        else:
            # If no existing row with NULL found, insert a new record
            new_entry = Information(**update_fields)
            session.add(new_entry)
            session.commit()
            return jsonify({"message": "New record inserted"}), 201

    except Exception as e:
        session.rollback()
        app.logger.error(f"Error in insert/update: {str(e)}")
        return jsonify({"error": "An internal server error occurred"}), 500

    finally:
        session.close()

# @app.route('/check_username', methods=['POST'])
# @jwt_required()
# def check_username():
#     data = request.get_json()
#     username = data.get('username')
    
#     if not username:
#         return jsonify({"error": "Username is required"}), 400
    
#     session = Session()
#     user_exists = session.query(UserDetails).filter_by(username=username).first() is not None
#     session.close()
    
#     return jsonify({"exists": user_exists})








# razor pay mentor
@app.route('/create_order', methods=['POST'])
def create_order():
    session = Session()
    data = request.get_json()
    mentor_id = data.get('mentor_id') 
    mentor = session.query(Newmentor).filter_by(mentor_id=mentor_id).first()
    if mentor is None:
        session.close()
        return jsonify({"message": "Mentor not found"}), 404
      
    mentor_fees = float(mentor.fee)*100
    

    payment_order = razorpay_client.order.create({
        "amount": mentor_fees, 
        "currency": "INR",
        "payment_capture": 1  
    })
    session.close()
    return jsonify(payment_order), 200

@app.route('/verify_payment', methods=['POST'])
def verify_payment():
    data = request.get_json()
    
    payment_id = data.get('razorpay_payment_id')
    order_id = data.get('razorpay_order_id')
    signature = data.get('razorpay_signature')

    # Verify payment signature
    try:
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        })
    except razorpay.errors.SignatureVerificationError:
        return jsonify({"message": "Payment verification failed"}), 400

    # Payment verification successful
    # Optionally: Add logic to record the payment in your database here.

    return jsonify({"message": "Payment verified successfully!"}), 200



# @app.route('/assign_mentor', methods=['POST'])
# @jwt_required()
# def assign_mentor():
#     current_user = get_jwt_identity()
#     session = Session()
    
#     data = request.get_json()
#     mentor_id = data.get('mentor_id')
#     user_id = data.get('user_id')

#     mentor = session.query(Mentor).filter_by(id=mentor_id).first()
#     user = session.query(User).filter_by(id=user_id).first()

#     if not mentor or not user:
#         session.close()
#         return jsonify({"message": "Mentor or user not found"}), 404

#     # Assign the mentor to the user
#     user.mentors.append(mentor)
#     session.commit()
#     session.close()

#     return jsonify({"message": f"Mentor {mentor_id} assigned to user {user_id} successfully"}), 200

@app.route('/assign_mentor', methods=['POST'])
@jwt_required()
def assign_mentor():
    current_user = get_jwt_identity()
    session = Session()
    
    data = request.get_json()
    mentor_id = data.get('mentor_id')
    user_id = data.get('user_id')

    mentor = session.query(Mentor).filter_by(id=mentor_id).first()
    user = session.query(User).filter_by(id=user_id).first()

    if not mentor or not user:
        session.close()
        return jsonify({"message": "Mentor or user not found"}), 404

    # Assign the mentor to the user
    user.mentors.append(mentor)
    session.commit()

    # Create notification message
    notification_message_user = f"You have been assigned a mentor: {mentor.mentor_name}."
    notification_message_mentor = f"You have been assigned to a new user: {user.username}."

    # Save notifications for both user and mentor in the database using user_id
    notification_for_user = Notification(user_id=user_id, message=notification_message_user)
    notification_for_mentor = Notification(user_id=mentor.user_id, message=notification_message_mentor)  # Assuming mentor has a user_id attribute
    session.add(notification_for_user)
    session.add(notification_for_mentor)
    session.commit()

    if user_id:
        notifications = session.query(Notification).filter_by(user_id=user_id).all()
        notification_messages = [{
            "message": notification.message,
            "timestamp": notification.timestamp.isoformat(), 
            "is_read": notification.is_read
        } for notification in notifications]

        emit('notifications', notification_messages, room=f"user_{user_id}", namespace='/')
    # Emit real-time notification to the user and mentor via Socket.IO
    emit('notification', {'message': notification_message_user, 'mentor_id': mentor_id, 'user_id': user_id},
         room=f"user_{user_id}", namespace='/')
    emit('notification', {'message': notification_message_mentor, 'mentor_id': mentor_id, 'user_id': user_id},
         room=f"mentor_{mentor.user_id}", namespace='/')

    session.close()
    return jsonify({"message": "Mentor assigned successfully."}), 200


@socketio.on('get_notifications')
def handle_get_notifications(data):
    user_id = data.get('user_id')
    session = Session()
    
    if user_id:
        
        notifications = session.query(Notification).filter_by(user_id=user_id).all()
        
        
        notification_messages = [{
            "message": notification.message,
            "timestamp": notification.timestamp.isoformat(), 
            "is_read": notification.is_read
        } for notification in notifications]

       
        emit('notifications', notification_messages, room=f"user_{user_id}")
    else:
        emit('notifications', {'message': 'No user ID provided'}, room=f"user_{user_id}")

@socketio.on('join')
def on_join(data):
    user_id = data.get('user_id')
    
    if user_id:
        join_room(f"user_{user_id}")
        emit('notification', {'message': 'Joined notification room successfully.'}, room=f"user_{user_id}")
    

@app.route('/create_payment_intent', methods=['POST'])
@jwt_required()
def create_payment_intent():
    data = request.get_json()
    mentor_id = data.get('mentor_id')
    user_id = data.get('user_id')

    if not mentor_id:
        return jsonify({"message": "Mentor ID is required"}), 400

    if not user_id:
        return jsonify({"message": "User ID is required"}), 400

    session = Session()

    user = session.query(User).filter_by(id=user_id).first()
    mentor = session.query(Mentor).filter_by(id=mentor_id).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    if not mentor:
        session.close()
        return jsonify({"message": "Mentor not found"}), 404

    try:
        amount = int(float(mentor.fees) * 100)

        payment_intent = stripe.PaymentIntent.create(
            amount=amount,
            currency='usd', 
            automatic_payment_methods={
                'enabled': True,
            },
        )

        return jsonify({
            'client_secret': payment_intent,
            'publishable_key': os.getenv('STRIPE_PUBLISHABLE_KEY')
        }), 200

    except Exception as e:
        session.close()
        return jsonify(error=str(e)), 500



@app.route('/confirm_payment', methods=['POST'])
@jwt_required()
def confirm_payment():
    data = request.get_json()
    mentor_id = data.get('mentor_id')
    payment_intent_id = data.get('payment_intent_id')
    user_id = data.get('user_id')
    

    if not mentor_id or not payment_intent_id:
        return jsonify({"message": "Mentor ID and Payment Intent ID are required"}), 400

    session = Session()
    user = session.query(User).filter_by(id=user_id).first()
    mentor = session.query(Mentor).filter_by(id=mentor_id).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    if not mentor:
        session.close()
        return jsonify({"message": "Mentor not found"}), 404

    try:
        # Retrieve the payment intent to confirm the payment status
        payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)

        if payment_intent.status == 'succeeded':
            # Assign the mentor to the user
            user.mentors.append(mentor)
            session.commit()
            session.close()
            return jsonify({"message": "Payment successful and mentor assigned!"}), 200
        else:
            session.close()
            return jsonify({"message": "Payment not completed"}), 400

    except Exception as e:
        session.close()
        return jsonify(error=str(e)), 500




@app.route('/assigned_mentors', methods=['GET'])
@jwt_required()
def get_assigned_mentors():
    current_user = get_jwt_identity()
    session = Session()

    user = session.query(User).filter_by(username=current_user).first()

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    assigned_mentors = user.mentors  # Fetch assigned mentors using the relationship

    mentor_list = []
    for mentor in assigned_mentors:
        mentor_info = {
            "id": mentor.id,
            "mentor_name": mentor.mentor_name,
            "username": mentor.username,  
            # "profile_photo": mentor.profile_photo.decode('utf-8', 'ignore'),  # Decode binary photo to string
            "description": mentor.description,
            "highest_degree": mentor.highest_degree,
            "expertise": mentor.expertise,
            "recent_project": mentor.recent_project,
            "meeting_time": mentor.meeting_time,
            "fees": mentor.fees,
            "stream_name": mentor.stream_name,
            "country": mentor.country,
            "verified": mentor.verified
        }
        mentor_list.append(mentor_info)

    session.close()

    return jsonify({"assigned_mentors": mentor_list}), 200


#milstoneapi
@app.route('/milestone', methods=['POST'])
@jwt_required()
def milestone():
    current_user = get_jwt_identity()
    session = Session()
    
    try:
        # Check if the user exists
        user = session.query(User).filter_by(username=current_user).first()
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        data = request.get_json()

        # Validate required fields
        required_fields = ['user_id', 'mentor_id', 'milestone', 'check_meeting_id', 'check_id']
        missing_fields = [field for field in required_fields if data.get(field) is None]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400
        
        user_id = data['user_id']
        mentor_id = data['mentor_id']
        milestone = data['milestone']
        check_meeting_id = data['check_meeting_id']
        check_id = data['check_id']

        # Check if the milestone entry already exists for the given check_id and check_meeting_id
        existing_entry = session.query(UserMentorship).filter_by(
            check_id=check_id,
            check_meeting_id=check_meeting_id
        ).first()

        if existing_entry:
            return jsonify({"error": "Milestone already submitted for this check_id and check_meeting_id"}), 400

        # Create new milestone entry
        new_milestone = UserMentorship(
            user_id=user_id,
            mentor_id=mentor_id,
            milestone=milestone,
            check_meeting_id=check_meeting_id,
            check_id=check_id
        )

        session.add(new_milestone)
        session.commit()

        return jsonify({"message": "User mentorship created successfully"}), 201

    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()

#milestone new
@app.route('/mentor/milestone', methods=['POST'])
@jwt_required()
def mentor_save_milestone():
    current_user = get_jwt_identity()
    session = Session()
    try:
        # Get the User object for the current user
        user = session.query(User).filter_by(username=current_user).first()
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Check if the user is a mentor in Newmentortable
        mentor = session.query(Newmentor).filter_by(user_id=user.id).first()
        if not mentor:
            session.close()
            return jsonify({"message": "Only mentors can save milestones."}), 403

        data = request.get_json()
        required_fields = ['user_id', 'mentor_id', 'milestone', 'check_meeting_id', 'check_id']
        missing_fields = [field for field in required_fields if data.get(field) is None]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400

        user_id = data['user_id']
        mentor_id = data['mentor_id']
        milestone = data['milestone']
        check_meeting_id = data['check_meeting_id']
        check_id = data['check_id']

        # Check if the milestone entry already exists for the given check_id and check_meeting_id
        existing_entry = session.query(UserMentorship).filter_by(
            check_id=check_id,
            check_meeting_id=check_meeting_id
        ).first()
        if existing_entry:
            return jsonify({"error": "Milestone already submitted for this check_id and check_meeting_id"}), 400

        # Create new milestone entry
        new_milestone = UserMentorship(
            user_id=user_id,
            mentor_id=mentor_id,
            milestone=milestone,
            check_meeting_id=check_meeting_id,
            check_id=check_id
        )
        session.add(new_milestone)
        session.commit()
        return jsonify({"message": "User mentorship created successfully"}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()

@app.route('/api/milestone', methods=['GET'])
@jwt_required()
def get_milestone():
    session = Session()
    try:
        mentor_id = request.args.get('mentor_id')
        user_id = request.args.get('user_id')
        history = request.args.get('history', default='0')

        if not mentor_id or not user_id:
            return jsonify({"error": "mentor_id and user_id are required"}), 400

        milestone_entry = session.query(UserMentorship).filter_by(
            mentor_id=mentor_id,
            user_id=user_id
        ).first()

        if not milestone_entry:
            return jsonify({"error": "No milestone found for the given mentor_id and user_id"}), 404

        # Get milestone list
        milestone_list = milestone_entry.milestone or []

        # Default: latest milestone object
        latest_milestone = milestone_list[-1] if isinstance(milestone_list, list) and milestone_list else {}

        history_count = len(milestone_list)

        # Prepare response
        milestone_data = {
            "serial_number": milestone_entry.serial_number,
            "user_id": milestone_entry.user_id,
            "mentor_id": milestone_entry.mentor_id,
            "latest_milestone": latest_milestone,
            "check_id": milestone_entry.check_id,
            "check_meeting_id": milestone_entry.check_meeting_id,
            "created_at": milestone_entry.created_at,
            "history_count":history_count
        }

        # If history=1, include full milestone list and count
        if history == '1':
            milestone_data["milestone_history"] = milestone_list
            milestone_data["history_count"] = len(milestone_list)

        return jsonify(milestone_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


# update api milestone
@app.route('/api/milestone', methods=['PUT'])
@jwt_required()
def update_milestone():
    session = Session()
    try:
        data = request.get_json()
        serial_number = data.get('serial_number')
        mentor_id = data.get('mentor_id')
        user_id = data.get('user_id')
        new_milestone = data.get('milestone')

        if not serial_number or not mentor_id or not user_id or new_milestone is None:
            return jsonify({"error": "serial_number, mentor_id, user_id, and milestone are required"}), 400

        milestone_entry = session.query(UserMentorship).filter_by(
            serial_number=serial_number,
            mentor_id=mentor_id,
            user_id=user_id
        ).first()

        if not milestone_entry:
            return jsonify({"error": "No milestone found for the given serial_number, mentor_id, and user_id"}), 404

        # Defensive: ensure milestone is a list
        if milestone_entry.milestone is None:
            milestone_entry.milestone = []
        elif isinstance(milestone_entry.milestone, str):
            try:
                milestone_entry.milestone = json.loads(milestone_entry.milestone)
            except Exception:
                milestone_entry.milestone = []

        if not isinstance(milestone_entry.milestone, list):
            milestone_entry.milestone = [milestone_entry.milestone]

        milestone_entry.milestone.append(new_milestone)
        flag_modified(milestone_entry, "milestone")

        # Update other fields if provided
        if 'check_id' in data:
            milestone_entry.check_id = data['check_id']
        if 'check_meeting_id' in data:
            milestone_entry.check_meeting_id = data['check_meeting_id']

        session.commit()
        return jsonify({"message": "Milestone appended successfully"}), 200

    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()




# milestone check in meeting
@app.route('/checkmeeting/milestone', methods=['GET'])
@jwt_required()
def get_meetingmilestone():
    session = Session()
    try:
        mentor_id = request.args.get('mentor_id')
        user_id = request.args.get('user_id')
        
        

        if not mentor_id or not user_id:
            return jsonify({"error": "mentor_id or user_id is required"}), 400

        # Query the milestone based on user_id and mentor_id
        milestone_entry = session.query(UserMentorship).filter_by(
            mentor_id=mentor_id,
            user_id=user_id
        ).first()

        if not milestone_entry:
            return jsonify({"error": "No check_meeting_id found for the given mentor_id and user_id"}), 404

        # Convert the milestone entry to a dictionary
        milestone_data = {
            "serial_number": milestone_entry.serial_number,
            "user_id": milestone_entry.user_id,
            "mentor_id": milestone_entry.mentor_id,
            "milestone": milestone_entry.milestone,
            "check_id": milestone_entry.check_id,
            "check_meeting_id": milestone_entry.check_meeting_id,
            "created_at": milestone_entry.created_at
        }

        return jsonify(milestone_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


#progress apis
# Get Latest Milestone API
@app.route('/milestone/latest', methods=['GET'])
@jwt_required()
def get_latest_milestone():
    session = Session()
    try:
        mentor_id = request.args.get('mentor_id')
        user_id = request.args.get('user_id')

        if not mentor_id or not user_id:
            return jsonify({"error": "mentor_id and user_id are required"}), 400

        # Query the latest milestone based on user_id and mentor_id (ordered by created_at desc)
        milestone_entry = session.query(UserMentorship).filter_by(
            mentor_id=mentor_id,
            user_id=user_id
        ).order_by(UserMentorship.created_at.desc()).first()

        if not milestone_entry:
            return jsonify({"error": "No milestone found for the given mentor_id and user_id"}), 404

        # Convert the milestone entry to a dictionary
        milestone_data = {
            "serial_number": milestone_entry.serial_number,
            "user_id": milestone_entry.user_id,
            "mentor_id": milestone_entry.mentor_id,
            "milestone": milestone_entry.milestone,
            "check_id": milestone_entry.check_id,
            "check_meeting_id": milestone_entry.check_meeting_id,
            "created_at": milestone_entry.created_at
        }

        return jsonify(milestone_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


# Get Latest Feedback API
@app.route('/feedback/latest', methods=['GET'])
@jwt_required()
def get_latest_feedback():
    session = Session()
    try:
        mentor_id = request.args.get('mentor_id')
        user_id = request.args.get('user_id')

        if not mentor_id or not user_id:
            return jsonify({"error": "mentor_id and user_id are required"}), 400

        # Query the latest feedback based on user_id and mentor_id (ordered by created_at desc)
        feedback_entry = session.query(Feedback).filter_by(
            mentor_id=mentor_id,
            user_id=user_id
        ).order_by(Feedback.created_at.desc()).first()

        if not feedback_entry:
            return jsonify({"error": "No feedback found for the given mentor_id and user_id"}), 404

        # Convert the feedback entry to a dictionary
        feedback_data = {
            "feedback_id": feedback_entry.feedback_id,
            "user_id": feedback_entry.user_id,
            "mentor_id": feedback_entry.mentor_id,
            "milestone": feedback_entry.milestone,
            "milestone_achieved": feedback_entry.milestone_achieved,
            "next_steps_identified": feedback_entry.next_steps_identified,
            "progress_rating": feedback_entry.progress_rating,
            "mentor_responsibility": feedback_entry.mentor_responsibility,
            "user_responsibility": feedback_entry.user_responsibility,
            "check_id": feedback_entry.check_id,
            "check_meeting_id": feedback_entry.check_meeting_id,
            "created_at": feedback_entry.created_at
        }

        return jsonify(feedback_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


# Get Progress with Experts API - Dynamic Progress Calculation
@app.route('/progress', methods=['GET'])
@jwt_required()
def get_progress():
    session = Session()
    try:
        mentor_id = request.args.get('mentor_id')
        user_id = request.args.get('user_id')

        if not mentor_id or not user_id:
            return jsonify({"error": "mentor_id and user_id are required"}), 400

        # Get the latest milestone data
        milestone_entry = session.query(UserMentorship).filter_by(
            mentor_id=mentor_id,
            user_id=user_id
        ).order_by(UserMentorship.created_at.desc()).first()

        if not milestone_entry:
            return jsonify({"error": "No milestone found for the given mentor_id and user_id"}), 404

        # Get all feedback entries for this user-mentor pair
        feedback_entries = session.query(Feedback).filter_by(
            mentor_id=mentor_id,
            user_id=user_id
        ).order_by(Feedback.created_at.desc()).all()

        # Get the latest feedback
        latest_feedback = feedback_entries[0] if feedback_entries else None

        # Extract milestone data
        milestones = milestone_entry.milestone if milestone_entry.milestone else []
        total_milestones = len(milestones)
        
        if total_milestones == 0:
            return jsonify({"error": "No milestones defined"}), 400

        # Calculate completed milestones based on feedback
        completed_milestones = 0
        milestone_details = []
        pending_tasks = []
        completed_tasks = []

        for i, milestone in enumerate(milestones):
            milestone_name = milestone.get('milestone', '').lower()
            is_completed = False
            
            # Check if this milestone is completed based on feedback
            for feedback in feedback_entries:
                feedback_milestone = feedback.milestone.lower()
                # Match milestone names (case-insensitive)
                if (milestone_name in feedback_milestone or 
                    feedback_milestone in milestone_name or
                    f"milestone {i+1}" in feedback_milestone):
                    if feedback.milestone_achieved:
                        is_completed = True
                        completed_milestones += 1
                        break
            
            milestone_detail = {
                "milestone": milestone.get('milestone'),
                "description": milestone.get('description'),
                "expected_completion_date": milestone.get('expectedCompletionDate'),
                "mentor_fees": milestone.get('mentorFees'),
                "completed": is_completed,
                "completion_date": None  # You can add this if you track completion dates
            }
            milestone_details.append(milestone_detail)
            
            if is_completed:
                completed_tasks.append({
                    "task": milestone.get('milestone'),
                    "completion_date": milestone.get('expectedCompletionDate')  # or actual completion date
                })
            else:
                pending_tasks.append({
                    "task": milestone.get('milestone'),
                    "due_date": milestone.get('expectedCompletionDate')
                })

        # Calculate progress percentage
        progress_percentage = round((completed_milestones / total_milestones) * 100)

        # Prepare response data
        progress_data = {
            "milestones_completed": f"{completed_milestones}/{total_milestones}",
            "progress_percentage": progress_percentage,
            "latest_feedback": latest_feedback.milestone if latest_feedback else "No feedback available",
            "milestone_details": milestone_details,
            "pending_tasks": pending_tasks,
            "completed_tasks": completed_tasks,
            "total_milestones": total_milestones,
            "completed_count": completed_milestones,
            "user_id": user_id,
            "mentor_id": mentor_id,
            "last_updated": milestone_entry.created_at if milestone_entry else None
        }

        return jsonify(progress_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


# Helper function to normalize milestone names for comparison
def normalize_milestone_name(milestone_name):
    """
    Normalize milestone names for better matching
    """
    if not milestone_name:
        return ""
    
    # Convert to lowercase and remove extra spaces
    normalized = milestone_name.lower().strip()
    
    # Handle common variations
    normalized = normalized.replace("milestone", "").strip()
    
    return normalized


# Enhanced Progress API with better milestone matching
@app.route('/progress/enhanced', methods=['GET'])
@jwt_required()
def get_enhanced_progress():
    session = Session()
    try:
        mentor_id = request.args.get('mentor_id')
        user_id = request.args.get('user_id')

        if not mentor_id or not user_id:
            return jsonify({"error": "mentor_id and user_id are required"}), 400

        # Get the latest milestone data
        milestone_entry = session.query(UserMentorship).filter_by(
            mentor_id=mentor_id,
            user_id=user_id
        ).order_by(UserMentorship.created_at.desc()).first()

        if not milestone_entry:
            return jsonify({"error": "No milestone found"}), 404

        # Get all feedback entries
        feedback_entries = session.query(Feedback).filter_by(
            mentor_id=mentor_id,
            user_id=user_id
        ).order_by(Feedback.created_at.desc()).all()

        milestones = milestone_entry.milestone if milestone_entry.milestone else []
        total_milestones = len(milestones)
        
        if total_milestones == 0:
            return jsonify({"error": "No milestones defined"}), 400

        # Enhanced milestone matching and progress calculation
        completed_milestones = []
        pending_milestones = []
        
        for i, milestone in enumerate(milestones):
            milestone_name = milestone.get('milestone', '')
            is_completed = False
            completion_feedback = None
            
            # Check multiple matching strategies
            for feedback in feedback_entries:
                if feedback.milestone_achieved:
                    feedback_milestone = feedback.milestone.lower()
                    milestone_lower = milestone_name.lower()
                    
                    # Strategy 1: Exact match
                    if feedback_milestone == milestone_lower:
                        is_completed = True
                        completion_feedback = feedback
                        break
                    
                    # Strategy 2: Contains match
                    elif (milestone_lower in feedback_milestone or 
                          feedback_milestone in milestone_lower):
                        is_completed = True
                        completion_feedback = feedback
                        break
                    
                    # Strategy 3: Milestone number match
                    elif f"milestone {i+1}" in feedback_milestone:
                        is_completed = True
                        completion_feedback = feedback
                        break
            
            milestone_info = {
                "id": i + 1,
                "milestone": milestone_name,
                "description": milestone.get('description', ''),
                "expected_completion_date": milestone.get('expectedCompletionDate'),
                "mentor_fees": milestone.get('mentorFees'),
                "completed": is_completed,
                "completion_date": completion_feedback.created_at if completion_feedback else None,
                "progress_rating": completion_feedback.progress_rating if completion_feedback else None
            }
            
            if is_completed:
                completed_milestones.append(milestone_info)
            else:
                pending_milestones.append(milestone_info)

        # Calculate progress percentage
        completed_count = len(completed_milestones)
        progress_percentage = round((completed_count / total_milestones) * 100)

        # Get latest feedback info
        latest_feedback = feedback_entries[0] if feedback_entries else None

        # Prepare comprehensive response
        response_data = {
            "progress_summary": {
                "milestones_completed": f"{completed_count}/{total_milestones}",
                "progress_percentage": progress_percentage,
                "total_milestones": total_milestones,
                "completed_count": completed_count,
                "pending_count": len(pending_milestones)
            },
            "latest_feedback": {
                "milestone": latest_feedback.milestone if latest_feedback else None,
                "milestone_achieved": latest_feedback.milestone_achieved if latest_feedback else None,
                "progress_rating": latest_feedback.progress_rating if latest_feedback else None,
                "created_at": latest_feedback.created_at if latest_feedback else None
            } if latest_feedback else None,
            "milestones": {
                "completed": completed_milestones,
                "pending": pending_milestones
            },
            "metadata": {
                "user_id": int(user_id),
                "mentor_id": int(mentor_id),
                "last_updated": milestone_entry.created_at,
                "total_feedback_entries": len(feedback_entries)
            }
        }

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()

# new mentor api get,post
@app.route('/add_new_mentor', methods=['POST'])
@jwt_required()
def add_new_mentor():
    current_user = get_jwt_identity()
    session = Session()
   
    # Fetch the user based on the JWT identity
    user = session.query(User).filter_by(username=current_user).first()
   
    if not user:
        return jsonify({"message": "User not found"}), 404
   
    try:
        data = request.get_json()  
       
        user_id = user.id
        name = data.get('name')
        email = data.get('email')
        phone = data.get('phone', None)
        linkedin = data.get('linkedin')
        expertise = data.get('expertise')
        degree = data.get('degree')
        background = data.get('background')
        fee = data.get('fee', None)
        milestones = data.get('milestones')
        profile_picture = data.get('profile_picture', None)
        resume = data.get('resume', None)
        availability = data.get('availability', [])  # New field for availability
        current_role = data.get('current_role', None)
        work_experience = data.get('work_experience', None)
        interested_field = data.get('interested_field', None)
       
        # Validate availability data
        if availability:
            for slot in availability:
                if not all(key in slot for key in ['day', 'startTime', 'endTime']):
                    return jsonify({'error': 'Invalid availability format'}), 400
        
        if not all([user_id, name, email, linkedin, expertise, degree, background, milestones]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        print("availability==>",availability)
       
        new_mentor = Newmentor(
            user_id=user_id,
            name=name,
            email=email,
            phone=phone,
            linkedin=linkedin,
            expertise=expertise,
            degree=degree,
            background=background,
            fee=fee,
            milestones=milestones,
            profile_picture=profile_picture,
            resume=resume,
            availability=availability,  # Add availability to the new mentor
            current_role=current_role,
            work_experience=work_experience,
            interested_field=interested_field
        )
       
        session.add(new_mentor)
        session.commit()
        return jsonify({
            'message': 'New mentor added successfully', 
            'mentor_id': new_mentor.mentor_id,
            'availability': availability
        }), 201
    except IntegrityError:
        session.rollback()
        return jsonify({'error': 'Email already exists'}), 400
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    
    
#mentor assign
@app.route('/new_assign_mentor', methods=['POST'])
@jwt_required()
def new_assign_mentor():
    current_user = get_jwt_identity()
    session = Session()

    try:
        data = request.get_json()
        user_id = data.get('user_id')
        mentor_id = data.get('mentor_id')

        if not all([user_id, mentor_id]):
            return jsonify({'error': 'Missing required fields'}), 400

        # Validate the user and mentor
        user = session.query(User).filter_by(id=user_id).first()
        mentor = session.query(Newmentor).filter_by(mentor_id=mentor_id).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not mentor:
            return jsonify({'error': 'Mentor not found'}), 404

        # Check if the assignment already exists
        existing_assignment = session.query(UserMentorAssignment).filter_by(user_id=user_id, mentor_id=mentor_id).first()
        if existing_assignment:
            return jsonify({'error': 'User is already assigned to this mentor'}), 400

        # Assign mentor to user
        new_assignment = UserMentorAssignment(user_id=user_id, mentor_id=mentor_id)
        session.add(new_assignment)

        # Save notifications
        notification_message_user = f"You have been assigned a mentor: {mentor.name}."
        notification_message_mentor = f"You have been assigned to a new user: {user.username}."

        notification_for_user = Notification(user_id=user_id, message=notification_message_user)
        notification_for_mentor = Notification(user_id=mentor.user_id, message=notification_message_mentor)
        session.add(notification_for_user)
        session.add(notification_for_mentor)
        session.commit()

        # Emit notifications via Socket.IO
        user_notifications = session.query(Notification).filter_by(user_id=user_id).all()
        user_notification_data = [{
            "message": n.message,
            "timestamp": n.timestamp.isoformat(),
            "is_read": n.is_read
        } for n in user_notifications]

        # Emit notifications to the user
        socketio.emit('notifications', user_notification_data, room=f"user_{user_id}", namespace='/')

        # Emit real-time notifications to both user and mentor
        socketio.emit('notification', {'message': notification_message_user, 'mentor_id': mentor_id, 'user_id': user_id},
                      room=f"user_{user_id}", namespace='/')
        socketio.emit('notification', {'message': notification_message_mentor, 'mentor_id': mentor_id, 'user_id': user_id},
                      room=f"mentor_{mentor.user_id}", namespace='/')

        return jsonify({"message": "Mentor assigned successfully."}), 200

    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

#get mentor list
@app.route('/get_assigned_mentors', methods=['GET'])
@jwt_required()
def get_assigned_mentors_list():
    current_user = get_jwt_identity()  # Get the identity from JWT (likely an email)
    session = Session()

    try:
        # Fetch user ID using the email (if JWT stores email)
        user = session.query(User).filter_by(username=current_user).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        user_id = user.id

        # Query the assignments for the logged-in user
        assignments = session.query(UserMentorAssignment).filter_by(user_id=user_id).all()

        if not assignments:
            return jsonify({'message': 'No mentors assigned to this user'}), 404

        # Retrieve mentor details for the assignments
        mentors = [
            {
                "mentor_id": assignment.mentor.mentor_id,
                "name": assignment.mentor.name,
                "email": assignment.mentor.email,
                "phone": assignment.mentor.phone,
                "linkedin": assignment.mentor.linkedin,
                "expertise": assignment.mentor.expertise,
                "degree": assignment.mentor.degree,
                "background": assignment.mentor.background,
                "fee": assignment.mentor.fee,
                "milestones": assignment.mentor.milestones,
                "profile_picture": assignment.mentor.profile_picture,
                "resume": assignment.mentor.resume,
                "availability":assignment.mentor.availability
            }
            for assignment in assignments
        ]

        return jsonify({"mentors": mentors}), 200

    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()




@app.route('/recommended_mentors', methods=['GET'])
@jwt_required()
def get_recommended_mentors():
    session = Session()
    try:
        # Fetch the current user based on the JWT token
        current_user = get_jwt_identity()
        user = session.query(User).filter_by(username=current_user).first()

        if not user:
            return jsonify({"message": "User not found"}), 404

        # Fetch the user's stream name from UserDetails
        user_details = user.details  # Access the UserDetails relationship
        if not user_details or not user_details.stream_name:
            return jsonify({"error": "User's stream not found"}), 400

        stream = user_details.stream_name  # Extract the user's stream name

        # Fetch all mentors, excluding the current user's profile
        mentors = session.query(Newmentor).filter(
            Newmentor.user_id != user.id
        ).all()

        if not mentors:
            return jsonify({"message": "No mentors found"}), 404

        # Add recommendation priority
        def recommendation_priority(mentor):
            if mentor.expertise.lower() == stream.lower():
                return 1  # Exact match
            elif stream.lower() in mentor.expertise.lower():
                return 2  # Partial match
            else:
                return 3  # No match

        # Sort mentors based on the recommendation priority
        sorted_mentors = sorted(mentors, key=recommendation_priority)

        # Format the response
        mentors_list = [
            {
                "mentor_id": mentor.mentor_id,
                "name": mentor.name,
                "email": mentor.email,
                "phone": mentor.phone,
                "linkedin": mentor.linkedin,
                "expertise": mentor.expertise,
                "degree": mentor.degree,
                "background": mentor.background,
                "fee": mentor.fee,
                "milestones": mentor.milestones,
                "profile_picture": mentor.profile_picture,
                "resume": mentor.resume,
                "created_at": mentor.created_at
            }
            for mentor in sorted_mentors
        ]

        return jsonify({"mentors": mentors_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        session.close()


#new recommend
@app.route('/api/recommend-mentors', methods=['GET'])
@jwt_required()
def recommend_mentors():
    current_user_email = get_jwt_identity()

    session = Session()

    try:
        user = session.query(User).filter_by(username=current_user_email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        basic_info = session.query(BasicInfo).filter_by(emailid=current_user_email).first()
        if not basic_info:
            return jsonify({'error': 'User basic_info not found'}), 404

        high_education = (basic_info.high_education or '').lower()
        interested_stream = (basic_info.interested_stream or '').lower()

        # Combine user fields for fuzzy search, you can tweak this
        search_terms = [high_education, interested_stream]

        # Minimum similarity threshold (0 to 1), tweak for sensitivity
        similarity_threshold = 0.3

        filters = []
        for term in search_terms:
            if term:
                filters.append(func.similarity(Newmentor.degree, term) > similarity_threshold)
                filters.append(func.similarity(Newmentor.expertise, term) > similarity_threshold)
                filters.append(func.similarity(Newmentor.background, term) > similarity_threshold)

        # Query with OR of fuzzy similarity filters
        recommended_mentors = session.query(Newmentor).filter(or_(*filters)).all()

        mentor_data = [
            {
                'mentor_id': m.mentor_id,
                'name': m.name,
                'email': m.email,
                'phone': m.phone,
                'linkedin': m.linkedin,
                'expertise': m.expertise,
                'degree': m.degree,
                'background': m.background,
                'fee': m.fee,
                'milestones': m.milestones,
                'profile_picture': m.profile_picture,
                'resume': m.resume,
                'availability': m.availability,
                'created_at': m.created_at
            } for m in recommended_mentors
        ]

        return jsonify({'recommended_mentors': mentor_data}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


# @app.route('/recommended_mentors', methods=['GET'])
# @jwt_required()
# def get_recommended_mentors():
#     session = Session()
#     try:
#         # Fetch the current user based on the JWT token
#         current_user = get_jwt_identity()
#         user = session.query(User).filter_by(username=current_user).first()

#         if not user:
#             return jsonify({"message": "User not found"}), 404

#         # Fetch the user's stream name from UserDetails
#         user_details = user.details  # Access the UserDetails relationship
#         if not user_details or not user_details.stream_name:
#             return jsonify({"error": "User's stream not found"}), 400

#         stream = user_details.stream_name  # Extract the user's stream name

#         # Fetch all assigned mentor IDs for the current user
#         assigned_mentor_ids = session.query(UserMentorAssignment.mentor_id).filter_by(user_id=user.id).all()
#         assigned_mentor_ids = {row[0] for row in assigned_mentor_ids}  # Convert to a set of mentor IDs

#         # Fetch all mentors excluding the assigned mentors, the current user's profile, and where the logged-in user is also a mentor
#         mentors = session.query(Newmentor).filter(
#             Newmentor.user_id != user.id,  # Exclude logged-in user as a mentor
#             ~Newmentor.mentor_id.in_(assigned_mentor_ids)  # Exclude already assigned mentors
#         ).all()

#         # Add recommendation priority
#         def recommendation_priority(mentor):
#             if mentor.expertise.lower() == stream.lower():
#                 return 1  # Exact match
#             elif stream.lower() in mentor.expertise.lower():
#                 return 2  # Partial match
#             else:
#                 return 3  # No match

#         # Sort mentors based on the recommendation priority
#         sorted_mentors = sorted(mentors, key=recommendation_priority)

#         # Format the response
#         mentors_list = [
#             {
#                 "mentor_id": mentor.mentor_id,
#                 "name": mentor.name,
#                 "email": mentor.email,
#                 "phone": mentor.phone,
#                 "linkedin": mentor.linkedin,
#                 "expertise": mentor.expertise,
#                 "degree": mentor.degree,
#                 "background": mentor.background,
#                 "fee": mentor.fee,
#                 "milestones": mentor.milestones,
#                 "profile_picture": mentor.profile_picture,
#                 "resume": mentor.resume,
#                 "created_at": mentor.created_at
#             }
#             for mentor in sorted_mentors
#         ]

#         return jsonify({"mentors": mentors_list}), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

#     finally:
#         session.close()





#review api
@app.route('/api/reviews', methods=['GET'])
def get_all_reviews():
    session = Session()
    try:
        reviews = session.query(Review).all()
        review_list = []
        for review in reviews:
            review_list.append({
                "id": review.id,
                "date": review.date.isoformat() if review.date else None,
                "ReviewIndetail": review.ReviewIndetail,
                "userDetails": review.userDetails,  # Will be returned as JSON
                "valid": review.valid
            })
        return jsonify(review_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()

@app.route('/api/reviews', methods=['POST'])
def upload_reviews():
    session = Session()
    try:
        data = request.get_json()
        if not isinstance(data, list):
            return jsonify({"error": "Expected a list of reviews"}), 400

        for item in data:
            review = Review(
                date=datetime.strptime(item['date'], "%Y-%m-%d").date(),
                ReviewIndetail=item.get('ReviewIndetail'),
                userDetails=item.get('userDetails'),
                valid=item.get('valid')
            )
            session.add(review)  # use add instead of merge since ID is auto
        session.commit()
        return jsonify({"message": "Reviews inserted successfully"}), 200
    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()
        
#contact us api
@app.route('/api/contact-us', methods=['POST'])
def submit_contact():
    session = Session()
    try:
        data = request.get_json()

        fullname = data.get('fullname')
        email = data.get('email')
        phone_number = data.get('phone_number')
        description = data.get('description')

        if not all([fullname, email, description]):
            return jsonify({"error": "fullname, email, and description are required"}), 400

        contact = ContactUs(
            fullname=fullname,
            email=email,
            phone_number=phone_number,
            description=description
        )

        session.add(contact)
        session.commit()

        return jsonify({"message": "Contact form submitted successfully"}), 201
    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route('/api/intent', methods=['POST'])
@jwt_required()
def create_intent():
    current_user_id = get_jwt_identity()
    session = Session()
    try:
        # Fetch user email from BasicInfo using useruniqid
        user_info = session.query(BasicInfo).filter_by(useruniqid=str(current_user_id)).first()
        if not user_info:
            return jsonify({'error': 'User basic info not found'}), 404
        email = user_info.emailid
        useruniqid = user_info.useruniqid

        # Check if intent already exists for this user
        existing_intent = session.query(Intent).filter_by(useruniqid=useruniqid).first()
        if existing_intent:
            return jsonify({'error': 'Intent already exists for this user'}), 400

        data = request.get_json()
        area_exploring = data.get('area_exploring')
        goal_challenge = data.get('goal_challenge')
        support_types = data.get('support_types', [])  # Should be a list/array

        # Save intent
        new_intent = Intent(
            useruniqid=useruniqid,
            email=email,
            area_exploring=area_exploring,
            goal_challenge=goal_challenge,
            support_types=support_types
        )
        session.add(new_intent)
        session.commit()
        return jsonify({'message': 'Intent saved successfully', 'id': new_intent.id}), 201
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/intent', methods=['GET'])
@jwt_required()
def get_intent():
    current_user_id = get_jwt_identity()
    session = Session()
    try:
        intent = session.query(Intent).filter_by(useruniqid=str(current_user_id)).order_by(Intent.created_at.desc()).first()
        if not intent:
            return jsonify({'error': 'No intent found for this user'}), 404
        result = {
            'id': intent.id,
            'useruniqid': intent.useruniqid,
            'email': intent.email,
            'area_exploring': intent.area_exploring,
            'goal_challenge': intent.goal_challenge,
            'support_types': intent.support_types,
            'created_at': intent.created_at.isoformat() if intent.created_at else None
        }
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()



@app.route('/api/basic-info', methods=['POST'])
def create_basic_info():
    data = request.get_json()

    # Validate required fields
    if 'emailid' not in data or 'useruniqid' not in data:
        return jsonify({'error': 'Missing required field: emailid or useruniqid'}), 400

    session = Session()

    try:
        # Check if basic_info already exists for this emailid or useruniqid
        existing_user = session.query(BasicInfo).filter(
            (BasicInfo.emailid == data['emailid']) |
            (BasicInfo.useruniqid == data['useruniqid'])
        ).first()

        if existing_user:
            return jsonify({'error': 'This user already has a basic_info record'}), 400

        if data.get('role_based') is None:
            return jsonify({'error': 'role_based field is required'}), 400
        
        role_based=data.get('role_based')
        print("role_based==>",role_based)
        


        # Create new basic_info record using manually provided useruniqid
        new_info = BasicInfo(
            emailid=data['emailid'],
            useruniqid=data['useruniqid'],
            firstname=data.get('firstname'),
            lastname=data.get('lastname'),
            high_education=data.get('high_education'),
            interested_stream=data.get('interested_stream'),
            data_filed=data.get('data_filed', False),  # Default to False
            role_based=data.get('role_based'),  # Default to None
            work_experience=data.get('work_experience')
        )

        session.add(new_info)
        session.commit()

        return jsonify({'message': 'Basic info added successfully', 'id': new_info.id}), 201

    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

        
        
@app.route('/api/basic-info', methods=['GET'])
@jwt_required()
def get_basic_info():
    # Get the current logged-in user's ID from JWT
    current_user_id = get_jwt_identity()

    session = Session()

    try:
        # Fetch the basic_info record associated with the current user
        user_info = session.query(BasicInfo).filter_by(useruniqid=str(current_user_id)).first()

        if not user_info:
            return jsonify({'error': 'No basic_info record found for this user'}), 404

        # Serialize and return the basic_info record
        result = {
            'id': user_info.id,
            'emailid': user_info.emailid,
            'useruniqid': user_info.useruniqid,
            'firstname': user_info.firstname,
            'lastname': user_info.lastname,
            'high_education': user_info.high_education,
            'interested_stream': user_info.interested_stream,
            'data_filed': user_info.data_filed,
            'role_based': user_info.role_based,
            'work_experience': user_info.work_experience
        }
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()
        
@app.route('/api/basic-info', methods=['PUT'])
@jwt_required()
def update_basic_info():
    # Get current logged-in user's ID from JWT
    current_user_id = get_jwt_identity()

    session = Session()

    try:
        # Fetch the basic_info record for this user
        user_info = session.query(BasicInfo).filter_by(useruniqid=str(current_user_id)).first()

        if not user_info:
            return jsonify({'error': 'No basic_info record found for this user'}), 404

        # Get the JSON data from request
        data = request.get_json()

        # Update fields if present in request data
        if 'emailid' in data:
            user_info.emailid = data['emailid']
        if 'firstname' in data:
            user_info.firstname = data['firstname']
        if 'lastname' in data:
            user_info.lastname = data['lastname']
        if 'high_education' in data:
            user_info.high_education = data['high_education']
        if 'interested_stream' in data:
            user_info.interested_stream = data['interested_stream']
        if 'data_filed' in data:
            user_info.data_filed = data['data_filed']
        if 'role_based' in data:
            user_info.role_based = data['role_based']

        # Commit changes
        session.commit()

        return jsonify({'message': 'Basic info updated successfully'}), 200

    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500

    finally:
        session.close()


        
@app.route('/assigned_users', methods=['GET'])
@jwt_required()
def get_assigned_users():
    current_user = get_jwt_identity()
    session = Session()

    # Fetch user object based on current_user
    user = session.query(User).filter_by(username=current_user).first()
    

    

    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    # Check if the user is a mentor
    # mentor = session.query(Mentor).join(user_mentor_association).filter(
    #     user_mentor_association.c.mentor_id == user.id
    # ).first()
    mentor = session.query(Mentor).filter_by(username=current_user).first()

    print("mentorid==?",mentor)


    if not mentor:
        session.close()
        return jsonify({"message": "User is not a mentor"}), 403

    # Fetch assigned users for this mentor
    assigned_users = session.query(User).join(user_mentor_association).filter(
        user_mentor_association.c.mentor_id == mentor.id
    ).all()

    user_list = []
    for assigned_user in assigned_users:
        user_info = {
            "id": assigned_user.id,
            "username": assigned_user.username,
            "first_name": assigned_user.details.first_name if assigned_user.details else None,
            "last_name": assigned_user.details.last_name if assigned_user.details else None,
            "email": assigned_user.username,  # Assuming username is used as email
        }
        user_list.append(user_info)

    session.close()

    return jsonify({"assigned_users": user_list}), 200



@socketio.on('send_message')
def handle_message(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    message_text = data.get('message')

    session = Session()
    
    try:
        # Check if sender and receiver are both Users
        sender = session.query(User).filter_by(id=sender_id).first()
        receiver = session.query(User).filter_by(id=receiver_id).first()

        if not sender or not receiver:
            emit('message_status', {'success': False, 'message': 'Sender or receiver not found'})
            return

        new_message = Msg(sender_id=sender_id, receiver_id=receiver_id, message=message_text)
        session.add(new_message)
        session.commit()

        room = f"{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"
        emit('receive_message', {'sender_id': sender_id, 'message': message_text, 'timestamp': new_message.timestamp.isoformat()}, room=room)
    except Exception as e:
        emit('message_status', {'success': False, 'message': str(e)})
    finally:
        session.close()


@socketio.on('join_room')
def handle_join_room(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')

    if not sender_id or not receiver_id:
        emit('message_error', {"error": "sender_id and receiver_id are required"})
        return
    
    room = f"{min(sender_id, receiver_id)}_{max(sender_id, receiver_id)}"
    join_room(room)
    emit('joined_room', {"room": room})

@socketio.on('get_messages')
def handle_get_messages(data):
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    
    if not sender_id or not receiver_id:
        emit('message_error', {"error": "sender_id and receiver_id are required"})
        return
    
    session = Session()
    try:
        messages = session.query(Msg).filter(
            or_(
                and_(Msg.sender_id == sender_id, Msg.receiver_id == receiver_id),
                and_(Msg.sender_id == receiver_id, Msg.receiver_id == sender_id)
            )
        ).order_by(Msg.timestamp).all()
        
        message_list = [
            {"sender_id": msg.sender_id, "receiver_id": msg.receiver_id, "message": msg.message, "timestamp": msg.timestamp.isoformat()}
            for msg in messages
        ]
        
        emit('message_history', {"messages": message_list})
    except Exception as e:
        emit('message_error', {"error": str(e)})
    finally:
        session.close()

if __name__ == '__main__':
    socketio.run(app, debug=True)

# Delete All Users Endpoint
@app.route('/delete_users', methods=['DELETE'])
@jwt_required()
def delete_users():
    current_user = get_jwt_identity()
    session = Session()

    session.query(User).delete()
    session.commit()
    session.close()

    return jsonify({"message": "All users deleted successfully"}), 200

# Delete All Mentors Endpoint
@app.route('/delete_mentors', methods=['DELETE'])
@jwt_required()
def delete_mentors():
    current_user = get_jwt_identity()
    session = Session()

    session.query(Mentor).delete()
    session.commit()
    session.close()

    return jsonify({"message": "All mentors deleted successfully"}), 200




if __name__ == '__main__':
    app.run(debug=True)

                    



                    


from flask import Flask, request, jsonify, redirect, url_for
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Column, Integer, String, ForeignKey, Text, DateTime, Boolean
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
from sqlalchemy import LargeBinary
import base64
from datetime import datetime
from flask_socketio import emit
from flask_socketio import SocketIO
from flask_socketio import join_room

import stripe
import razorpay
from razorpay import Client






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
    user_id = Column(Integer, ForeignKey('users.id'))  # Add the user_id column as a foreign key to User

    users = relationship("User", secondary=user_mentor_association, back_populates="mentors")
    stream = relationship("Stream", backref="mentors")

    


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
Base.metadata.create_all(engine)


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
    
    
class Notification(Base):
    __tablename__ = 'notifications'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))  # The user ID for both users and mentors
    message = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False)
    
Session = sessionmaker(bind=engine)

app = Flask(__name__)
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

    return jsonify({"message": "User registered successfully"}), 201


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
    data_fill = user.details.data_filled if user.details else False

    access_token = create_access_token(identity=username, expires_delta=False)
    session.close()
    return jsonify({"access_token": access_token, "data_fill": data_fill}), 200

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

@app.route('/user_details', methods=['GET', 'POST'])
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
            return jsonify({"message": "User details already exist"}), 400

        if not user.details:
            user.details = UserDetails(user=user)

        user.details.first_name = data.get('first_name', user.details.first_name)
        user.details.last_name = data.get('last_name', user.details.last_name)
        user.details.school_name = data.get('school_name', user.details.school_name)
        user.details.bachelors_degree = data.get('bachelors_degree', user.details.bachelors_degree)
        user.details.masters_degree = data.get('masters_degree', user.details.masters_degree)
        user.details.certification = data.get('certification', user.details.certification)
        user.details.activity = data.get('activity', user.details.activity)
        user.details.country = data.get('country', user.details.country)
        user.details.stream_name = data.get('stream_name', user.details.stream_name) 

        user.details.data_filled = True

        try:
            session.commit()
            session.close()
            return jsonify({"message": "User details added/updated successfully"}), 200
        except Exception as e:
            session.rollback()
            session.close()
            return jsonify({"message": f"Failed to add/update user details: {str(e)}"}), 500


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
            mentor_ids_same_stream.append(mentor.id)  # Collect mentor IDs for further lookup

        # Step 2: Fetch mentors related to the mentors in the same stream, but exclude the mentors already retrieved
        related_mentors = session.query(Mentor).filter(
            Mentor.users.any(User.mentors.any(Mentor.id.in_(mentor_ids_same_stream))),
            ~Mentor.id.in_(mentor_ids_same_stream)  # Exclude mentors from mentors_with_same_stream
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




# razor pay mentor
@app.route('/create_order', methods=['POST'])
def create_order():
    session = Session()
    data = request.get_json()
    mentor_id = data.get('mentor_id') 
    mentor = session.query(Mentor).filter_by(id=mentor_id).first()
    if mentor is None:
        session.close()
        return jsonify({"message": "Mentor not found"}), 404
      
    mentor_fees = float(mentor.fees)*100
    

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

                    

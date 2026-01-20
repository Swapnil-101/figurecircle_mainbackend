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
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from uuid import uuid4
from random import randint

CALENDLY_API_KEY = '5LMFYDPIVF5ADVOCQYFW437GGWJZOSDT'



load_dotenv()

connection_string = "postgresql://neondb_owner:Pl8cWUu0iLHn@ep-tiny-haze-a1w7wrrg.ap-southeast-1.aws.neon.tech/figure_circle"


engine = create_engine(
    connection_string,
    connect_args={'connect_timeout': 10},
    pool_pre_ping=True,  # Test connections before using them
    pool_recycle=3600,   # Recycle connections after 1 hour
    pool_size=10,        # Number of connections to maintain in the pool
    max_overflow=20      # Maximum number of connections that can be created beyond pool_size
)

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
    industry = Column(String(150), nullable=True)
    role = Column(String(150), nullable=True)
    intent = Column(String(255), nullable=True)
    bachelor = Column(String(255), nullable=True)

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
    current_role = Column(String(255), nullable=True)
    interested_field = Column(String(255), nullable=True)
    expertise = Column(String(255), nullable=True)
    degree = Column(String(255), nullable=True)
    background = Column(Text, nullable=True)
    fee = Column(String(255), nullable=True)
    milestones = Column(Integer, nullable=True)
    profile_picture = Column(String(500), nullable=True)
    resume = Column(String(500), nullable=True)
    availability = Column(JSON, nullable=True)  # New column to store availability as JSON
    intent_price = Column(JSON, nullable=True)  # New column to store intent and price pairs as JSON
    created_at = Column(DateTime, default=datetime.utcnow)
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

# Categories table for Education, Industry, Experience Level, Role, Skills
class Category(Base):
    __tablename__ = 'categories'

    id = Column(Integer, primary_key=True, autoincrement=True)
    category_type = Column(String(50), nullable=False)  # 'education', 'industry', 'experience_level', 'role', 'skills'
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (UniqueConstraint('category_type', 'name', name='_category_type_name_uc'),)
    
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

class MilestoneHistory(Base):
    __tablename__ = 'milestone_history'

    id = Column(Integer, primary_key=True, autoincrement=True)
    serial_number = Column(Integer, nullable=False)  # Reference to UserMentorship
    user_id = Column(Integer, nullable=False)
    mentor_id = Column(Integer, nullable=False)
    milestone_data = Column(JSONB, nullable=False)  # Previous milestone state
    edited_at = Column(DateTime, default=datetime.utcnow)
    edited_by = Column(String, nullable=True)  # Username from JWT

class MeetingHost(Base):
    __tablename__ = 'meeting_hosts'

    room_id = Column(String(50), primary_key=True)
    host_peer_id = Column(String(100), nullable=False)
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
    sender_id = Column(Integer, ForeignKey('users.id'), nullable=True)  # Sender ID for chat messages
    mentor_id = Column(Integer, ForeignKey('mentors.id'), nullable=True)  # Optional mentor_id for mentor-related notifications
    message = Column(String)
    message_type = Column(String, default='notification')  # 'notification' or 'chat'
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False)
    
    
    
class Wallet(Base):
    __tablename__ = 'wallets'

    id = Column(Integer, primary_key=True, autoincrement=True)
    owner_type = Column(String(20), nullable=False)  # 'user' or 'mentor'
    owner_id = Column(Integer, nullable=False)
    balance_paise = Column(Integer, nullable=False, default=0)
    currency = Column(String(3), nullable=False, default='INR')
    razorpay_contact_id = Column(String(100), nullable=True)
    razorpay_fund_account_id = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    transactions = relationship('WalletTransaction', back_populates='wallet', cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint('owner_type', 'owner_id', name='_wallet_owner_uc'),
    )


class WalletTransaction(Base):
    __tablename__ = 'wallet_transactions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    wallet_id = Column(Integer, ForeignKey('wallets.id', ondelete='CASCADE'), nullable=False, index=True)
    transaction_type = Column(String(20), nullable=False)  # 'credit' or 'debit'
    amount_paise = Column(Integer, nullable=False)  # Stored in paise to avoid floating point issues
    currency = Column(String(3), nullable=False, default='INR')
    status = Column(String(20), nullable=False, default='pending')  # 'pending', 'completed', 'failed'
    razorpay_order_id = Column(String(100), nullable=True)
    razorpay_payment_id = Column(String(100), nullable=True)
    razorpay_signature = Column(String(255), nullable=True)
    notes = Column(JSON, nullable=True)
    closing_balance_paise = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    wallet = relationship('Wallet', back_populates='transactions')

    __table_args__ = (
        UniqueConstraint('razorpay_order_id', 'wallet_id', name='_wallet_order_uc'),
    )


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

#trial meeting
class TrialSchedule(Base):
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
    __table_args__ = (UniqueConstraint('user_id', 'mentor_id', name='_user_mentor_intent_uc'),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    useruniqid = Column(String(100), nullable=False)
    email = Column(String(255), nullable=False)
    area_exploring = Column(String(255), nullable=True)
    goal_challenge = Column(String(255), nullable=True)
    support_types = Column(JSON, nullable=True)  # Store as JSON array
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, nullable=False)
    mentor_id = Column(Integer, nullable=False)

# Meeting Notification table
class MeetingNotification(Base):
    __tablename__ = 'meeting_notifications'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False)  # The user who will receive the notification
    mentor_id = Column(Integer, nullable=False)  # The mentor involved
    schedule_id = Column(Integer, nullable=True)  # Reference to the schedule/meeting
    notification_type = Column(String(50), nullable=False)  # 'meeting_scheduled', 'meeting_reminder', 'meeting_cancelled', 'message'
    title = Column(String(255), nullable=False)  # Notification title
    message = Column(Text, nullable=False)  # Notification message
    meeting_datetime = Column(DateTime, nullable=True)  # When the meeting is scheduled
    meeting_link = Column(String(500), nullable=True)  # Meeting link if available
    is_read = Column(Boolean, default=False)  # Whether the notification has been read
    created_at = Column(DateTime, default=datetime.utcnow)  # When notification was created
    read_at = Column(DateTime, nullable=True)  # When notification was read
    notification_data = Column(JSON, nullable=True)  # Additional data like sender info for messages

class OTP(Base):
    __tablename__ = 'otps'

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False)
    otp = Column(String(6), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_verified = Column(Boolean, default=False)

    
Session = sessionmaker(bind=engine)

VALID_WALLET_OWNER_TYPES = {'user', 'mentor'}


def _get_authenticated_entities(session, identity):
    """
    Returns a tuple of (user, admin) for the provided JWT identity.
    Only one of them will be non-null.
    """
    if not identity:
        return None, None

    user = session.query(User).filter_by(username=identity).first()
    if user:
        return user, None

    admin = session.query(Admin).filter_by(username=identity).first()
    return None, admin


def ensure_wallet_access(session, identity, owner_type, owner_id):
    """
    Validates that the current identity is allowed to manage the requested wallet.
    Returns (owner_record, user, admin, error_response)
    """
    if owner_type not in VALID_WALLET_OWNER_TYPES:
        return None, None, None, (jsonify({'error': 'Invalid owner_type supplied'}), 400)

    user, admin = _get_authenticated_entities(session, identity)

    if owner_type == 'user':
        owner = session.query(User).filter_by(id=owner_id).first()
        if not owner:
            return None, None, None, (jsonify({'error': 'User not found'}), 404)
        if admin or (user and user.id == owner_id):
            return owner, user, admin, None
        return None, None, None, (jsonify({'error': 'Unauthorized to access this user wallet'}), 403)

    # owner_type == 'mentor'
    owner = session.query(Newmentor).filter_by(mentor_id=owner_id).first()
    if not owner:
        return None, None, None, (jsonify({'error': 'Mentor not found'}), 404)
    if admin or (user and owner.user_id == user.id):
        return owner, user, admin, None
    return None, None, None, (jsonify({'error': 'Unauthorized to access this mentor wallet'}), 403)


def rupees_to_paise(amount):
    try:
        value = Decimal(str(amount)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    except (InvalidOperation, TypeError):
        raise ValueError('Invalid amount format. Provide a numeric value with at most two decimal places.')

    if value <= 0:
        raise ValueError('Amount must be greater than zero.')

    paise = int((value * 100).to_integral_value(rounding=ROUND_HALF_UP))
    return paise


def paise_to_rupees(paise):
    if paise is None:
        return 0.0
    return float(Decimal(paise) / Decimal(100))


def get_or_create_wallet(session, owner_type, owner_id):
    wallet = (
        session.query(Wallet)
        .filter_by(owner_type=owner_type, owner_id=owner_id)
        .first()
    )
    if not wallet:
        wallet = Wallet(owner_type=owner_type, owner_id=owner_id)
        session.add(wallet)
        session.flush()
    return wallet


def serialize_wallet(wallet):
    return {
        'wallet_id': wallet.id,
        'owner_type': wallet.owner_type,
        'owner_id': wallet.owner_id,
        'balance': paise_to_rupees(wallet.balance_paise),
        'balance_paise': wallet.balance_paise,
        'currency': wallet.currency,
        'razorpay_contact_id': wallet.razorpay_contact_id,
        'razorpay_fund_account_id': wallet.razorpay_fund_account_id,
        'created_at': wallet.created_at.isoformat() if wallet.created_at else None,
        'updated_at': wallet.updated_at.isoformat() if wallet.updated_at else None,
    }


def serialize_wallet_transaction(transaction):
    return {
        'transaction_id': transaction.id,
        'wallet_id': transaction.wallet_id,
        'transaction_type': transaction.transaction_type,
        'amount': paise_to_rupees(transaction.amount_paise),
        'amount_paise': transaction.amount_paise,
        'currency': transaction.currency,
        'status': transaction.status,
        'razorpay_order_id': transaction.razorpay_order_id,
        'razorpay_payment_id': transaction.razorpay_payment_id,
        'closing_balance': paise_to_rupees(transaction.closing_balance_paise) if transaction.closing_balance_paise is not None else None,
        'closing_balance_paise': transaction.closing_balance_paise,
        'notes': transaction.notes,
        'created_at': transaction.created_at.isoformat() if transaction.created_at else None,
    }


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
socketio = SocketIO(
    app, 
    cors_allowed_origins="*",
    async_mode='threading',  # Use threading for better WebSocket support
    logger=True,  # Enable logging for debugging
    engineio_logger=True,  # Enable Engine.IO logging
    ping_timeout=60,  # Increase timeout
    ping_interval=25,  # Keep connection alive
    manage_session=False  # Don't manage Flask sessions
)
jwt = JWTManager(app)

client = WebApplicationClient(app.config['GOOGLE_CLIENT_ID'])


def generate_otp():
    return str(randint(100000, 999999))

def send_otp_email(email, otp):
    msg = Message('Your OTP for FigureCircle', sender='figurecircle2024@gmail.com', recipients=[email])
    msg.body = f'Your OTP is {otp}. It is valid for 10 minutes.'
    mail.send(msg)

@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email')
    request_type = data.get('type') # 'register' or 'forgot'

    if not email or not request_type:
        return jsonify({"message": "Missing email or type"}), 400

    session = Session()
    
    user = session.query(User).filter_by(username=email).first()
    
    if request_type == 'register':
        if user:
            session.close()
            return jsonify({"message": "User already exists"}), 400
    elif request_type == 'forgot':
        if not user:
            session.close()
            return jsonify({"message": "User not found"}), 404
    else:
        session.close()
        return jsonify({"message": "Invalid type"}), 400

    otp = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    # Check if an active OTP already exists for this email, invalidate it or update it
    existing_otp = session.query(OTP).filter_by(email=email).first()
    if existing_otp:
        existing_otp.otp = otp
        existing_otp.expires_at = expires_at
        existing_otp.is_verified = False
    else:
        new_otp = OTP(email=email, otp=otp, expires_at=expires_at)
        session.add(new_otp)
    
    try:
        send_otp_email(email, otp)
        session.commit()
        session.close()
        return jsonify({"message": "OTP sent successfully"}), 200
    except Exception as e:
        session.rollback()
        session.close()
        return jsonify({"message": f"Failed to send OTP: {str(e)}"}), 500

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
            session.flush()  # Flush to get the user ID
            
            # Create empty user details for the new user
            new_user_details = UserDetails(user=user)
            session.add(new_user_details)
            
            # Automatically create wallet for the new user
            user_wallet = Wallet(owner_type='user', owner_id=user.id)
            session.add(user_wallet)
            
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
    # username = data.get('username')
    # password = data.get('password')
    # otp = data.get('otp')

    # if not username or not password or not otp:
    #     return jsonify({"message": "Missing username, password, or OTP"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    session = Session()

    # Verify OTP
    # otp_record = session.query(OTP).filter_by(email=username, otp=otp, is_verified=False).first()
    # if not otp_record:
    #     session.close()
    #     return jsonify({"message": "Invalid OTP"}), 400
    
    # if otp_record.expires_at < datetime.utcnow():
    #     session.close()
    #     return jsonify({"message": "OTP expired"}), 400

    # Check if the username already exists
    if session.query(User).filter_by(username=username).first():
        session.close()
        return jsonify({"message": "Username already exists"}), 400

    # Create a new user
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password)
    session.add(new_user)
    session.flush()  # Flush to get the user ID

    # Create empty user details for the new user
    new_user_details = UserDetails(user=new_user)
    session.add(new_user_details)

    # Automatically create wallet for the new user
    user_wallet = Wallet(owner_type='user', owner_id=new_user.id)
    session.add(user_wallet)

    # Mark OTP as verified
    # otp_record.is_verified = True
    # session.delete(otp_record) # Optional: delete used OTP

    session.commit()
    session.close()

    return jsonify({
        "message": "User registered successfully",
        "register": True
    }), 201


@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    if not email or not otp or not new_password:
        return jsonify({"message": "Missing email, OTP, or new password"}), 400

    session = Session()

    # Verify OTP
    otp_record = session.query(OTP).filter_by(email=email, otp=otp, is_verified=False).first()
    if not otp_record:
        session.close()
        return jsonify({"message": "Invalid OTP"}), 400
    
    if otp_record.expires_at < datetime.utcnow():
        session.close()
        return jsonify({"message": "OTP expired"}), 400

    user = session.query(User).filter_by(username=email).first()
    if not user:
        session.close()
        return jsonify({"message": "User not found"}), 404

    user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
    
    # Mark OTP as verified
    otp_record.is_verified = True
    session.delete(otp_record) # Optional: delete used OTP

    session.commit()
    session.close()

    return jsonify({"message": "Password reset successfully"}), 200



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
    is_mentor = session.query(Newmentor).filter_by(email=username).first() is not None

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

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
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
            "work_experience": mentor.work_experience,
            "current_role": mentor.current_role,
            "interested_field": mentor.interested_field,
            "expertise": mentor.expertise,
            "degree": mentor.degree,
            "background": mentor.background,
            "fee": mentor.fee,
            "milestones": mentor.milestones,
            "profile_picture": mentor.profile_picture,
            "resume": mentor.resume,
            "availability": mentor.availability,
            "intent_price": mentor.intent_price,
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
    degree_query = request.args.get('degree', '').strip().lower()
    education_filter = request.args.get('education', '').strip().lower()
    stream_filter = request.args.get('stream', '').strip().lower()
    experience_filter = request.args.get('experience', '').strip().lower()
    industry_filter = request.args.get('industry', '').strip().lower()

    if not degree_query and education_filter:
        degree_query = education_filter

    if not degree_query:
        return jsonify({"error": "Please provide a degree name"}), 400

    session = Session()

    def split_csv(value):
        if not value:
            return []
        return [item.strip() for item in value.split(',') if item.strip()]

    def education_matches(entry, term):
        if not term:
            return False
        term = term.lower()
        bachelors = (entry.bachelors_degree or '').strip().lower()
        masters = (entry.masters_degree or '').strip().lower()
        return term in bachelors or term in masters

    def entry_text(entry):
        parts = [
            entry.role,
            entry.stream,
            entry.bachelors_degree,
            entry.masters_degree,
            entry.certifications,
            entry.competitions,
            entry.courses
        ]
        return " ".join([part for part in parts if part]).lower()

    def build_match_payload(entry, match_type, base_score, confidence):
        if stream_filter and (entry.stream or '').strip().lower() != stream_filter:
            return None

        blob = entry_text(entry)
        education_match = None
        if education_filter:
            education_match = education_matches(entry, education_filter)
            if not education_match:
                return None

        industry_match = None
        if industry_filter:
            industry_match = industry_filter in blob

        experience_match = None
        if experience_filter:
            experience_match = experience_filter in blob

        degree_match = education_matches(entry, degree_query)

        score = base_score
        reasons = []
        if stream_filter:
            score += 5
            reasons.append("stream_match")
        if education_match:
            score += 5
            reasons.append("education_match")
        if degree_match:
            score += 5
            reasons.append("degree_match")
        if industry_match:
            score += 3
            reasons.append("industry_match")
        if experience_match:
            score += 3
            reasons.append("experience_match")
        if degree_query and degree_query in blob and "degree_match" not in reasons:
            score += 2
            reasons.append("degree_term_match")

        return {
            "matched_role": entry.role,
            "stream": entry.stream,
            "bachelors_degree": entry.bachelors_degree,
            "masters_degree": entry.masters_degree,
            "certifications": split_csv(entry.certifications),
            "competitions": split_csv(entry.competitions),
            "courses": split_csv(entry.courses),
            "match_type": match_type,
            "confidence": confidence,
            "recommendation_score": score,
            "match_reasons": reasons,
            "industry_match": industry_match,
            "experience_match": experience_match,
            "education_match": education_match,
            "degree_match": degree_match
        }

    # Fetch all education entries
    education_entries = session.query(education).all()

    # Create a map of role -> entry
    role_map = {
        entry.role.strip().lower(): entry
        for entry in education_entries
        if entry.role
    }

    matched_roles_map = {}

    def upsert_match(entry, match_type, base_score, confidence):
        payload = build_match_payload(entry, match_type, base_score, confidence)
        if not payload:
            return
        role_key = (entry.role or '').strip().lower()
        existing = matched_roles_map.get(role_key)
        if not existing or payload["recommendation_score"] > existing["recommendation_score"]:
            matched_roles_map[role_key] = payload

    # If exact match exists, include it first
    if degree_query in role_map:
        exact_edu = role_map[degree_query]
        upsert_match(exact_edu, "exact", 100, 100)
        # Add all fuzzy matches excluding the exact match
        candidates = [role for role in role_map.keys() if role != degree_query]
        fuzzy_matches = process.extract(degree_query, candidates, limit=None)
    else:
        # No exact match; get all fuzzy matches
        fuzzy_matches = process.extract(degree_query, role_map.keys(), limit=None)

    # Append fuzzy matches
    for best_match, score in (fuzzy_matches or []):
        edu = role_map[best_match]
        upsert_match(edu, "fuzzy", score, score)

    # Also search in bachelors_degree and masters_degree fields
    for entry in education_entries:
        # Check if degree_query matches bachelor's or master's degree
        if education_matches(entry, degree_query):
            upsert_match(entry, "degree_match", 85, 85)

    matched_roles = list(matched_roles_map.values())
    matched_roles.sort(
        key=lambda item: (item.get("recommendation_score", 0), item.get("confidence", 0)),
        reverse=True
    )

    degree_recommendations = None
    if degree_data:
        degree_record = degree_data.get(degree_query)
        degree_match_type = None
        degree_confidence = None
        matched_degree_name = None
        if degree_record:
            degree_match_type = "exact"
            degree_confidence = 100
        else:
            best_match = process.extractOne(degree_query, degree_data.keys())
            if best_match:
                matched_degree_name, degree_confidence = best_match
                if degree_confidence >= 70:
                    degree_record = degree_data[matched_degree_name]
                    degree_match_type = "fuzzy"

        if degree_record and degree_match_type:
            degree_recommendations = {
                "name": degree_record.name,
                "courses": split_csv(degree_record.courses),
                "competitions": split_csv(degree_record.competitions),
                "certifications": split_csv(degree_record.certifications),
                "match_type": degree_match_type,
                "confidence": degree_confidence
            }
            if matched_degree_name and degree_match_type == "fuzzy":
                degree_recommendations["matched_degree"] = matched_degree_name

    if matched_roles:
        response = {"matched_roles": matched_roles}
        if degree_recommendations:
            response["degree_recommendations"] = degree_recommendations
        return jsonify(response), 200

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



# @app.route('/update_mentor/<int:mentor_id>', methods=['PUT'])
# @jwt_required()
# def update_mentor(mentor_id):
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

        # Send meeting notifications to both user and mentor
        try:
            # Notification for user
            user_notification_id = send_meeting_notification(
                user_id=user_id,
                mentor_id=mentor_id,
                notification_type='meeting_scheduled',
                title='Meeting Scheduled',
                message=f'Your meeting with {mentor_name} has been scheduled for {start_datetime.strftime("%Y-%m-%d at %H:%M")}',
                schedule_id=schedule.id,
                meeting_datetime=start_datetime,
                meeting_link=link,
                notification_data={'mentor_name': mentor_name, 'duration': duration}
            )
            
            # Notification for mentor
            mentor_notification_id = send_meeting_notification(
                user_id=mentor_id,  # For mentor, we use mentor_id as user_id in the notification
                mentor_id=mentor_id,
                notification_type='meeting_scheduled',
                title='Meeting Scheduled',
                message=f'You have a meeting scheduled with {name} for {start_datetime.strftime("%Y-%m-%d at %H:%M")}',
                schedule_id=schedule.id,
                meeting_datetime=start_datetime,
                meeting_link=link,
                notification_data={'user_name': name, 'duration': duration}
            )
            
            print(f"Meeting notifications sent - User: {user_notification_id}, Mentor: {mentor_notification_id}")
        except Exception as e:
            print(f"Error sending meeting notifications: {str(e)}")
            # Don't fail the schedule creation if notification fails

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
            session.query(TrialSchedule)
            .filter(
                or_(TrialSchedule.user_id == user_id, TrialSchedule.mentor_id == mentor_id),
                TrialSchedule.start_datetime < end_datetime,
                TrialSchedule.end_datetime > start_datetime,
            )
            .first()
        )

        if overlapping:
            return jsonify({
                "error": "Overlapping meeting exists for the user or mentor in the selected time range"
            }), 409

        # Create a new schedule entry
        schedule = TrialSchedule(
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

        # Send meeting notifications to both user and mentor for trial meeting
        try:
            # Notification for user
            user_notification_id = send_meeting_notification(
                user_id=user_id,
                mentor_id=mentor_id,
                notification_type='meeting_scheduled',
                title='Trial Meeting Scheduled',
                message=f'Your trial meeting with {mentor_name} has been scheduled for {start_datetime.strftime("%Y-%m-%d at %H:%M")}',
                schedule_id=schedule.id,
                meeting_datetime=start_datetime,
                meeting_link=link,
                notification_data={'mentor_name': mentor_name, 'duration': duration, 'meeting_type': 'trial'}
            )
            
            # Notification for mentor
            mentor_notification_id = send_meeting_notification(
                user_id=mentor_id,  # For mentor, we use mentor_id as user_id in the notification
                mentor_id=mentor_id,
                notification_type='meeting_scheduled',
                title='Trial Meeting Scheduled',
                message=f'You have a trial meeting scheduled with {name} for {start_datetime.strftime("%Y-%m-%d at %H:%M")}',
                schedule_id=schedule.id,
                meeting_datetime=start_datetime,
                meeting_link=link,
                notification_data={'user_name': name, 'duration': duration, 'meeting_type': 'trial'}
            )
            
            print(f"Trial meeting notifications sent - User: {user_notification_id}, Mentor: {mentor_notification_id}")
        except Exception as e:
            print(f"Error sending trial meeting notifications: {str(e)}")
            # Don't fail the schedule creation if notification fails

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

        filters = []
        if user_id:
            filters.append((Schedule.user_id, TrialSchedule.user_id, user_id))
        if mentor_id:
            filters.append((Schedule.mentor_id, TrialSchedule.mentor_id, mentor_id))

        def apply_filters(query, model):
            for schedule_field, trial_field, value in filters:
                field = schedule_field if model is Schedule else trial_field
                query = query.filter(field == value)
            return query

        schedule_query = apply_filters(session.query(Schedule), Schedule)
        trial_query = apply_filters(session.query(TrialSchedule), TrialSchedule)

        def _compact_payload(payload):
            if not payload:
                return None
            has_value = any(value is not None for value in payload.values())
            return payload if has_value else None

        def build_intent_data(schedule_user_id, schedule_mentor_id):
            user_account = session.query(User).filter_by(id=schedule_user_id).first()
            user_email = user_account.username if user_account else None
            user_details = None
            if user_account:
                user_details = session.query(UserDetails).filter_by(
                    username=user_account.username
                ).first()

            user_profile = None
            if user_email:
                user_profile = session.query(BasicInfo).filter(
                    or_(BasicInfo.emailid == user_email, BasicInfo.useruniqid == user_email)
                ).first()
            if not user_profile:
                user_profile = session.query(BasicInfo).filter_by(
                    useruniqid=str(schedule_user_id)
                ).first()

            intent = session.query(Intent).filter_by(
                user_id=schedule_user_id,
                mentor_id=schedule_mentor_id
            ).first()

            intent_email = None
            if intent and intent.email:
                intent_email = intent.email
            elif user_profile and user_profile.emailid:
                intent_email = user_profile.emailid
            else:
                intent_email = user_email

            user_profile_data = None
            if user_profile:
                user_profile_data = {
                    'id': user_profile.id,
                    'emailid': user_profile.emailid,
                    'useruniqid': user_profile.useruniqid,
                    'firstname': user_profile.firstname,
                    'lastname': user_profile.lastname,
                    'high_education': user_profile.high_education,
                    'bachelor': user_profile.bachelor,
                    'work_experience': user_profile.work_experience,
                    'industry': user_profile.industry,
                    'role': user_profile.role,
                    'interested_stream': user_profile.interested_stream,
                    'role_based': user_profile.role_based,
                    'intent': _deserialize_intent_payload(user_profile.intent),
                    'data_filed': user_profile.data_filed
                }

            first_name = None
            last_name = None
            if user_details and (user_details.first_name or user_details.last_name):
                first_name = user_details.first_name
                last_name = user_details.last_name
            elif user_profile:
                first_name = user_profile.firstname
                last_name = user_profile.lastname

            user_info_data = _compact_payload({
                'user_id': schedule_user_id,
                'username': user_account.username if user_account else None,
                'email': intent_email,
                'first_name': first_name,
                'last_name': last_name,
                'country': user_details.country if user_details else None
            })

            user_education_data = _compact_payload({
                'high_education': user_profile.high_education if user_profile else None,
                'bachelor': user_profile.bachelor if user_profile else None,
                'school_name': user_details.school_name if user_details else None,
                'bachelors_degree': user_details.bachelors_degree if user_details else None,
                'masters_degree': user_details.masters_degree if user_details else None,
                'certification': user_details.certification if user_details else None,
                'activity': user_details.activity if user_details else None,
                'stream_name': user_details.stream_name if user_details else None
            })

            user_work_data = _compact_payload({
                'work_experience': user_profile.work_experience if user_profile else None,
                'industry': user_profile.industry if user_profile else None,
                'role': user_profile.role if user_profile else None,
                'role_based': user_profile.role_based if user_profile else None
            })

            return {
                'id': intent.id if intent else None,
                'useruniqid': intent.useruniqid if intent else (user_profile.useruniqid if user_profile else None),
                'email': intent_email,
                'area_exploring': intent.area_exploring if intent else None,
                'goal_challenge': intent.goal_challenge if intent else None,
                'support_types': intent.support_types if intent else None,
                'user_id': intent.user_id if intent else schedule_user_id,
                'mentor_id': intent.mentor_id if intent else schedule_mentor_id,
                'created_at': intent.created_at.isoformat() if intent and intent.created_at else None,
                'has_intent': bool(intent),
                'user_info': user_info_data,
                'user_profile': user_profile_data,
                'user_education': user_education_data,
                'user_work': user_work_data
            }

        schedule_results = []
        for s in schedule_query.all():
            intent_data = build_intent_data(s.user_id, s.mentor_id)
            
            schedule_results.append({
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
                "duration": s.duration,
                "timezone": s.timezone,
                "meeting_type": "regular",
                "intent": intent_data
            })

        trial_results = []
        for t in trial_query.all():
            intent_data = build_intent_data(t.user_id, t.mentor_id)
            
            trial_results.append({
                "id": t.id,
                "name": t.name,
                "email": t.email,
                "start_datetime": t.start_datetime.isoformat(),
                "end_datetime": t.end_datetime.isoformat(),
                "link": t.link,
                "created_at": t.created_at.isoformat(),
                "mentor_id": t.mentor_id,
                "mentor_name": t.mentor_name,
                "mentor_email": t.mentor_email,
                "user_id": t.user_id,
                "duration": t.duration,
                "timezone": t.timezone,
                "meeting_type": "trial",
                "intent": intent_data
            })

        combined_results = schedule_results + trial_results
        combined_results.sort(key=lambda item: item["start_datetime"])

        return jsonify(combined_results), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    finally:
        session.close()

# GET intent by user_id and mentor_id
@app.route('/api/intentwithids', methods=['GET'])
def get_intent_by_ids():
    session = Session()
    try:
        user_id = request.args.get('user_id')
        mentor_id = request.args.get('mentor_id')

        if not user_id or not mentor_id:
            return jsonify({'error': 'user_id and mentor_id are required'}), 400

        # Query intent by user_id and mentor_id
        intent = session.query(Intent).filter_by(
            user_id=int(user_id), 
            mentor_id=int(mentor_id)
        ).first()

        if not intent:
            return jsonify({'error': 'Intent not found'}), 404

        intent_data = {
            'id': intent.id,
            'useruniqid': intent.useruniqid,
            'email': intent.email,
            'area_exploring': intent.area_exploring,
            'goal_challenge': intent.goal_challenge,
            'support_types': intent.support_types,
            'user_id': intent.user_id,
            'mentor_id': intent.mentor_id,
            'created_at': intent.created_at.isoformat()
        }

        return jsonify(intent_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


# check user api meeting after meeting
@app.route('/api/validMeeting/<int:schedule_id>', methods=['GET'])
def get_schedule(schedule_id):
    session = Session()
    
    # Search for the schedule where the link contains "/v2/meetingcall/<schedule_id>"
    # First, try to find in regular Schedule table
    schedule = session.query(Schedule).filter(Schedule.link.contains(f"/v2/meetingcall/{schedule_id}")).first()
    
    # If not found in Schedule, try TrialSchedule table
    if not schedule:
        schedule = session.query(TrialSchedule).filter(TrialSchedule.link.contains(f"/v2/meetingcall/{schedule_id}")).first()
    
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
    
    # First, try to find in regular Schedule table
    schedule = session.query(Schedule).filter(Schedule.link.contains(f"/v2/meetingcall/{schedule_id}")).first()
    
    # If not found in Schedule, try TrialSchedule table
    if not schedule:
        schedule = session.query(TrialSchedule).filter(TrialSchedule.link.contains(f"/v2/meetingcall/{schedule_id}")).first()
    
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

    # First, try to find in regular Schedule table
    schedule = session.query(Schedule).filter_by(link=link).first()
    
    # If not found in Schedule, try TrialSchedule table
    if not schedule:
        schedule = session.query(TrialSchedule).filter_by(link=link).first()
    
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
    check_meeting_id = request.args.get('check_meeting_id')  # Optional: filter by check_meeting_id
    session = Session()

    # Ensure at least one identifier is provided
    if not user_id and not mentor_id and not check_meeting_id:
        return jsonify({'error': 'Missing user_id, mentor_id, or check_meeting_id parameter'}), 400

    # Build dynamic filters
    or_filters = []
    if user_id:
        or_filters.append(Feedback.user_id == user_id)
    if mentor_id:
        or_filters.append(Feedback.mentor_id == mentor_id)

    query = session.query(Feedback)
    if or_filters:
        query = query.filter(or_(*or_filters)) if len(or_filters) > 1 else query.filter(or_filters[0])
    if check_meeting_id:
        query = query.filter(Feedback.check_meeting_id == check_meeting_id)

    feedback_list = query.all()

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


@app.route('/wallet/init', methods=['POST'])
@jwt_required()
def init_wallet():
    identity = get_jwt_identity()
    data = request.get_json() or {}
    owner_type = data.get('owner_type')
    owner_id = data.get('owner_id')

    if owner_id is None:
        return jsonify({'error': 'owner_id is required'}), 400

    try:
        owner_id_int = int(owner_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'owner_id must be an integer'}), 400

    session = Session()
    try:
        existing_wallet = session.query(Wallet).filter_by(owner_type=owner_type, owner_id=owner_id_int).first()
        if existing_wallet:
            response = serialize_wallet(existing_wallet)
            session.close()
            return jsonify({'wallet': response, 'message': 'Wallet already exists'}), 200

        _owner, _, _, error_response = ensure_wallet_access(session, identity, owner_type, owner_id_int)
        if error_response:
            session.close()
            return error_response

        wallet = Wallet(owner_type=owner_type, owner_id=owner_id_int)
        session.add(wallet)
        session.commit()
        session.refresh(wallet)

        response = serialize_wallet(wallet)
        session.close()
        return jsonify({'wallet': response, 'message': 'Wallet created successfully'}), 201
    except Exception as e:
        session.rollback()
        session.close()
        return jsonify({'error': str(e)}), 500


@app.route('/wallet/balance', methods=['GET'])
@jwt_required()
def wallet_balance():
    identity = get_jwt_identity()
    owner_type = request.args.get('owner_type')
    owner_id = request.args.get('owner_id')

    if not owner_type or owner_id is None:
        return jsonify({'error': 'owner_type and owner_id are required'}), 400

    try:
        owner_id_int = int(owner_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'owner_id must be an integer'}), 400

    session = Session()
    try:
        _owner, _, _, error_response = ensure_wallet_access(session, identity, owner_type, owner_id_int)
        if error_response:
            session.close()
            return error_response

        wallet = session.query(Wallet).filter_by(owner_type=owner_type, owner_id=owner_id_int).first()
        if not wallet:
            session.close()
            return jsonify({'error': 'Wallet not found. Initialize it first.'}), 404

        response = serialize_wallet(wallet)
        session.close()
        return jsonify({'wallet': response}), 200
    except Exception as e:
        session.rollback()
        session.close()
        return jsonify({'error': str(e)}), 500


@app.route('/wallet/add-money', methods=['POST'])
@jwt_required()
def wallet_add_money():
    identity = get_jwt_identity()
    data = request.get_json() or {}
    owner_type = data.get('owner_type')
    owner_id = data.get('owner_id')
    amount = data.get('amount')
    notes = data.get('notes') or {}

    if owner_id is None or amount is None:
        return jsonify({'error': 'owner_id and amount are required'}), 400

    try:
        owner_id_int = int(owner_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'owner_id must be an integer'}), 400

    if not isinstance(notes, dict):
        notes = {'info': str(notes)}

    session = Session()
    try:
        _owner, _, _, error_response = ensure_wallet_access(session, identity, owner_type, owner_id_int)
        if error_response:
            session.close()
            return error_response

        try:
            amount_paise = rupees_to_paise(amount)
        except ValueError as ve:
            session.close()
            return jsonify({'error': str(ve)}), 400

        wallet = get_or_create_wallet(session, owner_type, owner_id_int)
        session.flush()

        receipt = f"wallet_{uuid4().hex}"
        razorpay_order = razorpay_client.order.create({
            'amount': amount_paise,
            'currency': wallet.currency,
            'payment_capture': 1,
            'receipt': receipt,
            'notes': {
                'owner_type': owner_type,
                'owner_id': str(owner_id_int),
                'wallet_id': str(wallet.id),
                **{str(k): str(v) for k, v in notes.items()}
            }
        })

        transaction = WalletTransaction(
            wallet_id=wallet.id,
            transaction_type='credit',
            amount_paise=amount_paise,
            currency=wallet.currency,
            status='pending',
            razorpay_order_id=razorpay_order['id'],
            notes=notes
        )
        session.add(transaction)
        session.commit()
        session.refresh(transaction)

        response = {
            'order': razorpay_order,
            'transaction': serialize_wallet_transaction(transaction),
            'wallet': serialize_wallet(wallet)
        }
        session.close()
        return jsonify(response), 201
    except Exception as e:
        session.rollback()
        session.close()
        return jsonify({'error': str(e)}), 500


@app.route('/wallet/confirm', methods=['POST'])
@jwt_required()
def wallet_confirm_payment():
    identity = get_jwt_identity()
    data = request.get_json() or {}
    owner_type = data.get('owner_type')
    owner_id = data.get('owner_id')
    order_id = data.get('razorpay_order_id')
    payment_id = data.get('razorpay_payment_id')
    signature = data.get('razorpay_signature')

    if owner_id is None or not order_id or not payment_id or not signature:
        return jsonify({'error': 'owner_id, razorpay_order_id, razorpay_payment_id, and razorpay_signature are required'}), 400

    try:
        owner_id_int = int(owner_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'owner_id must be an integer'}), 400

    session = Session()
    try:
        _owner, _, _, error_response = ensure_wallet_access(session, identity, owner_type, owner_id_int)
        if error_response:
            session.close()
            return error_response

        wallet = session.query(Wallet).filter_by(owner_type=owner_type, owner_id=owner_id_int).first()
        if not wallet:
            session.close()
            return jsonify({'error': 'Wallet not found. Initialize it first.'}), 404

        transaction = session.query(WalletTransaction).filter_by(wallet_id=wallet.id, razorpay_order_id=order_id).first()
        if not transaction:
            session.close()
            return jsonify({'error': 'No pending transaction found for the provided order ID'}), 404

        if transaction.status == 'completed':
            response = {
                'message': 'Transaction already completed',
                'wallet': serialize_wallet(wallet),
                'transaction': serialize_wallet_transaction(transaction)
            }
            session.close()
            return jsonify(response), 200

        try:
            razorpay_client.utility.verify_payment_signature({
                'razorpay_order_id': order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature
            })
        except razorpay.errors.SignatureVerificationError:
            session.close()
            return jsonify({'error': 'Payment verification failed'}), 400

        wallet.balance_paise += transaction.amount_paise
        transaction.status = 'completed'
        transaction.razorpay_payment_id = payment_id
        transaction.razorpay_signature = signature
        transaction.closing_balance_paise = wallet.balance_paise

        session.commit()
        session.refresh(wallet)
        session.refresh(transaction)

        response = {
            'message': 'Wallet credited successfully',
            'wallet': serialize_wallet(wallet),
            'transaction': serialize_wallet_transaction(transaction)
        }
        session.close()
        return jsonify(response), 200
    except Exception as e:
        session.rollback()
        session.close()
        return jsonify({'error': str(e)}), 500


@app.route('/wallet/debit', methods=['POST'])
@jwt_required()
def wallet_debit():
    identity = get_jwt_identity()
    data = request.get_json() or {}
    owner_type = data.get('owner_type')
    owner_id = data.get('owner_id')
    amount = data.get('amount')
    reference = data.get('reference')
    notes = data.get('notes') or {}

    if owner_id is None or amount is None:
        return jsonify({'error': 'owner_id and amount are required'}), 400

    try:
        owner_id_int = int(owner_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'owner_id must be an integer'}), 400

    if not isinstance(notes, dict):
        notes = {'info': str(notes)}

    session = Session()
    try:
        _owner, _, _, error_response = ensure_wallet_access(session, identity, owner_type, owner_id_int)
        if error_response:
            session.close()
            return error_response

        wallet = session.query(Wallet).filter_by(owner_type=owner_type, owner_id=owner_id_int).first()
        if not wallet:
            session.close()
            return jsonify({'error': 'Wallet not found. Initialize it first.'}), 404

        try:
            amount_paise = rupees_to_paise(amount)
        except ValueError as ve:
            session.close()
            return jsonify({'error': str(ve)}), 400

        if wallet.balance_paise < amount_paise:
            session.close()
            return jsonify({'error': 'Insufficient wallet balance'}), 400

        wallet.balance_paise -= amount_paise
        transaction = WalletTransaction(
            wallet_id=wallet.id,
            transaction_type='debit',
            amount_paise=amount_paise,
            currency=wallet.currency,
            status='completed',
            notes={**notes, 'reference': reference} if reference else notes,
            closing_balance_paise=wallet.balance_paise
        )
        session.add(transaction)
        session.commit()
        session.refresh(wallet)
        session.refresh(transaction)

        response = {
            'message': 'Wallet debited successfully',
            'wallet': serialize_wallet(wallet),
            'transaction': serialize_wallet_transaction(transaction)
        }
        session.close()
        return jsonify(response), 200
    except Exception as e:
        session.rollback()
        session.close()
        return jsonify({'error': str(e)}), 500


@app.route('/wallet/pay-mentor', methods=['POST'])
@jwt_required()
def wallet_pay_mentor():
    """
    Pay a mentor using wallet balance. This endpoint:
    1. Debits amount from user's wallet
    2. Credits amount to mentor's wallet
    3. Creates transactions for both wallets
    """
    identity = get_jwt_identity()
    data = request.get_json() or {}
    user_id = data.get('user_id')
    mentor_id = data.get('mentor_id')
    amount = data.get('amount')
    notes = data.get('notes') or {}
    reference = data.get('reference')  # e.g., 'mentor_hiring', 'session_payment', etc.

    if not all([user_id, mentor_id, amount]):
        return jsonify({'error': 'user_id, mentor_id, and amount are required'}), 400

    try:
        user_id_int = int(user_id)
        mentor_id_int = int(mentor_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'user_id and mentor_id must be integers'}), 400

    if not isinstance(notes, dict):
        notes = {'info': str(notes)}

    session = Session()
    try:
        # Verify user has access to their wallet
        _owner, _, _, error_response = ensure_wallet_access(session, identity, 'user', user_id_int)
        if error_response:
            session.close()
            return error_response

        # Get user and mentor wallets
        user_wallet = session.query(Wallet).filter_by(owner_type='user', owner_id=user_id_int).first()
        if not user_wallet:
            session.close()
            return jsonify({'error': 'User wallet not found. Please initialize wallet first.'}), 404

        mentor_wallet = get_or_create_wallet(session, 'mentor', mentor_id_int)
        session.flush()

        # Verify mentor exists
        mentor = session.query(Newmentor).filter_by(mentor_id=mentor_id_int).first()
        if not mentor:
            session.close()
            return jsonify({'error': 'Mentor not found'}), 404

        # Convert amount to paise
        try:
            amount_paise = rupees_to_paise(amount)
        except ValueError as ve:
            session.close()
            return jsonify({'error': str(ve)}), 400

        # Check if user has sufficient balance
        if user_wallet.balance_paise < amount_paise:
            session.close()
            return jsonify({
                'error': 'Insufficient wallet balance',
                'current_balance': paise_to_rupees(user_wallet.balance_paise),
                'required_amount': paise_to_rupees(amount_paise)
            }), 400

        # Debit from user wallet
        user_wallet.balance_paise -= amount_paise
        user_debit_transaction = WalletTransaction(
            wallet_id=user_wallet.id,
            transaction_type='debit',
            amount_paise=amount_paise,
            currency=user_wallet.currency,
            status='completed',
            notes={**notes, 'reference': reference or 'mentor_payment', 'mentor_id': mentor_id_int},
            closing_balance_paise=user_wallet.balance_paise
        )
        session.add(user_debit_transaction)

        # Credit to mentor wallet
        mentor_wallet.balance_paise += amount_paise
        mentor_credit_transaction = WalletTransaction(
            wallet_id=mentor_wallet.id,
            transaction_type='credit',
            amount_paise=amount_paise,
            currency=mentor_wallet.currency,
            status='completed',
            notes={**notes, 'reference': reference or 'mentor_payment', 'user_id': user_id_int},
            closing_balance_paise=mentor_wallet.balance_paise
        )
        session.add(mentor_credit_transaction)

        session.commit()
        session.refresh(user_wallet)
        session.refresh(mentor_wallet)
        session.refresh(user_debit_transaction)
        session.refresh(mentor_credit_transaction)

        response = {
            'message': 'Payment to mentor successful',
            'user_wallet': serialize_wallet(user_wallet),
            'mentor_wallet': serialize_wallet(mentor_wallet),
            'debit_transaction': serialize_wallet_transaction(user_debit_transaction),
            'credit_transaction': serialize_wallet_transaction(mentor_credit_transaction),
            'amount_paid': paise_to_rupees(amount_paise)
        }
        session.close()
        return jsonify(response), 200
    except Exception as e:
        session.rollback()
        session.close()
        return jsonify({'error': str(e)}), 500


@app.route('/wallet/transfer', methods=['POST'])
@jwt_required()
def wallet_transfer():
    """
    Transfer money between wallets (user to user, mentor to mentor, etc.)
    This is a general transfer endpoint for any wallet-to-wallet transfer.
    """
    identity = get_jwt_identity()
    data = request.get_json() or {}
    from_owner_type = data.get('from_owner_type')
    from_owner_id = data.get('from_owner_id')
    to_owner_type = data.get('to_owner_type')
    to_owner_id = data.get('to_owner_id')
    amount = data.get('amount')
    notes = data.get('notes') or {}
    reference = data.get('reference')

    if not all([from_owner_type, from_owner_id, to_owner_type, to_owner_id, amount]):
        return jsonify({'error': 'from_owner_type, from_owner_id, to_owner_type, to_owner_id, and amount are required'}), 400

    if from_owner_type not in VALID_WALLET_OWNER_TYPES or to_owner_type not in VALID_WALLET_OWNER_TYPES:
        return jsonify({'error': 'Invalid owner_type. Must be "user" or "mentor"'}), 400

    try:
        from_owner_id_int = int(from_owner_id)
        to_owner_id_int = int(to_owner_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'owner_ids must be integers'}), 400

    if from_owner_type == to_owner_type and from_owner_id_int == to_owner_id_int:
        return jsonify({'error': 'Cannot transfer to the same wallet'}), 400

    if not isinstance(notes, dict):
        notes = {'info': str(notes)}

    session = Session()
    try:
        # Verify sender has access to their wallet
        _owner, _, _, error_response = ensure_wallet_access(session, identity, from_owner_type, from_owner_id_int)
        if error_response:
            session.close()
            return error_response

        # Get sender wallet
        from_wallet = session.query(Wallet).filter_by(owner_type=from_owner_type, owner_id=from_owner_id_int).first()
        if not from_wallet:
            session.close()
            return jsonify({'error': 'Sender wallet not found. Please initialize wallet first.'}), 404

        # Get or create receiver wallet
        to_wallet = get_or_create_wallet(session, to_owner_type, to_owner_id_int)
        session.flush()

        # Convert amount to paise
        try:
            amount_paise = rupees_to_paise(amount)
        except ValueError as ve:
            session.close()
            return jsonify({'error': str(ve)}), 400

        # Check if sender has sufficient balance
        if from_wallet.balance_paise < amount_paise:
            session.close()
            return jsonify({
                'error': 'Insufficient wallet balance',
                'current_balance': paise_to_rupees(from_wallet.balance_paise),
                'required_amount': paise_to_rupees(amount_paise)
            }), 400

        # Debit from sender wallet
        from_wallet.balance_paise -= amount_paise
        from_debit_transaction = WalletTransaction(
            wallet_id=from_wallet.id,
            transaction_type='debit',
            amount_paise=amount_paise,
            currency=from_wallet.currency,
            status='completed',
            notes={**notes, 'reference': reference or 'wallet_transfer', 'to_owner_type': to_owner_type, 'to_owner_id': to_owner_id_int},
            closing_balance_paise=from_wallet.balance_paise
        )
        session.add(from_debit_transaction)

        # Credit to receiver wallet
        to_wallet.balance_paise += amount_paise
        to_credit_transaction = WalletTransaction(
            wallet_id=to_wallet.id,
            transaction_type='credit',
            amount_paise=amount_paise,
            currency=to_wallet.currency,
            status='completed',
            notes={**notes, 'reference': reference or 'wallet_transfer', 'from_owner_type': from_owner_type, 'from_owner_id': from_owner_id_int},
            closing_balance_paise=to_wallet.balance_paise
        )
        session.add(to_credit_transaction)

        session.commit()
        session.refresh(from_wallet)
        session.refresh(to_wallet)
        session.refresh(from_debit_transaction)
        session.refresh(to_credit_transaction)

        response = {
            'message': 'Transfer successful',
            'from_wallet': serialize_wallet(from_wallet),
            'to_wallet': serialize_wallet(to_wallet),
            'debit_transaction': serialize_wallet_transaction(from_debit_transaction),
            'credit_transaction': serialize_wallet_transaction(to_credit_transaction),
            'amount_transferred': paise_to_rupees(amount_paise)
        }
        session.close()
        return jsonify(response), 200
    except Exception as e:
        session.rollback()
        session.close()
        return jsonify({'error': str(e)}), 500


@app.route('/wallet/transactions', methods=['GET'])
@jwt_required()
def wallet_transactions():
    identity = get_jwt_identity()
    owner_type = request.args.get('owner_type')
    owner_id = request.args.get('owner_id')
    limit = request.args.get('limit', default=50, type=int)

    if not owner_type or owner_id is None:
        return jsonify({'error': 'owner_type and owner_id are required'}), 400

    try:
        owner_id_int = int(owner_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'owner_id must be an integer'}), 400

    session = Session()
    try:
        _owner, _, _, error_response = ensure_wallet_access(session, identity, owner_type, owner_id_int)
        if error_response:
            session.close()
            return error_response

        wallet = session.query(Wallet).filter_by(owner_type=owner_type, owner_id=owner_id_int).first()
        if not wallet:
            session.close()
            return jsonify({'error': 'Wallet not found. Initialize it first.'}), 404

        transactions = (
            session.query(WalletTransaction)
            .filter_by(wallet_id=wallet.id)
            .order_by(WalletTransaction.created_at.desc())
            .limit(limit)
            .all()
        )

        response = {
            'wallet': serialize_wallet(wallet),
            'transactions': [serialize_wallet_transaction(txn) for txn in transactions],
            'count': len(transactions)
        }
        session.close()
        return jsonify(response), 200
    except Exception as e:
        session.rollback()
        session.close()
        return jsonify({'error': str(e)}), 500


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
    notification_for_user = Notification(
        user_id=user_id, 
        mentor_id=mentor_id,
        message=notification_message_user,
        message_type='notification'
    )
    notification_for_mentor = Notification(
        user_id=mentor.user_id, 
        mentor_id=mentor_id,
        message=notification_message_mentor,
        message_type='notification'
    )
    session.add(notification_for_user)
    session.add(notification_for_mentor)
    session.commit()

    # Debug logging
    print(f"[assign_mentor] Emitting notification to user_{user_id} and user_{mentor.user_id}")
    
    # Emit real-time notification to the user via Socket.IO
    socketio.emit('notification', {
        'message': notification_message_user, 
        'mentor_id': mentor_id, 
        'user_id': user_id
    }, room=f"user_{user_id}", namespace='/')
    
    # Emit real-time notification to the mentor via Socket.IO
    socketio.emit('notification', {
        'message': notification_message_mentor, 
        'mentor_id': mentor_id, 
        'user_id': user_id
    }, room=f"user_{mentor.user_id}", namespace='/')

    session.close()
    return jsonify({"message": "Mentor assigned successfully."}), 200


@app.route('/get_notifications/<int:user_id>', methods=['GET'])
def get_notifications(user_id):
    session = Session()
    
    try:
        # Get user by ID
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            session.close()
            return jsonify({
                "success": False,
                "message": "User not found"
            }), 404
        
        # Get all notifications for the current user using user.id
        notifications = session.query(Notification).filter_by(user_id=user.id).order_by(Notification.timestamp.desc()).all()
        
        notification_list = []
        for notification in notifications:
            notification_data = {
                "id": notification.id,
                "message": notification.message,
                "timestamp": notification.timestamp.isoformat(),
                "is_read": notification.is_read,
                "message_type": notification.message_type,
                "mentor_id": notification.mentor_id
            }
            notification_list.append(notification_data)
        
        session.close()
        return jsonify({
            "success": True,
            "notifications": notification_list,
            "total_count": len(notification_list)
        }), 200
        
    except Exception as e:
        session.close()
        return jsonify({
            "success": False,
            "message": f"Error fetching notifications: {str(e)}"
        }), 500


@app.route('/user_notification_read/<int:user_id>/<int:notification_id>', methods=['PUT'])
def user_notification_read(user_id, notification_id):
    session = Session()
    
    try:
        # Get user by ID
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            session.close()
            return jsonify({
                "success": False,
                "message": "User not found"
            }), 404
        
        notification = session.query(Notification).filter_by(
            id=notification_id, 
            user_id=user.id
        ).first()
        
        if not notification:
            session.close()
            return jsonify({
                "success": False,
                "message": "Notification not found"
            }), 404
        
        notification.is_read = True
        session.commit()
        session.close()
        
        return jsonify({
            "success": True,
            "message": "Notification marked as read"
        }), 200
        
    except Exception as e:
        session.close()
        return jsonify({
            "success": False,
            "message": f"Error updating notification: {str(e)}"
        }), 500


@app.route('/user_notifications_mark_all_read/<int:user_id>', methods=['PUT'])
def user_notifications_mark_all_read(user_id):
    session = Session()
    
    try:
        # Get user by ID
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            session.close()
            return jsonify({
                "success": False,
                "message": "User not found"
            }), 404
        
        notifications = session.query(Notification).filter_by(
            user_id=user.id,
            is_read=False
        ).all()
        
        for notification in notifications:
            notification.is_read = True
        
        session.commit()
        session.close()
        
        return jsonify({
            "success": True,
            "message": f"Marked {len(notifications)} notifications as read"
        }), 200
        
    except Exception as e:
        session.close()
        return jsonify({
            "success": False,
            "message": f"Error updating notifications: {str(e)}"
        }), 500


# Message API for chat functionality
@app.route('/send_message', methods=['POST'])
def send_message():
    session = Session()
    
    try:
        data = request.get_json()
        sender_id = data.get('sender_id')
        receiver_id = data.get('receiver_id')
        message_content = data.get('message')
        mentor_id = data.get('mentor_id')  # Optional mentor_id for mentor-related messages
        
        if not sender_id:
            session.close()
            return jsonify({
                "success": False,
                "message": "Sender ID is required"
            }), 400
        
        # Get sender user
        sender = session.query(User).filter_by(id=sender_id).first()
        
        if not sender:
            session.close()
            return jsonify({
                "success": False,
                "message": "Sender user not found"
            }), 404
        
        if not receiver_id or not message_content:
            session.close()
            return jsonify({
                "success": False,
                "message": "Receiver ID and message are required"
            }), 400
        
        # Verify receiver exists
        receiver = session.query(User).filter_by(id=receiver_id).first()
        if not receiver:
            session.close()
            return jsonify({
                "success": False,
                "message": "Receiver not found"
            }), 404
        
        # Validate mentor_id if provided
        validated_mentor_id = None
        if mentor_id:
            mentor = session.query(Mentor).filter_by(id=mentor_id).first()
            if mentor:
                validated_mentor_id = mentor_id
            # If mentor doesn't exist, set to None (optional field)
        
        # Create message in Notification table with message_type='chat'
        message = Notification(
            user_id=receiver_id,
            sender_id=sender.id,
            mentor_id=validated_mentor_id,
            message=message_content,
            message_type='chat',
            is_read=False
        )
        
        session.add(message)
        session.commit()
        
        # Emit real-time message via Socket.IO to both sender and receiver
        message_data = {
            'id': message.id,
            'sender_id': sender.id,
            'receiver_id': receiver_id,
            'sender_name': sender.username,
            'message': message_content,
            'timestamp': message.timestamp.isoformat(),
            'mentor_id': validated_mentor_id
        }
        
        # Debug logging
        print(f"[REST API] Emitting new_message to user_{receiver_id} and user_{sender.id}")
        print(f"[REST API] Message data: {message_data}")
        
        # Emit to receiver's room
        socketio.emit('new_message', message_data, room=f"user_{receiver_id}", namespace='/')
        
        # Emit to sender's room
        socketio.emit('new_message', message_data, room=f"user_{sender.id}", namespace='/')
        
        session.close()
        
        return jsonify({
            "success": True,
            "message": "Message sent successfully",
            "message_id": message.id
        }), 200
        
    except Exception as e:
        session.close()
        return jsonify({
            "success": False,
            "message": f"Error sending message: {str(e)}"
        }), 500


@app.route('/get_messages/<int:user_id>/<int:partner_id>', methods=['GET'])
def get_messages(user_id, partner_id):
    session = Session()
    
    try:
        # Get user by ID
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            session.close()
            return jsonify({
                "success": False,
                "message": "User not found"
            }), 404
        
        # Get messages between current user and partner (both directions)
        messages = session.query(Notification).filter(
            or_(
                and_(Notification.user_id == user.id, Notification.sender_id == partner_id),
                and_(Notification.user_id == partner_id, Notification.sender_id == user.id)
            ),
            Notification.message_type == 'chat'
        ).order_by(Notification.timestamp.asc()).all()
        
        message_list = []
        for message in messages:
            message_data = {
                "id": message.id,
                "sender_id": message.sender_id,
                "receiver_id": message.user_id,
                "message": message.message,
                "timestamp": message.timestamp.isoformat(),
                "is_read": message.is_read,
                "mentor_id": message.mentor_id
            }
            message_list.append(message_data)
        
        # Mark messages as read
        for message in messages:
            if message.user_id == user.id and not message.is_read:
                message.is_read = True
        
        session.commit()
        session.close()
        
        return jsonify({
            "success": True,
            "messages": message_list,
            "total_count": len(message_list)
        }), 200
        
    except Exception as e:
        session.close()
        return jsonify({
            "success": False,
            "message": f"Error fetching messages: {str(e)}"
        }), 500


@app.route('/get_chat_list/<int:user_id>', methods=['GET'])
def get_chat_list(user_id):
    session = Session()
    
    try:
        # Get user by ID
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            session.close()
            return jsonify({
                "success": False,
                "message": "User not found"
            }), 404
        
        # Get unique users that current user has chatted with
        chat_partners = session.query(Notification).filter(
            or_(
                Notification.sender_id == user.id,
                Notification.user_id == user.id
            ),
            Notification.message_type == 'chat'
        ).distinct().all()
        
        chat_list = []
        partner_ids = set()
        
        for chat in chat_partners:
            partner_id = chat.sender_id if chat.user_id == user.id else chat.user_id
            
            if partner_id not in partner_ids:
                partner = session.query(User).filter_by(id=partner_id).first()
                if partner:
                    # Get last message
                    last_message = session.query(Notification).filter(
                        or_(
                            and_(Notification.sender_id == user.id, Notification.user_id == partner_id),
                            and_(Notification.sender_id == partner_id, Notification.user_id == user.id)
                        ),
                        Notification.message_type == 'chat'
                    ).order_by(Notification.timestamp.desc()).first()
                    
                    # Count unread messages
                    unread_count = session.query(Notification).filter(
                        Notification.user_id == user.id,
                        Notification.sender_id == partner_id,
                        Notification.message_type == 'chat',
                        Notification.is_read == False
                    ).count()
                    
                    chat_data = {
                        "partner_id": partner_id,
                        "partner_name": partner.username,
                        "last_message": last_message.message if last_message else "",
                        "last_message_time": last_message.timestamp.isoformat() if last_message else "",
                        "unread_count": unread_count
                    }
                    chat_list.append(chat_data)
                    partner_ids.add(partner_id)
        
        session.close()
        
        return jsonify({
            "success": True,
            "chat_list": chat_list
        }), 200
        
    except Exception as e:
        session.close()
        return jsonify({
            "success": False,
            "message": f"Error fetching chat list: {str(e)}"
        }), 500


@socketio.on('get_notifications')
def handle_get_notifications(data):
    user_id = data.get('user_id')
    session = Session()
    
    if user_id:
        notifications = session.query(Notification).filter_by(user_id=user_id).order_by(Notification.timestamp.desc()).all()
        
        notification_messages = [{
            "id": notification.id,
            "message": notification.message,
            "timestamp": notification.timestamp.isoformat(), 
            "is_read": notification.is_read,
            "message_type": notification.message_type,
            "mentor_id": notification.mentor_id
        } for notification in notifications]

        emit('notifications', notification_messages, room=f"user_{user_id}")
    else:
        emit('notifications', {'message': 'No user ID provided'}, room=f"user_{user_id}")


@socketio.on('join_room')
def on_join_room(data):
    user_id = data.get('user_id')
    room = data.get('room', f"user_{user_id}")
    
    if user_id:
        join_room(room)
        print(f"User {user_id} joined room: {room}")  # Debug log
        emit('status', {'msg': f'Joined room {room}'})


@socketio.on('send_message_socket')
def handle_send_message_socket(data):
    user_id = data.get('user_id')
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    mentor_id = data.get('mentor_id')
    
    if not user_id or not receiver_id or not message:
        emit('error', {'message': 'Missing required fields'})
        return
    
    session = Session()
    try:
        # Validate mentor_id if provided
        validated_mentor_id = None
        if mentor_id:
            mentor = session.query(Mentor).filter_by(id=mentor_id).first()
            if mentor:
                validated_mentor_id = mentor_id
            # If mentor doesn't exist, set to None (optional field)
        
        # Create message in database
        message_obj = Notification(
            user_id=receiver_id,
            sender_id=user_id,
            mentor_id=validated_mentor_id,
            message=message,
            message_type='chat',
            is_read=False
        )
        
        session.add(message_obj)
        session.commit()
        
        # Get sender info
        sender = session.query(User).filter_by(id=user_id).first()
        
        message_data = {
            'id': message_obj.id,
            'sender_id': user_id,
            'receiver_id': receiver_id,
            'sender_name': sender.username if sender else 'Unknown',
            'message': message,
            'timestamp': message_obj.timestamp.isoformat(),
            'mentor_id': validated_mentor_id
        }
        
        # Debug logging
        print(f"[Socket.IO] Emitting new_message to user_{receiver_id} and user_{user_id}")
        print(f"[Socket.IO] Message data: {message_data}")
        
        # Emit to receiver's room
        socketio.emit('new_message', message_data, room=f"user_{receiver_id}", namespace='/')
        
        # Emit to sender's room (so sender sees their own message)
        socketio.emit('new_message', message_data, room=f"user_{user_id}", namespace='/')
        
        # Emit confirmation to sender
        emit('message_sent', {
            'id': message_obj.id,
            'message': 'Message sent successfully'
        })
        
    except Exception as e:
        emit('error', {'message': f'Error sending message: {str(e)}'})
    finally:
        session.close()


@socketio.on('mark_notification_read_socket')
def handle_mark_notification_read_socket(data):
    user_id = data.get('user_id')
    notification_id = data.get('notification_id')
    
    if not user_id or not notification_id:
        emit('error', {'message': 'Missing user_id or notification_id'})
        return
    
    session = Session()
    try:
        notification = session.query(Notification).filter_by(
            id=notification_id,
            user_id=user_id
        ).first()
        
        if notification:
            notification.is_read = True
            session.commit()
            emit('notification_marked_read', {
                'notification_id': notification_id,
                'message': 'Notification marked as read'
            }, room=f"user_{user_id}")
        else:
            emit('error', {'message': 'Notification not found'})
            
    except Exception as e:
        emit('error', {'message': f'Error marking notification as read: {str(e)}'})
    finally:
        session.close()

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
        include_history = request.args.get('include_history', 'false').lower() == 'true'
        
        if not mentor_id or not user_id:
            return jsonify({"error": "mentor_id and user_id are required"}), 400

        milestone_entry = session.query(UserMentorship).filter_by(
            mentor_id=mentor_id,
            user_id=user_id
        ).first()

        if not milestone_entry:
            return jsonify([]), 200

        # Get current milestone list (latest state)
        current_milestones = milestone_entry.milestone or []

        # Prepare response with latest milestone outside
        milestone_data = {
            "serial_number": milestone_entry.serial_number,
            "user_id": milestone_entry.user_id,
            "mentor_id": milestone_entry.mentor_id,
            "current_milestone": current_milestones,  # Latest state
            "check_id": milestone_entry.check_id,
            "check_meeting_id": milestone_entry.check_meeting_id,
            "created_at": milestone_entry.created_at,
            "last_updated": milestone_entry.created_at
        }

        # Include history if requested - all old versions
        if include_history:
            history_records = session.query(MilestoneHistory).filter_by(
                serial_number=milestone_entry.serial_number,
                user_id=milestone_entry.user_id,
                mentor_id=milestone_entry.mentor_id
            ).order_by(MilestoneHistory.edited_at.desc()).all()

            # Put all old versions in history array
            milestone_data["history"] = [
                {
                    "id": record.id,
                    "milestone_state": record.milestone_data,  # Old state
                    "edited_at": record.edited_at,
                    "edited_by": record.edited_by
                }
                for record in history_records
            ]
            milestone_data["history_count"] = len(history_records)
        else:
            milestone_data["history_count"] = 0

        return jsonify(milestone_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route('/api/milestone/by-check-meeting', methods=['GET'])
@jwt_required()
def get_milestone_by_check_meeting():
    session = Session()
    try:
        def _clean_param(param_name):
            value = request.args.get(param_name)
            return value.strip() if isinstance(value, str) else value

        mentor_id = _clean_param('mentor_id')
        user_id = _clean_param('user_id')
        check_meeting_id = _clean_param('check_meeting_id')
        history = request.args.get('history', default='0')

        if not mentor_id or not user_id:
            return jsonify({"error": "mentor_id and user_id are required"}), 400

        try:
            mentor_id_int = int(mentor_id)
            user_id_int = int(user_id)
            check_meeting_id_int = int(check_meeting_id) if check_meeting_id else None
        except ValueError:
            return jsonify({"error": "mentor_id, user_id, and check_meeting_id (if provided) must be integers"}), 400

        milestone_query = session.query(UserMentorship).filter_by(
            mentor_id=mentor_id_int,
            user_id=user_id_int
        )

        if check_meeting_id_int is not None:
            milestone_query = milestone_query.filter_by(check_meeting_id=check_meeting_id_int)

        milestone_entry = milestone_query.order_by(UserMentorship.created_at.desc()).first()

        if not milestone_entry:
            missing_fields = "mentor_id, user_id, and check_meeting_id" if check_meeting_id else "mentor_id and user_id"
            return jsonify({"error": f"No milestone found for the given {missing_fields}"}), 404

        milestone_list = milestone_entry.milestone or []
        latest_milestone = milestone_list[-1] if isinstance(milestone_list, list) and milestone_list else {}
        history_count = len(milestone_list)

        milestone_data = {
            "serial_number": milestone_entry.serial_number,
            "user_id": milestone_entry.user_id,
            "mentor_id": milestone_entry.mentor_id,
            "latest_milestone": latest_milestone,
            "check_id": milestone_entry.check_id,
            "check_meeting_id": milestone_entry.check_meeting_id,
            "created_at": milestone_entry.created_at,
            "history_count": history_count
        }

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
        current_user = get_jwt_identity()
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

        # Save current state to history before editing
        import copy
        history_record = MilestoneHistory(
            serial_number=milestone_entry.serial_number,
            user_id=milestone_entry.user_id,
            mentor_id=milestone_entry.mentor_id,
            milestone_data=copy.deepcopy(milestone_entry.milestone) if milestone_entry.milestone else [],
            edited_by=current_user
        )
        session.add(history_record)

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
        return jsonify({"message": "Milestone appended successfully", "history_saved": True}), 200

    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


# edit specific milestone item
@app.route('/api/milestone', methods=['PATCH'])
@jwt_required()
def edit_milestone_item():
    session = Session()
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        serial_number = data.get('serial_number')
        mentor_id = data.get('mentor_id')
        user_id = data.get('user_id')
        milestone_index = data.get('milestone_index')  # Index of milestone to edit
        updated_milestone = data.get('milestone')  # New milestone data

        if not all([serial_number, mentor_id, user_id, milestone_index is not None, updated_milestone]):
            return jsonify({"error": "serial_number, mentor_id, user_id, milestone_index, and milestone are required"}), 400

        milestone_entry = session.query(UserMentorship).filter_by(
            serial_number=serial_number,
            mentor_id=mentor_id,
            user_id=user_id
        ).first()

        if not milestone_entry:
            return jsonify({"error": "No milestone found for the given serial_number, mentor_id, and user_id"}), 404

        # Ensure milestone is a list
        current_milestones = milestone_entry.milestone
        if current_milestones is None:
            current_milestones = []
        elif isinstance(current_milestones, str):
            try:
                current_milestones = json.loads(current_milestones)
            except Exception:
                current_milestones = []
        elif not isinstance(current_milestones, list):
            current_milestones = [current_milestones]

        # Validate index
        if milestone_index < 0 or milestone_index >= len(current_milestones):
            return jsonify({"error": f"Invalid milestone_index. Must be between 0 and {len(current_milestones) - 1}"}), 400

        # Save current state to history before editing
        import copy
        history_record = MilestoneHistory(
            serial_number=milestone_entry.serial_number,
            user_id=milestone_entry.user_id,
            mentor_id=milestone_entry.mentor_id,
            milestone_data=copy.deepcopy(current_milestones),
            edited_by=current_user
        )
        session.add(history_record)

        # Create a new list with the updated milestone
        updated_milestones = current_milestones.copy()
        updated_milestones[milestone_index] = updated_milestone
        
        # Assign the updated list back to the milestone field
        milestone_entry.milestone = updated_milestones
        flag_modified(milestone_entry, "milestone")

        # Update other fields if provided
        if 'check_id' in data:
            milestone_entry.check_id = data['check_id']
        if 'check_meeting_id' in data:
            milestone_entry.check_meeting_id = data['check_meeting_id']

        session.commit()
        
        return jsonify({
            "message": "Milestone updated successfully",
            "history_saved": True,
            "updated_index": milestone_index,
            "updated_milestone": updated_milestone
        }), 200

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
            "notification_data": {
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
        intent_price = data.get('intent_price', [])  # New field for intent and price pairs
        current_role = data.get('current_role', None)
        work_experience = data.get('work_experience', None)
        interested_field = data.get('interested_field', None)
       
        # Validate availability data
        if availability:
            for slot in availability:
                if not all(key in slot for key in ['day', 'startTime', 'endTime']):
                    return jsonify({'error': 'Invalid availability format'}), 400
        
        # Validate intent_price data
        if intent_price:
            for item in intent_price:
                if not all(key in item for key in ['intent', 'price']):
                    return jsonify({'error': 'Invalid intent_price format. Each item must have "intent" and "price" fields'}), 400
                # Validate that price is a valid number
                try:
                    float(item['price'])
                except (ValueError, TypeError):
                    return jsonify({'error': 'Price must be a valid number'}), 400
        
        print("availability==>",availability)
        print("intent_price==>",intent_price)
       
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
            intent_price=intent_price,  # Add intent_price to the new mentor
            current_role=current_role,
            work_experience=work_experience,
            interested_field=interested_field
        )
       
        session.add(new_mentor)
        session.flush()  # Flush to get the mentor_id
        
        # Automatically create wallet for the new mentor
        mentor_wallet = Wallet(owner_type='mentor', owner_id=new_mentor.mentor_id)
        session.add(mentor_wallet)
        
        session.commit()
        return jsonify({
            'message': 'New mentor added successfully', 
            'mentor_id': new_mentor.mentor_id,
            'availability': availability,
            'intent_price': intent_price
        }), 201
    except IntegrityError:
        session.rollback()
        return jsonify({'error': 'Email already exists'}), 400
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500


# Update existing mentor
@app.route('/update_mentor/<int:mentor_id>', methods=['PUT'])
@jwt_required()
def update_mentor(mentor_id):
    current_user = get_jwt_identity()
    session = Session()
   
    # Fetch the user based on the JWT identity
    user = session.query(User).filter_by(username=current_user).first()
   
    if not user:
        return jsonify({"message": "User not found"}), 404
   
    try:
        # Fetch the existing mentor
        mentor = session.query(Newmentor).filter_by(mentor_id=mentor_id).first()
        
        if not mentor:
            return jsonify({'error': 'Mentor not found'}), 404
        
        # Check if the mentor belongs to the current user
        if mentor.user_id != user.id:
            return jsonify({'error': 'Unauthorized to update this mentor'}), 403
        
        data = request.get_json()
        
        # Check if email is being updated and if it already exists for another mentor
        if 'email' in data:
            new_email = data['email']
            # Only check if the email is actually changing
            if new_email != mentor.email:
                # Check if email already exists for another mentor
                existing_mentor = session.query(Newmentor).filter(
                    Newmentor.email == new_email,
                    Newmentor.mentor_id != mentor_id
                ).first()
                if existing_mentor:
                    return jsonify({'error': 'Email already exists'}), 400
        
        # Update fields if provided
        if 'name' in data:
            mentor.name = data['name']
        if 'email' in data:
            mentor.email = data['email']
        if 'phone' in data:
            mentor.phone = data['phone']
        if 'linkedin' in data:
            mentor.linkedin = data['linkedin']
        if 'expertise' in data:
            mentor.expertise = data['expertise']
        if 'degree' in data:
            mentor.degree = data['degree']
        if 'background' in data:
            mentor.background = data['background']
        if 'fee' in data:
            mentor.fee = data['fee']
        if 'milestones' in data:
            mentor.milestones = data['milestones']
        if 'profile_picture' in data:
            mentor.profile_picture = data['profile_picture']
        if 'resume' in data:
            mentor.resume = data['resume']
        if 'current_role' in data:
            mentor.current_role = data['current_role']
        if 'work_experience' in data:
            mentor.work_experience = data['work_experience']
        if 'interested_field' in data:
            mentor.interested_field = data['interested_field']
        
        # Validate and update availability data
        if 'availability' in data:
            availability = data['availability']
            if availability:
                for slot in availability:
                    if not all(key in slot for key in ['day', 'startTime', 'endTime']):
                        return jsonify({'error': 'Invalid availability format'}), 400
            mentor.availability = availability
        
        # Validate and update intent_price data
        if 'intent_price' in data:
            intent_price = data['intent_price']
            if intent_price:
                for item in intent_price:
                    if not all(key in item for key in ['intent', 'price']):
                        return jsonify({'error': 'Invalid intent_price format. Each item must have "intent" and "price" fields'}), 400
                    # Validate that price is a valid number
                    try:
                        float(item['price'])
                    except (ValueError, TypeError):
                        return jsonify({'error': 'Price must be a valid number'}), 400
            mentor.intent_price = intent_price
        
        session.commit()
        
        return jsonify({
            'message': 'Mentor updated successfully',
            'mentor_id': mentor.mentor_id,
            'name': mentor.name,
            'email': mentor.email,
            'availability': mentor.availability,
            'intent_price': mentor.intent_price
        }), 200
        
    except IntegrityError:
        session.rollback()
        return jsonify({'error': 'Email already exists'}), 400
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()
    
    
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

        # Debug logging
        print(f"[new_assign_mentor] Emitting notification to user_{user_id} and user_{mentor.user_id}")
        
        # Emit real-time notifications to both user and mentor
        socketio.emit('notification', {
            'message': notification_message_user, 
            'mentor_id': mentor_id, 
            'user_id': user_id
        }, room=f"user_{user_id}", namespace='/')
        
        socketio.emit('notification', {
            'message': notification_message_mentor, 
            'mentor_id': mentor_id, 
            'user_id': user_id
        }, room=f"user_{mentor.user_id}", namespace='/')

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


# Get count of users assigned to a specific mentor
@app.route('/mentor_assigned_users_count/<int:mentor_id>', methods=['GET'])
@jwt_required()
def get_mentor_assigned_users_count(mentor_id):
    session = Session()
    
    try:
        # Check if mentor exists
        mentor = session.query(Newmentor).filter_by(mentor_id=mentor_id).first()
        
        if not mentor:
            return jsonify({'error': 'Mentor not found'}), 404
        
        # Count the number of users assigned to this mentor
        assigned_users_count = session.query(UserMentorAssignment).filter_by(mentor_id=mentor_id).count()
        
        # Optionally, get the list of assigned user IDs
        assignments = session.query(UserMentorAssignment).filter_by(mentor_id=mentor_id).all()
        
        assigned_users = []
        for assignment in assignments:
            user = assignment.user
            # In this system, username is used as email
            email = user.email if hasattr(user, 'email') and user.email else user.username
            
            user_detail = {
                'user_id': user.id,
                'username': user.username,
                'email': email,
                'assigned_at': assignment.assigned_at.isoformat() if assignment.assigned_at else None
            }
            
            # Add user details if available
            if user.details:
                user_detail.update({
                    'first_name': user.details.first_name,
                    'last_name': user.details.last_name,
                    'school_name': user.details.school_name,
                    'bachelors_degree': user.details.bachelors_degree,
                    'masters_degree': user.details.masters_degree,
                    'certification': user.details.certification,
                    'activity': user.details.activity,
                    'country': user.details.country,
                    'stream_name': user.details.stream_name,
                    'data_filled': user.details.data_filled
                })
            
            # Add basic info if available (using username as email)
            basic_info = session.query(BasicInfo).filter_by(emailid=email).first()
            if basic_info:
                user_detail.update({
                    'basic_info': {
                        'firstname': basic_info.firstname,
                        'lastname': basic_info.lastname,
                        'high_education': basic_info.high_education,
                        'interested_stream': basic_info.interested_stream,
                        'role_based': basic_info.role_based,
                        'work_experience': basic_info.work_experience,
                        'industry': basic_info.industry,
                        'role': basic_info.role,
                        'intent': _deserialize_intent_payload(basic_info.intent),
                        'bachelor': basic_info.bachelor
                    }
                })
            
            assigned_users.append(user_detail)
        
        return jsonify({
            'mentor_id': mentor_id,
            'mentor_name': mentor.name,
            'mentor_email': mentor.email,
            'assigned_users_count': assigned_users_count,
            'assigned_users': assigned_users
        }), 200
        
    except Exception as e:
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


        # If query param allmentor=true, return all mentors without fuzzy filtering
        allmentor_flag = (request.args.get('allmentor', '') or '').strip().lower()
        if allmentor_flag in ('true', '1', 'yes'):            
            recommended_mentors = session.query(Newmentor).all()
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
                    'created_at': m.created_at,
                    'intent_price': m.intent_price
                } for m in recommended_mentors
            ]
            return jsonify({'recommended_mentors': mentor_data}), 200

        # Fetch all intents for this user
        # user_intents = session.query(Intent).filter_by(user_id=user.id).all()
        # intent_map = {
        #     intent.mentor_id: {
        #         'id': intent.id,
        #         'area_exploring': intent.area_exploring,
        #         'goal_challenge': intent.goal_challenge,
        #         'support_types': intent.support_types,
        #         'created_at': intent.created_at.isoformat() if intent.created_at else None
        #     } for intent in user_intents
        # }

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
                'created_at': m.created_at,
                'created_at': m.created_at,
                'intent_price': m.intent_price
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
    session = Session()
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body must be JSON'}), 400

        user_id = data.get('user_id')
        mentor_id = data.get('mentor_id')
        area_exploring = data.get('area_exploring')
        goal_challenge = data.get('goal_challenge')
        support_types = data.get('support_types', [])  # Should be a list/array

        if not user_id or not mentor_id:
            return jsonify({'error': 'user_id and mentor_id are required'}), 400

        # Validate user exists and derive email
        user = session.query(User).filter_by(id=int(user_id)).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        email = user.username  # username acts as email in this system

        # Fetch useruniqid from BasicInfo using email
        user_info = session.query(BasicInfo).filter_by(emailid=email).first()
        if not user_info:
            return jsonify({'error': 'User basic info not found'}), 404
        useruniqid = user_info.useruniqid

        # Enforce uniqueness on (user_id, mentor_id)
        existing_intent = session.query(Intent).filter_by(user_id=int(user_id), mentor_id=int(mentor_id)).first()
        if existing_intent:
            return jsonify({'error': 'Intent already exists for this user and mentor'}), 400

        # Save intent
        new_intent = Intent(
            useruniqid=useruniqid,
            email=email,
            area_exploring=area_exploring,
            goal_challenge=goal_challenge,
            support_types=support_types,
            user_id=int(user_id),
            mentor_id=int(mentor_id)
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



def _serialize_intent_payload(intent_payload):
    """Ensure intent payload is stored as JSON string."""
    if intent_payload is None:
        return None

    parsed_payload = intent_payload
    if isinstance(intent_payload, str):
        try:
            parsed_payload = json.loads(intent_payload)
        except json.JSONDecodeError:
            raise ValueError("Intent must be a valid JSON object")

    if not isinstance(parsed_payload, dict):
        raise ValueError("Intent must be provided as a JSON object with boolean flags")

    return json.dumps(parsed_payload)


def _deserialize_intent_payload(intent_value):
    if intent_value is None:
        return None
    if isinstance(intent_value, dict):
        return intent_value
    try:
        parsed = json.loads(intent_value)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass
    return intent_value


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
        


        try:
            serialized_intent = _serialize_intent_payload(data.get('intent'))
        except ValueError as intent_error:
            return jsonify({'error': str(intent_error)}), 400

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
            work_experience=data.get('work_experience'),
            industry=data.get('industry'),
            role=data.get('role'),
            intent=serialized_intent,
            bachelor=data.get('bachelor')
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
            'work_experience': user_info.work_experience,
            'industry': user_info.industry,
            'role': user_info.role,
            'intent': _deserialize_intent_payload(user_info.intent),
            'bachelor': user_info.bachelor,
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
        if 'industry' in data:
            user_info.industry = data['industry']
        if 'role' in data:
            user_info.role = data['role']
        if 'intent' in data:
            try:
                user_info.intent = _serialize_intent_payload(data['intent'])
            except ValueError as intent_error:
                return jsonify({'error': str(intent_error)}), 400
        if 'bachelor' in data:
            user_info.bachelor = data['bachelor']
        if 'work_experience' in data:
            user_info.work_experience = data['work_experience']

        # Commit changes
        session.commit()

        return jsonify({'message': 'Basic info updated successfully'}), 200

    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500

    finally:
        session.close()

# Meeting Notification API Endpoints
@app.route('/api/meeting-notifications', methods=['GET'])
@jwt_required()
def get_meeting_notifications():
    """Get all meeting notifications for the current user"""
    current_user = get_jwt_identity()
    session = Session()
    
    try:
        # Get user from JWT identity
        user = session.query(User).filter_by(username=current_user).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get query parameters
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        # Build query
        query = session.query(MeetingNotification).filter_by(user_id=user.id)
        
        if unread_only:
            query = query.filter_by(is_read=False)
        
        notifications = query.order_by(MeetingNotification.created_at.desc()).offset(offset).limit(limit).all()
        
        notification_list = [
            {
                "id": notif.id,
                "mentor_id": notif.mentor_id,
                "schedule_id": notif.schedule_id,
                "notification_type": notif.notification_type,
                "title": notif.title,
                "message": notif.message,
                "meeting_datetime": notif.meeting_datetime.isoformat() if notif.meeting_datetime else None,
                "meeting_link": notif.meeting_link,
                "is_read": notif.is_read,
                "created_at": notif.created_at.isoformat(),
                "read_at": notif.read_at.isoformat() if notif.read_at else None,
                "notification_data": notif.notification_data
            }
            for notif in notifications
        ]
        
        return jsonify({"notifications": notification_list}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/meeting-notifications/<int:notification_id>/read', methods=['PUT'])
@jwt_required()
def mark_notification_read(notification_id):
    """Mark a specific notification as read"""
    current_user = get_jwt_identity()
    session = Session()
    
    try:
        # Get user from JWT identity
        user = session.query(User).filter_by(username=current_user).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Find the notification
        notification = session.query(MeetingNotification).filter_by(
            id=notification_id, 
            user_id=user.id
        ).first()
        
        if not notification:
            return jsonify({'error': 'Notification not found'}), 404
        
        # Mark as read
        notification.is_read = True
        notification.read_at = datetime.utcnow()
        session.commit()
        
        return jsonify({'message': 'Notification marked as read'}), 200
        
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/meeting-notifications/mark-all-read', methods=['PUT'])
@jwt_required()
def mark_all_notifications_read():
    """Mark all notifications as read for the current user"""
    current_user = get_jwt_identity()
    session = Session()
    
    try:
        # Get user from JWT identity
        user = session.query(User).filter_by(username=current_user).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Mark all unread notifications as read
        updated_count = session.query(MeetingNotification).filter_by(
            user_id=user.id, 
            is_read=False
        ).update({
            'is_read': True,
            'read_at': datetime.utcnow()
        })
        
        session.commit()
        
        return jsonify({
            'message': f'{updated_count} notifications marked as read'
        }), 200
        
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/meeting-notifications/unread-count', methods=['GET'])
@jwt_required()
def get_unread_notification_count():
    """Get the count of unread notifications for the current user"""
    current_user = get_jwt_identity()
    session = Session()
    
    try:
        # Get user from JWT identity
        user = session.query(User).filter_by(username=current_user).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Count unread notifications
        unread_count = session.query(MeetingNotification).filter_by(
            user_id=user.id, 
            is_read=False
        ).count()
        
        return jsonify({'unread_count': unread_count}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/meeting-notifications', methods=['POST'])
@jwt_required()
def create_meeting_notification():
    """Create a new meeting notification (for admin or system use)"""
    current_user = get_jwt_identity()
    session = Session()
    
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['user_id', 'mentor_id', 'notification_type', 'title', 'message']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        # Create notification
        notification = MeetingNotification(
            user_id=data['user_id'],
            mentor_id=data['mentor_id'],
            schedule_id=data.get('schedule_id'),
            notification_type=data['notification_type'],
            title=data['title'],
            message=data['message'],
            meeting_datetime=datetime.fromisoformat(data['meeting_datetime']) if data.get('meeting_datetime') else None,
            meeting_link=data.get('meeting_link'),
            notification_data=data.get('notification_data')
        )
        
        session.add(notification)
        session.commit()
        
        # Send real-time notification
        notification_data = {
            "id": notification.id,
            "mentor_id": notification.mentor_id,
            "schedule_id": notification.schedule_id,
            "notification_type": notification.notification_type,
            "title": notification.title,
            "message": notification.message,
            "meeting_datetime": notification.meeting_datetime.isoformat() if notification.meeting_datetime else None,
            "meeting_link": notification.meeting_link,
            "is_read": False,
            "created_at": notification.created_at.isoformat(),
            "notification_data": notification.notification_data
        }
        
        # Send to user room
        socketio.emit('new_meeting_notification', notification_data, room=f"meeting_user_{notification.user_id}", namespace='/')
        
        return jsonify({
            'message': 'Notification created successfully',
            'notification_id': notification.id
        }), 201
        
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/meeting-notifications/reminder', methods=['POST'])
@jwt_required()
def send_meeting_reminder():
    """Send meeting reminder notifications"""
    current_user = get_jwt_identity()
    session = Session()
    
    try:
        data = request.get_json()
        schedule_id = data.get('schedule_id')
        
        if not schedule_id:
            return jsonify({'error': 'schedule_id is required'}), 400
        
        # Get schedule details
        schedule = session.query(Schedule).filter_by(id=schedule_id).first()
        if not schedule:
            return jsonify({'error': 'Schedule not found'}), 404
        
        # Send reminder to user
        user_reminder_id = send_meeting_notification(
            user_id=schedule.user_id,
            mentor_id=schedule.mentor_id,
            notification_type='meeting_reminder',
            title='Meeting Reminder',
            message=f'Reminder: Your meeting with {schedule.mentor_name} is scheduled for {schedule.start_datetime.strftime("%Y-%m-%d at %H:%M")}',
            schedule_id=schedule.id,
            meeting_datetime=schedule.start_datetime,
            meeting_link=schedule.link,
            notification_data={'mentor_name': schedule.mentor_name, 'duration': schedule.duration}
        )
        
        # Send reminder to mentor
        mentor_reminder_id = send_meeting_notification(
            user_id=schedule.mentor_id,
            mentor_id=schedule.mentor_id,
            notification_type='meeting_reminder',
            title='Meeting Reminder',
            message=f'Reminder: Your meeting with {schedule.name} is scheduled for {schedule.start_datetime.strftime("%Y-%m-%d at %H:%M")}',
            schedule_id=schedule.id,
            meeting_datetime=schedule.start_datetime,
            meeting_link=schedule.link,
            notification_data={'user_name': schedule.name, 'duration': schedule.duration}
        )
        
        return jsonify({
            'message': 'Meeting reminders sent successfully',
            'user_reminder_id': user_reminder_id,
            'mentor_reminder_id': mentor_reminder_id
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/meeting-notifications/cancel', methods=['POST'])
@jwt_required()
def send_meeting_cancellation():
    """Send meeting cancellation notifications"""
    current_user = get_jwt_identity()
    session = Session()
    
    try:
        data = request.get_json()
        schedule_id = data.get('schedule_id')
        cancellation_reason = data.get('reason', 'No reason provided')
        
        if not schedule_id:
            return jsonify({'error': 'schedule_id is required'}), 400
        
        # Get schedule details
        schedule = session.query(Schedule).filter_by(id=schedule_id).first()
        if not schedule:
            return jsonify({'error': 'Schedule not found'}), 404
        
        # Send cancellation to user
        user_cancellation_id = send_meeting_notification(
            user_id=schedule.user_id,
            mentor_id=schedule.mentor_id,
            notification_type='meeting_cancelled',
            title='Meeting Cancelled',
            message=f'Your meeting with {schedule.mentor_name} scheduled for {schedule.start_datetime.strftime("%Y-%m-%d at %H:%M")} has been cancelled. Reason: {cancellation_reason}',
            schedule_id=schedule.id,
            meeting_datetime=schedule.start_datetime,
            meeting_link=schedule.link,
            notification_data={'mentor_name': schedule.mentor_name, 'cancellation_reason': cancellation_reason}
        )
        
        # Send cancellation to mentor
        mentor_cancellation_id = send_meeting_notification(
            user_id=schedule.mentor_id,
            mentor_id=schedule.mentor_id,
            notification_type='meeting_cancelled',
            title='Meeting Cancelled',
            message=f'Your meeting with {schedule.name} scheduled for {schedule.start_datetime.strftime("%Y-%m-%d at %H:%M")} has been cancelled. Reason: {cancellation_reason}',
            schedule_id=schedule.id,
            meeting_datetime=schedule.start_datetime,
            meeting_link=schedule.link,
            notification_data={'user_name': schedule.name, 'cancellation_reason': cancellation_reason}
        )
        
        return jsonify({
            'message': 'Meeting cancellation notifications sent successfully',
            'user_cancellation_id': user_cancellation_id,
            'mentor_cancellation_id': mentor_cancellation_id
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/meeting-notifications/upcoming', methods=['GET'])
@jwt_required()
def get_upcoming_meetings():
    """Get upcoming meetings for the current user"""
    current_user = get_jwt_identity()
    session = Session()
    
    try:
        # Get user from JWT identity
        user = session.query(User).filter_by(username=current_user).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get upcoming meetings (next 7 days)
        from datetime import timedelta
        now = datetime.utcnow()
        week_from_now = now + timedelta(days=7)
        
        upcoming_meetings = session.query(Schedule).filter(
            or_(Schedule.user_id == user.id, Schedule.mentor_id == user.id),
            Schedule.start_datetime > now,
            Schedule.start_datetime <= week_from_now
        ).order_by(Schedule.start_datetime).all()
        
        meetings_list = [
            {
                "id": meeting.id,
                "name": meeting.name,
                "email": meeting.email,
                "start_datetime": meeting.start_datetime.isoformat(),
                "end_datetime": meeting.end_datetime.isoformat(),
                "link": meeting.link,
                "mentor_id": meeting.mentor_id,
                "mentor_name": meeting.mentor_name,
                "mentor_email": meeting.mentor_email,
                "user_id": meeting.user_id,
                "duration": meeting.duration,
                "timezone": meeting.timezone
            }
            for meeting in upcoming_meetings
        ]
        
        return jsonify({"upcoming_meetings": meetings_list}), 200
        
    except Exception as e:
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


@socketio.on('join_chat_room')
def handle_join_chat_room(data):
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

# Meeting Notification Socket Events
@socketio.on('join_meeting_room')
def handle_join_meeting_room(data):
    """Join a user to their meeting notification room"""
    user_id = data.get('user_id')
    user_type = data.get('user_type', 'user')  # 'user' or 'mentor'
    
    if not user_id:
        emit('meeting_notification_error', {"error": "user_id is required"})
        return
    
    room_name = f"meeting_{user_type}_{user_id}"
    join_room(room_name)
    emit('joined_meeting_room', {"room": room_name, "user_id": user_id, "user_type": user_type})

@socketio.on('get_meeting_notifications')
def handle_get_meeting_notifications(data):
    """Get all meeting notifications for a user"""
    user_id = data.get('user_id')
    
    if not user_id:
        emit('meeting_notification_error', {"error": "user_id is required"})
        return
    
    session = Session()
    try:
        notifications = session.query(MeetingNotification).filter_by(user_id=user_id).order_by(MeetingNotification.created_at.desc()).all()
        
        notification_list = [
            {
                "id": notif.id,
                "mentor_id": notif.mentor_id,
                "schedule_id": notif.schedule_id,
                "notification_type": notif.notification_type,
                "title": notif.title,
                "message": notif.message,
                "meeting_datetime": notif.meeting_datetime.isoformat() if notif.meeting_datetime else None,
                "meeting_link": notif.meeting_link,
                "is_read": notif.is_read,
                "created_at": notif.created_at.isoformat(),
                "read_at": notif.read_at.isoformat() if notif.read_at else None,
                "notification_data": notif.notification_data
            }
            for notif in notifications
        ]
        
        emit('meeting_notifications', {"notifications": notification_list})
    except Exception as e:
        emit('meeting_notification_error', {"error": str(e)})
    finally:
        session.close()

@socketio.on('mark_notification_read')
def handle_mark_notification_read(data):
    """Mark a meeting notification as read"""
    notification_id = data.get('notification_id')
    user_id = data.get('user_id')
    
    if not notification_id or not user_id:
        emit('meeting_notification_error', {"error": "notification_id and user_id are required"})
        return
    
    session = Session()
    try:
        notification = session.query(MeetingNotification).filter_by(id=notification_id, user_id=user_id).first()
        
        if not notification:
            emit('meeting_notification_error', {"error": "Notification not found"})
            return
        
        notification.is_read = True
        notification.read_at = datetime.utcnow()
        session.commit()
        
        emit('notification_marked_read', {"notification_id": notification_id, "success": True})
    except Exception as e:
        session.rollback()
        emit('meeting_notification_error', {"error": str(e)})
    finally:
        session.close()

def send_meeting_notification(user_id, mentor_id, notification_type, title, message, schedule_id=None, meeting_datetime=None, meeting_link=None, notification_data=None):
    """Helper function to create and send meeting notifications"""
    session = Session()
    try:
        # Create notification record
        notification = MeetingNotification(
            user_id=user_id,
            mentor_id=mentor_id,
            schedule_id=schedule_id,
            notification_type=notification_type,
            title=title,
            message=message,
            meeting_datetime=meeting_datetime,
            meeting_link=meeting_link,
            notification_data=notification_data
        )
        session.add(notification)
        session.commit()
        
        # Send real-time notification via Socket.IO
        notification_data = {
            "id": notification.id,
            "mentor_id": mentor_id,
            "schedule_id": schedule_id,
            "notification_type": notification_type,
            "title": title,
            "message": message,
            "meeting_datetime": meeting_datetime.isoformat() if meeting_datetime else None,
            "meeting_link": meeting_link,
            "is_read": False,
            "created_at": notification.created_at.isoformat(),
            "notification_data": notification_data
        }
        
        # Send to user room
        socketio.emit('new_meeting_notification', notification_data, room=f"meeting_user_{user_id}", namespace='/')
        
        return notification.id
    except Exception as e:
        session.rollback()
        print(f"Error sending meeting notification: {str(e)}")
        return None
    finally:
        session.close()



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




# ===========================================
# CATEGORY MANAGEMENT APIs
# ===========================================

# Helper function to validate category type
def validate_category_type(category_type):
    valid_types = ['education', 'industry', 'experience_level', 'role', 'skills']
    return category_type in valid_types

# ===========================================
# EDUCATION APIs
# ===========================================

@app.route('/api/education', methods=['GET'])
def get_education_list():
    """Get all education categories (deduplicated by name)"""
    session = Session()
    try:
        education_list = session.query(Category).filter_by(
            category_type='education', 
            is_active=True
        ).order_by(Category.name).all()
        
        # Deduplicate by name - keep first occurrence
        seen_names = set()
        result = []
        
        for edu in education_list:
            # Normalize name for comparison (case-insensitive, strip whitespace)
            normalized_name = edu.name.strip().lower()
            
            if normalized_name not in seen_names:
                seen_names.add(normalized_name)
                result.append({
                    'id': edu.id,
                    'name': edu.name,
                    'description': edu.description,
                    'created_at': edu.created_at.isoformat() if edu.created_at else None,
                    'updated_at': edu.updated_at.isoformat() if edu.updated_at else None
                })
        
        return jsonify({'education': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/education', methods=['POST'])
@jwt_required()
def create_education():
    """Create a new education category"""
    session = Session()
    try:
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'error': 'Name is required'}), 400
        
        # Check if education with same name already exists
        existing = session.query(Category).filter_by(
            category_type='education',
            name=data['name']
        ).first()
        
        if existing:
            return jsonify({'error': 'Education with this name already exists'}), 400
        
        new_education = Category(
            category_type='education',
            name=data['name'],
            description=data.get('description'),
            is_active=data.get('is_active', True)
        )
        
        session.add(new_education)
        session.commit()
        
        return jsonify({
            'message': 'Education created successfully',
            'education': {
                'id': new_education.id,
                'name': new_education.name,
                'description': new_education.description,
                'created_at': new_education.created_at.isoformat()
            }
        }), 201
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/education/<int:education_id>', methods=['GET'])
def get_education(education_id):
    """Get a specific education category"""
    session = Session()
    try:
        education = session.query(Category).filter_by(
            id=education_id,
            category_type='education'
        ).first()
        
        if not education:
            return jsonify({'error': 'Education not found'}), 404
        
        return jsonify({
            'id': education.id,
            'name': education.name,
            'description': education.description,
            'is_active': education.is_active,
            'created_at': education.created_at.isoformat() if education.created_at else None,
            'updated_at': education.updated_at.isoformat() if education.updated_at else None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/education/<int:education_id>', methods=['PUT'])
@jwt_required()
def update_education(education_id):
    """Update an education category"""
    session = Session()
    try:
        data = request.get_json()
        education = session.query(Category).filter_by(
            id=education_id,
            category_type='education'
        ).first()
        
        if not education:
            return jsonify({'error': 'Education not found'}), 404
        
        # Check if name is being updated and if it conflicts with existing
        if 'name' in data and data['name'] != education.name:
            existing = session.query(Category).filter_by(
                category_type='education',
                name=data['name']
            ).first()
            
            if existing:
                return jsonify({'error': 'Education with this name already exists'}), 400
        
        # Update fields
        if 'name' in data:
            education.name = data['name']
        if 'description' in data:
            education.description = data['description']
        if 'is_active' in data:
            education.is_active = data['is_active']
        
        education.updated_at = datetime.utcnow()
        session.commit()
        
        return jsonify({
            'message': 'Education updated successfully',
            'education': {
                'id': education.id,
                'name': education.name,
                'description': education.description,
                'is_active': education.is_active,
                'updated_at': education.updated_at.isoformat()
            }
        }), 200
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/education/<int:education_id>', methods=['DELETE'])
@jwt_required()
def delete_education(education_id):
    """Delete an education category (soft delete)"""
    session = Session()
    try:
        education = session.query(Category).filter_by(
            id=education_id,
            category_type='education'
        ).first()
        
        if not education:
            return jsonify({'error': 'Education not found'}), 404
        
        education.is_active = False
        education.updated_at = datetime.utcnow()
        session.commit()
        
        return jsonify({'message': 'Education deleted successfully'}), 200
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

# ===========================================
# INDUSTRY APIs
# ===========================================

@app.route('/api/industry', methods=['GET'])
def get_industry_list():
    """Get all industry categories (deduplicated by name)"""
    session = Session()
    try:
        industry_list = session.query(Category).filter_by(
            category_type='industry', 
            is_active=True
        ).order_by(Category.name).all()
        
        # Deduplicate by name - keep first occurrence
        seen_names = set()
        result = []
        
        for ind in industry_list:
            # Normalize name for comparison (case-insensitive, strip whitespace)
            normalized_name = ind.name.strip().lower()
            
            if normalized_name not in seen_names:
                seen_names.add(normalized_name)
                result.append({
                    'id': ind.id,
                    'name': ind.name,
                    'description': ind.description,
                    'created_at': ind.created_at.isoformat() if ind.created_at else None,
                    'updated_at': ind.updated_at.isoformat() if ind.updated_at else None
                })
        
        return jsonify({'industry': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/industry', methods=['POST'])
@jwt_required()
def create_industry():
    """Create a new industry category"""
    session = Session()
    try:
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'error': 'Name is required'}), 400
        
        # Check if industry with same name already exists
        existing = session.query(Category).filter_by(
            category_type='industry',
            name=data['name']
        ).first()
        
        if existing:
            return jsonify({'error': 'Industry with this name already exists'}), 400
        
        new_industry = Category(
            category_type='industry',
            name=data['name'],
            description=data.get('description'),
            is_active=data.get('is_active', True)
        )
        
        session.add(new_industry)
        session.commit()
        
        return jsonify({
            'message': 'Industry created successfully',
            'industry': {
                'id': new_industry.id,
                'name': new_industry.name,
                'description': new_industry.description,
                'created_at': new_industry.created_at.isoformat()
            }
        }), 201
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/industry/<int:industry_id>', methods=['GET'])
def get_industry(industry_id):
    """Get a specific industry category"""
    session = Session()
    try:
        industry = session.query(Category).filter_by(
            id=industry_id,
            category_type='industry'
        ).first()
        
        if not industry:
            return jsonify({'error': 'Industry not found'}), 404
        
        return jsonify({
            'id': industry.id,
            'name': industry.name,
            'description': industry.description,
            'is_active': industry.is_active,
            'created_at': industry.created_at.isoformat() if industry.created_at else None,
            'updated_at': industry.updated_at.isoformat() if industry.updated_at else None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/industry/<int:industry_id>', methods=['PUT'])
@jwt_required()
def update_industry(industry_id):
    """Update an industry category"""
    session = Session()
    try:
        data = request.get_json()
        industry = session.query(Category).filter_by(
            id=industry_id,
            category_type='industry'
        ).first()
        
        if not industry:
            return jsonify({'error': 'Industry not found'}), 404
        
        # Check if name is being updated and if it conflicts with existing
        if 'name' in data and data['name'] != industry.name:
            existing = session.query(Category).filter_by(
                category_type='industry',
                name=data['name']
            ).first()
            
            if existing:
                return jsonify({'error': 'Industry with this name already exists'}), 400
        
        # Update fields
        if 'name' in data:
            industry.name = data['name']
        if 'description' in data:
            industry.description = data['description']
        if 'is_active' in data:
            industry.is_active = data['is_active']
        
        industry.updated_at = datetime.utcnow()
        session.commit()
        
        return jsonify({
            'message': 'Industry updated successfully',
            'industry': {
                'id': industry.id,
                'name': industry.name,
                'description': industry.description,
                'is_active': industry.is_active,
                'updated_at': industry.updated_at.isoformat()
            }
        }), 200
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/industry/<int:industry_id>', methods=['DELETE'])
@jwt_required()
def delete_industry(industry_id):
    """Delete an industry category (soft delete)"""
    session = Session()
    try:
        industry = session.query(Category).filter_by(
            id=industry_id,
            category_type='industry'
        ).first()
        
        if not industry:
            return jsonify({'error': 'Industry not found'}), 404
        
        industry.is_active = False
        industry.updated_at = datetime.utcnow()
        session.commit()
        
        return jsonify({'message': 'Industry deleted successfully'}), 200
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

# ===========================================
# EXPERIENCE LEVEL APIs
# ===========================================

@app.route('/api/experience-level', methods=['GET'])
def get_experience_level_list():
    """Get all experience level categories"""
    session = Session()
    try:
        experience_list = session.query(Category).filter_by(
            category_type='experience_level', 
            is_active=True
        ).order_by(Category.name).all()
        
        result = [
            {
                'id': exp.id,
                'name': exp.name,
                'description': exp.description,
                'created_at': exp.created_at.isoformat() if exp.created_at else None,
                'updated_at': exp.updated_at.isoformat() if exp.updated_at else None
            }
            for exp in experience_list
        ]
        
        return jsonify({'experience_level': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


@app.route('/api/experience-level/ranges', methods=['GET'])
def get_experience_level_ranges():
    """Return contiguous experience ranges in 'start-end Years' format."""
    static_ranges = [
        {"label": "0-1 Years", "start": 0, "end": 1},
        {"label": "1-3 Years", "start": 1, "end": 3},
        {"label": "3-5 Years", "start": 3, "end": 5},
        {"label": "5-8 Years", "start": 5, "end": 8},
        {"label": "8-12 Years", "start": 8, "end": 12},
        {"label": "12+ Years", "start": 12, "end": None},
    ]

    response_payload = {
        "experience_ranges": [item["label"] for item in static_ranges],
        "range_details": static_ranges,
        "max_year_value": "12+"
    }

    return jsonify(response_payload), 200

@app.route('/api/experience-level', methods=['POST'])
@jwt_required()
def create_experience_level():
    """Create a new experience level category"""
    session = Session()
    try:
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'error': 'Name is required'}), 400
        
        # Check if experience level with same name already exists
        existing = session.query(Category).filter_by(
            category_type='experience_level',
            name=data['name']
        ).first()
        
        if existing:
            return jsonify({'error': 'Experience level with this name already exists'}), 400
        
        new_experience = Category(
            category_type='experience_level',
            name=data['name'],
            description=data.get('description'),
            is_active=data.get('is_active', True)
        )
        
        session.add(new_experience)
        session.commit()
        
        return jsonify({
            'message': 'Experience level created successfully',
            'experience_level': {
                'id': new_experience.id,
                'name': new_experience.name,
                'description': new_experience.description,
                'created_at': new_experience.created_at.isoformat()
            }
        }), 201
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/experience-level/<int:experience_id>', methods=['GET'])
def get_experience_level(experience_id):
    """Get a specific experience level category"""
    session = Session()
    try:
        experience = session.query(Category).filter_by(
            id=experience_id,
            category_type='experience_level'
        ).first()
        
        if not experience:
            return jsonify({'error': 'Experience level not found'}), 404
        
        return jsonify({
            'id': experience.id,
            'name': experience.name,
            'description': experience.description,
            'is_active': experience.is_active,
            'created_at': experience.created_at.isoformat() if experience.created_at else None,
            'updated_at': experience.updated_at.isoformat() if experience.updated_at else None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/experience-level/<int:experience_id>', methods=['PUT'])
@jwt_required()
def update_experience_level(experience_id):
    """Update an experience level category"""
    session = Session()
    try:
        data = request.get_json()
        experience = session.query(Category).filter_by(
            id=experience_id,
            category_type='experience_level'
        ).first()
        
        if not experience:
            return jsonify({'error': 'Experience level not found'}), 404
        
        # Check if name is being updated and if it conflicts with existing
        if 'name' in data and data['name'] != experience.name:
            existing = session.query(Category).filter_by(
                category_type='experience_level',
                name=data['name']
            ).first()
            
            if existing:
                return jsonify({'error': 'Experience level with this name already exists'}), 400
        
        # Update fields
        if 'name' in data:
            experience.name = data['name']
        if 'description' in data:
            experience.description = data['description']
        if 'is_active' in data:
            experience.is_active = data['is_active']
        
        experience.updated_at = datetime.utcnow()
        session.commit()
        
        return jsonify({
            'message': 'Experience level updated successfully',
            'experience_level': {
                'id': experience.id,
                'name': experience.name,
                'description': experience.description,
                'is_active': experience.is_active,
                'updated_at': experience.updated_at.isoformat()
            }
        }), 200
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/experience-level/<int:experience_id>', methods=['DELETE'])
@jwt_required()
def delete_experience_level(experience_id):
    """Delete an experience level category (soft delete)"""
    session = Session()
    try:
        experience = session.query(Category).filter_by(
            id=experience_id,
            category_type='experience_level'
        ).first()
        
        if not experience:
            return jsonify({'error': 'Experience level not found'}), 404
        
        experience.is_active = False
        experience.updated_at = datetime.utcnow()
        session.commit()
        
        return jsonify({'message': 'Experience level deleted successfully'}), 200
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

# ===========================================
# ROLE APIs
# ===========================================

@app.route('/api/role', methods=['GET'])
def get_role_list():
    """Get all role categories"""
    session = Session()
    try:
        role_list = session.query(Category).filter_by(
            category_type='role', 
            is_active=True
        ).order_by(Category.name).all()
        
        result = [
            {
                'id': role.id,
                'name': role.name,
                'description': role.description,
                'created_at': role.created_at.isoformat() if role.created_at else None,
                'updated_at': role.updated_at.isoformat() if role.updated_at else None
            }
            for role in role_list
        ]
        
        return jsonify({'role': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/role', methods=['POST'])
@jwt_required()
def create_role():
    """Create a new role category"""
    session = Session()
    try:
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'error': 'Name is required'}), 400
        
        # Check if role with same name already exists
        existing = session.query(Category).filter_by(
            category_type='role',
            name=data['name']
        ).first()
        
        if existing:
            return jsonify({'error': 'Role with this name already exists'}), 400
        
        new_role = Category(
            category_type='role',
            name=data['name'],
            description=data.get('description'),
            is_active=data.get('is_active', True)
        )
        
        session.add(new_role)
        session.commit()
        
        return jsonify({
            'message': 'Role created successfully',
            'role': {
                'id': new_role.id,
                'name': new_role.name,
                'description': new_role.description,
                'created_at': new_role.created_at.isoformat()
            }
        }), 201
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/role/<int:role_id>', methods=['GET'])
def get_role(role_id):
    """Get a specific role category"""
    session = Session()
    try:
        role = session.query(Category).filter_by(
            id=role_id,
            category_type='role'
        ).first()
        
        if not role:
            return jsonify({'error': 'Role not found'}), 404
        
        return jsonify({
            'id': role.id,
            'name': role.name,
            'description': role.description,
            'is_active': role.is_active,
            'created_at': role.created_at.isoformat() if role.created_at else None,
            'updated_at': role.updated_at.isoformat() if role.updated_at else None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/role/<int:role_id>', methods=['PUT'])
@jwt_required()
def update_role(role_id):
    """Update a role category"""
    session = Session()
    try:
        data = request.get_json()
        role = session.query(Category).filter_by(
            id=role_id,
            category_type='role'
        ).first()
        
        if not role:
            return jsonify({'error': 'Role not found'}), 404
        
        # Check if name is being updated and if it conflicts with existing
        if 'name' in data and data['name'] != role.name:
            existing = session.query(Category).filter_by(
                category_type='role',
                name=data['name']
            ).first()
            
            if existing:
                return jsonify({'error': 'Role with this name already exists'}), 400
        
        # Update fields
        if 'name' in data:
            role.name = data['name']
        if 'description' in data:
            role.description = data['description']
        if 'is_active' in data:
            role.is_active = data['is_active']
        
        role.updated_at = datetime.utcnow()
        session.commit()
        
        return jsonify({
            'message': 'Role updated successfully',
            'role': {
                'id': role.id,
                'name': role.name,
                'description': role.description,
                'is_active': role.is_active,
                'updated_at': role.updated_at.isoformat()
            }
        }), 200
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/role/<int:role_id>', methods=['DELETE'])
@jwt_required()
def delete_role(role_id):
    """Delete a role category (soft delete)"""
    session = Session()
    try:
        role = session.query(Category).filter_by(
            id=role_id,
            category_type='role'
        ).first()
        
        if not role:
            return jsonify({'error': 'Role not found'}), 404
        
        role.is_active = False
        role.updated_at = datetime.utcnow()
        session.commit()
        
        return jsonify({'message': 'Role deleted successfully'}), 200
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

# ===========================================
# SKILLS APIs
# ===========================================

@app.route('/api/skills', methods=['GET'])
def get_skills_list():
    """Get all skills categories"""
    session = Session()
    try:
        skills_list = session.query(Category).filter_by(
            category_type='skills', 
            is_active=True
        ).order_by(Category.name).all()
        
        result = [
            {
                'id': skill.id,
                'name': skill.name,
                'description': skill.description,
                'created_at': skill.created_at.isoformat() if skill.created_at else None,
                'updated_at': skill.updated_at.isoformat() if skill.updated_at else None
            }
            for skill in skills_list
        ]
        
        return jsonify({'skills': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/skills', methods=['POST'])
@jwt_required()
def create_skill():
    """Create a new skill category"""
    session = Session()
    try:
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'error': 'Name is required'}), 400
        
        # Check if skill with same name already exists
        existing = session.query(Category).filter_by(
            category_type='skills',
            name=data['name']
        ).first()
        
        if existing:
            return jsonify({'error': 'Skill with this name already exists'}), 400
        
        new_skill = Category(
            category_type='skills',
            name=data['name'],
            description=data.get('description'),
            is_active=data.get('is_active', True)
        )
        
        session.add(new_skill)
        session.commit()
        
        return jsonify({
            'message': 'Skill created successfully',
            'skill': {
                'id': new_skill.id,
                'name': new_skill.name,
                'description': new_skill.description,
                'created_at': new_skill.created_at.isoformat()
            }
        }), 201
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/skills/<int:skill_id>', methods=['GET'])
def get_skill(skill_id):
    """Get a specific skill category"""
    session = Session()
    try:
        skill = session.query(Category).filter_by(
            id=skill_id,
            category_type='skills'
        ).first()
        
        if not skill:
            return jsonify({'error': 'Skill not found'}), 404
        
        return jsonify({
            'id': skill.id,
            'name': skill.name,
            'description': skill.description,
            'is_active': skill.is_active,
            'created_at': skill.created_at.isoformat() if skill.created_at else None,
            'updated_at': skill.updated_at.isoformat() if skill.updated_at else None
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/skills/<int:skill_id>', methods=['PUT'])
@jwt_required()
def update_skill(skill_id):
    """Update a skill category"""
    session = Session()
    try:
        data = request.get_json()
        skill = session.query(Category).filter_by(
            id=skill_id,
            category_type='skills'
        ).first()
        
        if not skill:
            return jsonify({'error': 'Skill not found'}), 404
        
        # Check if name is being updated and if it conflicts with existing
        if 'name' in data and data['name'] != skill.name:
            existing = session.query(Category).filter_by(
                category_type='skills',
                name=data['name']
            ).first()
            
            if existing:
                return jsonify({'error': 'Skill with this name already exists'}), 400
        
        # Update fields
        if 'name' in data:
            skill.name = data['name']
        if 'description' in data:
            skill.description = data['description']
        if 'is_active' in data:
            skill.is_active = data['is_active']
        
        skill.updated_at = datetime.utcnow()
        session.commit()
        
        return jsonify({
            'message': 'Skill updated successfully',
            'skill': {
                'id': skill.id,
                'name': skill.name,
                'description': skill.description,
                'is_active': skill.is_active,
                'updated_at': skill.updated_at.isoformat()
            }
        }), 200
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/skills/<int:skill_id>', methods=['DELETE'])
@jwt_required()
def delete_skill(skill_id):
    """Delete a skill category (soft delete)"""
    session = Session()
    try:
        skill = session.query(Category).filter_by(
            id=skill_id,
            category_type='skills'
        ).first()
        
        if not skill:
            return jsonify({'error': 'Skill not found'}), 404
        
        skill.is_active = False
        skill.updated_at = datetime.utcnow()
        session.commit()
        
        return jsonify({'message': 'Skill deleted successfully'}), 200
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

# ===========================================
# BULK OPERATIONS
# ===========================================

@app.route('/api/categories/bulk', methods=['POST'])
@jwt_required()
def bulk_create_categories():
    """Bulk create categories"""
    session = Session()
    try:
        data = request.get_json()
        
        if not data or 'categories' not in data:
            return jsonify({'error': 'Categories array is required'}), 400
        
        created_categories = []
        errors = []
        
        for category_data in data['categories']:
            try:
                if not validate_category_type(category_data.get('category_type')):
                    errors.append(f"Invalid category_type: {category_data.get('category_type')}")
                    continue
                
                # Check if category already exists
                existing = session.query(Category).filter_by(
                    category_type=category_data['category_type'],
                    name=category_data['name']
                ).first()
                
                if existing:
                    errors.append(f"Category {category_data['name']} already exists")
                    continue
                
                new_category = Category(
                    category_type=category_data['category_type'],
                    name=category_data['name'],
                    description=category_data.get('description'),
                    is_active=category_data.get('is_active', True)
                )
                
                session.add(new_category)
                created_categories.append({
                    'category_type': new_category.category_type,
                    'name': new_category.name,
                    'description': new_category.description
                })
                
            except Exception as e:
                errors.append(f"Error creating {category_data.get('name', 'unknown')}: {str(e)}")
        
        session.commit()
        
        return jsonify({
            'message': f'Created {len(created_categories)} categories',
            'created': created_categories,
            'errors': errors
        }), 201
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/categories/search', methods=['GET'])
def search_categories():
    """Search categories by name across all types"""
    session = Session()
    try:
        query = request.args.get('q', '').strip()
        category_type = request.args.get('type', '').strip()
        
        if not query:
            return jsonify({'error': 'Search query is required'}), 400
        
        # Build query
        db_query = session.query(Category).filter(
            Category.name.ilike(f'%{query}%'),
            Category.is_active == True
        )
        
        if category_type and validate_category_type(category_type):
            db_query = db_query.filter(Category.category_type == category_type)
        
        results = db_query.order_by(Category.name).all()
        
        categories = [
            {
                'id': cat.id,
                'category_type': cat.category_type,
                'name': cat.name,
                'description': cat.description,
                'created_at': cat.created_at.isoformat() if cat.created_at else None
            }
            for cat in results
        ]
        
        return jsonify({
            'query': query,
            'category_type': category_type,
            'results': categories,
            'count': len(categories)
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()


# Meeting Host APIs
@app.route('/meeting-host/<room_id>', methods=['GET'])
def get_meeting_host(room_id):
    """Get the host peer ID for a room"""
    session = Session()
    try:
        meeting_host = session.query(MeetingHost).filter_by(room_id=room_id).first()
        
        if meeting_host:
            return jsonify({
                "hostPeerId": meeting_host.host_peer_id
            }), 200
        else:
            return jsonify({
                "hostPeerId": None
            }), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route('/meeting-host', methods=['POST'])
def create_meeting_host():
    """Create meeting host record - only if no host exists"""
    session = Session()
    try:
        data = request.get_json()
        room_id = data.get('roomId')
        host_peer_id = data.get('hostPeerId')
        
        if not room_id or not host_peer_id:
            return jsonify({"error": "roomId and hostPeerId are required"}), 400
        
        # Check if host already exists
        existing_host = session.query(MeetingHost).filter_by(room_id=room_id).first()
        
        if existing_host:
            # Host already exists - reject registration
            return jsonify({
                "error": "Host already exists for this room",
                "existingHostPeerId": existing_host.host_peer_id
            }), 409  # 409 Conflict
        else:
            # No host exists - create new host record
            new_host = MeetingHost(
                room_id=room_id,
                host_peer_id=host_peer_id
            )
            session.add(new_host)
            session.commit()
            
            return jsonify({
                "message": "Meeting host registered successfully",
                "roomId": room_id,
                "hostPeerId": host_peer_id
            }), 201  # 201 Created
    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


@app.route('/meeting-host/<room_id>', methods=['DELETE'])
def delete_meeting_host(room_id):
    """Delete meeting host record when host leaves"""
    session = Session()
    try:
        meeting_host = session.query(MeetingHost).filter_by(room_id=room_id).first()
        
        if meeting_host:
            session.delete(meeting_host)
            session.commit()
            return jsonify({
                "message": "Meeting host removed successfully",
                "roomId": room_id
            }), 200 
        else:
            return jsonify({
                "message": "No host found for this room",
                "roomId": room_id
            }), 404
    except Exception as e:
        session.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        session.close()


Base.metadata.create_all(engine)

if __name__ == '__main__':
    socketio.run(app, debug=True)

from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker
import random
from typing import List

Base = declarative_base()

class Information(Base):
    __tablename__ = 'information'
    id = Column(Integer, primary_key=True, autoincrement=True)
    bachelors_degree = Column(String(255))
    masters_degree = Column(String(255))
    certifications = Column(String(255))  # Storing only one certification per record
    primary_expertise_area = Column(String(255))
    highest_degree_achieved = Column(String(255))
    
class Degree(Base):
    __tablename__ = 'degrees'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    courses = Column(Text, nullable=True) 
    competitions = Column(Text, nullable=True) 
    certifications = Column(Text, nullable=True)
    

# Database configuration
DATABASE_URL = "postgresql://neondb_owner:Pl8cWUu0iLHn@ep-tiny-haze-a1w7wrrg.ap-southeast-1.aws.neon.tech/figure_circle"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# Data generators -------------------------------------------------------------
def generate_bachelors() -> List[str]:
    degrees = []
    prefixes = ['B.Sc.', 'B.Tech', 'B.E.', 'B.A.', 'B.Com']
    fields = [
        'Computer Science', 'Electrical Engineering', 'Data Science',
        'Artificial Intelligence', 'Cybersecurity', 'Biotechnology',
        'Mechanical Engineering', 'Digital Marketing', 'Psychology'
    ]
    specializations = [
        'with AI Focus', 'in Cloud Computing', 'IoT Systems',
        'Quantum Computing', 'Robotics', 'Game Development'
    ]
    
    for prefix in prefixes:
        for field in fields:
            degrees.append(f"{prefix} {field}")
            for spec in random.sample(specializations, 3):
                degrees.append(f"{prefix} {field} ({spec})")
    
    random.shuffle(degrees)
    return degrees[:1200]  # Ensure exactly 1200

def generate_masters() -> List[str]:
    programs = []
    prefixes = ['M.Sc.', 'M.Tech', 'M.E.', 'MBA', 'MS', 'M.Res', 'M.Phil']
    fields = [
        'Advanced Computer Science', 'AI Engineering', 'Cybersecurity',
        'Data Analytics', 'Renewable Energy', 'FinTech', 'Robotics',
        'Quantum Computing', 'Bioinformatics', 'Neuroscience',
        'Environmental Science', 'Digital Marketing', 'Supply Chain Management'
    ]
    
    for prefix in prefixes:
        for field in fields:
            programs.append(f"{prefix} {field}")
            programs.append(f"{prefix} {field} (Research Track)")
            programs.append(f"{prefix} {field} (Industry Practice)")

    while len(programs) < 1000:
        programs.extend(programs.copy())

    return random.sample(programs, 1000)

def generate_certifications() -> List[str]:
    vendors = ['AWS', 'Google', 'Microsoft', 'Cisco', 'PMI', 'Oracle']
    types = [
        'Solutions Architect', 'Data Engineer', 'Security Specialist',
        'Cloud Practitioner', 'DevOps Engineer', 'Machine Learning',
        'Java Programmer', 'Database Administrator'
    ]
    levels = ['Associate', 'Professional', 'Expert']
    
    return [
        f"{vendor} Certified {cert_type} ({level})"
        for vendor in vendors
        for cert_type in types
        for level in levels
    ][:1500]

def generate_expertise_areas() -> List[str]:
    techs = ['AI', 'Blockchain', 'IoT', 'Cloud Computing', 'Data Science']
    industries = ['Healthcare', 'Finance', 'Retail', 'Manufacturing', 'Logistics']
    return [
        f"{tech} for {industry}" 
        for tech in techs 
        for industry in industries
    ][:1000]

def generate_highest_degrees() -> List[str]:
    return [
        *[f"Ph.D. {field}" for field in [
            'Computer Science', 'Electrical Engineering', 'Biotechnology',
            'Quantum Physics', 'Neuroscience'
        ]],
        *[f"Dr. {field}" for field in [
            'Engineering', 'Philosophy', 'Education'
        ]],
        *['MBA', 'MD', 'JD']
    ] * 200  # Generate sufficient quantities

# Relationship logic ----------------------------------------------------------
def get_related_masters(bachelor: str) -> str:
    if 'Computer Science' in bachelor:
        return random.choice([
            'M.Sc. Artificial Intelligence',
            'M.Tech Cybersecurity',
            'MS Data Science'
        ])
    elif 'Engineering' in bachelor:
        return random.choice([
            'M.E. Advanced Manufacturing',
            'M.Tech Renewable Energy Systems'
        ])
    return random.choice(masters_list)

def get_related_certification(degree: str) -> str:
    if 'Cloud' in degree:
        return random.choice([
            'AWS Certified Solutions Architect (Professional)',
            'Google Cloud Professional Architect'
        ])
    elif 'AI' in degree:
        return 'TensorFlow Developer Certificate'
    return random.choice(certifications_list)

def get_related_expertise(degrees: list) -> str:
    keywords = ' '.join(degrees).lower()
    if 'data' in keywords:
        return 'Data Pipeline Architecture'
    elif 'security' in keywords:
        return 'Threat Intelligence Analysis'
    return random.choice(expertise_list)

# Main script execution -------------------------------------------------------
if __name__ == "__main__":
    # Generate datasets
    bachelors_list = generate_bachelors()
    masters_list = generate_masters()
    certifications_list = generate_certifications()
    expertise_list = generate_expertise_areas()
    highest_degrees_list = generate_highest_degrees()
    
    # Create 1500 records with logical relationships
    records = []
    for _ in range(1500):
        bachelors = random.choice(bachelors_list)
        masters = get_related_masters(bachelors)
        cert = get_related_certification(bachelors)  # Assign only one certification
        expertise = get_related_expertise([bachelors, masters])
        highest_degree = random.choice([masters, bachelors] + highest_degrees_list)
        
        records.append(Information(
            bachelors_degree=bachelors,
            masters_degree=masters,
            certifications=cert,  # Store a single certification
            primary_expertise_area=expertise,
            highest_degree_achieved=highest_degree
        ))
    
    # Batch insert with error handling
    try:
        with SessionLocal() as session:
            chunk_size = 500
            for i in range(0, len(records), chunk_size):
                session.bulk_save_objects(records[i:i+chunk_size])
                session.commit()
                print(f"Inserted {min(i+chunk_size, len(records))} records")
        print("Success: All records inserted")
    except Exception as e:
        print(f"Error: {str(e)}")
        session.rollback()

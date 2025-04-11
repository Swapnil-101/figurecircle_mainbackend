from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker
# from models import Degree, Base  # Import your Degree model

Base = declarative_base()

DATABASE_URL = "postgresql://neondb_owner:Pl8cWUu0iLHn@ep-tiny-haze-a1w7wrrg.ap-southeast-1.aws.neon.tech/figure_circle"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
session = SessionLocal()

class Degree(Base):
    __tablename__ = 'degrees'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    courses = Column(Text, nullable=True) 
    competitions = Column(Text, nullable=True) 
    certifications = Column(Text, nullable=True)
    
# Bulk Data
degrees = [
    Degree(name="MCA", 
           courses="Software Engineering, Artificial Intelligence, Data Science, Cybersecurity, Web Development, Cloud Computing",
           competitions="CodeChef Contests, Google Kickstart, ACM ICPC, Facebook Hacker Cup, TCS CodeVita, Amazon HackOn",
           certifications="AWS Certified Developer, Google Cloud Associate, Microsoft Azure Fundamentals, Oracle Java Certification, Red Hat Certified Engineer"),

    Degree(name="B.Tech CSE",
           courses="Operating Systems, Machine Learning, Web Development, Cloud Computing, Blockchain, Cybersecurity",
           competitions="Google Code Jam, Facebook Hacker Cup, Microsoft Imagine Cup, ACM ICPC, Topcoder Challenges, Kaggle Competitions",
           certifications="AWS Solutions Architect, Google Professional Cloud Architect, Certified Ethical Hacker, Cisco CCNA, Microsoft AI Engineer"),

    Degree(name="B.Tech ECE",
           courses="VLSI Design, Embedded Systems, IoT, Wireless Communication, Signal Processing, Robotics",
           competitions="Texas Instruments Innovation Challenge, NASA Robotic Mining Competition, IEEE Xtreme Programming, ISRO Hackathons",
           certifications="Embedded Systems Certification, IoT Specialization by Coursera, MATLAB Certification, Cisco Networking Certification"),

    Degree(name="B.Tech IT",
           courses="Full Stack Development, DevOps, Database Management, Software Engineering, Data Mining",
           competitions="Google Code Jam, TCS CodeVita, HackMIT, Major League Hacking (MLH), Hack The Box",
           certifications="Google Associate Cloud Engineer, AWS Cloud Practitioner, Python for Data Science, DevOps Certification"),

    Degree(name="B.Tech Mechanical",
           courses="Thermodynamics, CAD/CAM, Manufacturing Technology, Robotics, Automobile Engineering",
           competitions="Formula SAE, ASME Student Design Competition, Baja SAE, Hyperloop Design Challenge",
           certifications="Autodesk Certified Professional, SolidWorks Certification, Six Sigma Green Belt, PMP Certification"),

    Degree(name="B.Tech Civil",
           courses="Structural Analysis, Geotechnical Engineering, Fluid Mechanics, Construction Technology",
           competitions="NASA Human Exploration Rover Challenge, Indian Concrete Institute Competitions, Smart City Challenges",
           certifications="AutoCAD Civil 3D, LEED Green Associate, Revit Structure Certification, Project Management Professional"),

    Degree(name="B.Tech Electrical",
           courses="Power Systems, Renewable Energy, Embedded Systems, Circuit Analysis, Electrical Machines",
           competitions="Tesla's Electric Mobility Challenge, IEEE Maker Faire, Shell Eco-Marathon, Smart Grid Innovation Challenge",
           certifications="Electrical Safety Certification, Power Systems Engineering, Certified Energy Manager"),

    Degree(name="MBA",
           courses="Marketing Management, Financial Accounting, Business Analytics, HR Management, Operations Research",
           competitions="Hult Prize, Google AdWords Challenge, Global Case Competition at Harvard, CFA Challenge",
           certifications="Google Digital Marketing, PMP Certification, CFA Level 1, Six Sigma Black Belt, Financial Risk Manager (FRM)"),

    Degree(name="BBA",
           courses="Financial Accounting, Business Strategy, Digital Marketing, Human Resource Management, Entrepreneurship",
           competitions="Harvard Business Review Case Study Challenge, IIM Ahmedabad Confluence, Hult Prize, Startup India Challenge",
           certifications="Certified Business Analyst, Google Digital Marketing, Advanced Excel Certification, SAP Business One"),

    Degree(name="B.Com",
           courses="Corporate Accounting, Financial Markets, Taxation, Business Law, Cost Accounting",
           competitions="CFA Research Challenge, ICAI Commerce Wizard, Finance Olympiad, CFA Investment Challenge",
           certifications="Chartered Financial Analyst (CFA), ACCA Certification, CPA (Certified Public Accountant), GST Practitioner Certification"),

    Degree(name="B.Sc Computer Science",
           courses="Python Programming, AI & ML, Cybersecurity, Game Development, Internet of Things",
           competitions="National Cyber Olympiad, AI & Robotics Challenge, Kaggle ML Competitions, DEF CON CTF",
           certifications="CompTIA Security+, Certified Ethical Hacker, AI & ML Specialization, Google TensorFlow Developer"),

    Degree(name="B.Sc Mathematics",
           courses="Linear Algebra, Real Analysis, Probability & Statistics, Numerical Methods, Computational Mathematics",
           competitions="Putnam Mathematical Competition, IMO (International Mathematics Olympiad), Data Science Hackathons",
           certifications="Data Science with Python, Machine Learning with R, Quantitative Finance Certification"),

    Degree(name="B.Sc Physics",
           courses="Quantum Mechanics, Electromagnetism, Astrophysics, Nanotechnology, Optical Physics",
           competitions="MIT Physics Challenge, International Physics Olympiad (IPhO), CERN Summer Student Program",
           certifications="Quantum Computing Certification, Optical Instrumentation Specialist, Nanotechnology Professional"),

    Degree(name="B.Sc Chemistry",
           courses="Organic Chemistry, Physical Chemistry, Industrial Chemistry, Polymer Science, Analytical Chemistry",
           competitions="International Chemistry Olympiad (IChO), RSC Chemistry Challenge, American Chemical Society (ACS) Exams",
           certifications="Industrial Chemical Safety, Environmental Chemistry Certification, Pharmaceutical Quality Assurance"),

    Degree(name="B.Sc Biotechnology",
           courses="Genetic Engineering, Molecular Biology, Biopharmaceuticals, Bioinformatics, Immunology",
           competitions="iGEM (International Genetically Engineered Machine), Biotechnology Hackathons, ISCB Student Challenge",
           certifications="Bioinformatics with Python, Genetic Engineering Certification, Clinical Research Associate"),

    Degree(name="B.Sc Agriculture",
           courses="Soil Science, Agronomy, Plant Pathology, Horticulture, Agricultural Economics",
           competitions="ICAR National Talent Search, AgriTech Startup Challenge, Smart Farming Competitions",
           certifications="Agribusiness Management Certification, Organic Farming Specialist, GIS in Agriculture"),

    Degree(name="B.Sc Nursing",
           courses="Anatomy & Physiology, Pharmacology, Medical-Surgical Nursing, Pediatric Nursing, Geriatric Care",
           competitions="Florence Nightingale Nursing Challenge, International Medical Olympiad, Global Healthcare Hackathon",
           certifications="Certified Nursing Assistant (CNA), Advanced Cardiac Life Support (ACLS), Infection Control Certification"),

    Degree(name="LLB",
           courses="Corporate Law, Criminal Law, Constitutional Law, Cyber Law, Intellectual Property Rights (IPR)",
           competitions="Moot Court Competitions, International Law Olympiad, Harvard Negotiation Challenge",
           certifications="Certified Corporate Lawyer, Intellectual Property Law Certification, Mediation & Arbitration Certification"),

    Degree(name="B.Ed",
           courses="Educational Psychology, Pedagogy, Curriculum Development, Special Education, EdTech",
           competitions="Teacher Innovation Challenge, National Teaching Awards, EdTech Hackathons",
           certifications="Certified Education Specialist, Google for Education Certification, Teaching with Technology Certification"),
    Degree(name="BA English Literature",
           courses="British Literature, American Literature, Postcolonial Studies, Creative Writing, Linguistics",
           competitions="Shakespeare Drama Fest, National Essay Writing, Scholastic Art & Writing Awards",
           certifications="TEFL/TESOL, Cambridge English Teaching, Content Writing Certification"),

    Degree(name="BA History",
           courses="Ancient Civilizations, Modern World History, Indian History, Archaeology, Political History",
           competitions="National History Bee, UNESCO Heritage Research Challenge",
           certifications="Archival Studies, Museum Curator Certification"),

    Degree(name="BA Psychology",
           courses="Cognitive Psychology, Clinical Psychology, Neuropsychology, Social Behavior",
           competitions="APA Research Challenge, Mind Games Olympiad",
           certifications="Certified Behavioral Analyst, Mental Health First Aid"),

    Degree(name="BA Economics",
           courses="Microeconomics, Macroeconomics, Econometrics, Development Economics",
           competitions="CFA Investment Research, World Bank Case Challenge",
           certifications="NSE Certification in Financial Markets, Bloomberg Market Concepts"),

    Degree(name="B.Des (Fashion Design)",
           courses="Textile Science, Fashion Illustration, Garment Construction, Sustainable Fashion",
           competitions="Lakmé Fashion Week GenNext, International Design Contest",
           certifications="Adobe Fashion Design Tools, Certified Fashion Stylist"),

    Degree(name="B.Arch (Architecture)",
           courses="Urban Planning, Sustainable Design, Architectural History, BIM (Building Information Modeling)",
           competitions="NASA Mars Habitat Challenge, ArchiTECH Hackathon",
           certifications="Autodesk Revit Certification, LEED Green Associate"),

    Degree(name="BFA (Fine Arts)",
           courses="Painting, Sculpture, Digital Art, Art History",
           competitions="St+Art India Competition, National Young Artists Award",
           certifications="Adobe Creative Suite Certification, Professional Artist Portfolio"),

    Degree(name="B.Pharm (Pharmacy)",
           courses="Pharmaceutical Chemistry, Pharmacology, Drug Formulation, Clinical Pharmacy",
           competitions="National Pharma Quiz, ISF College of Pharmacy Hackathon",
           certifications="Certified Pharmacy Technician, Drug Safety Certification"),

    Degree(name="BDS (Dental Surgery)",
           courses="Oral Pathology, Orthodontics, Periodontics, Dental Materials",
           competitions="IDA Dental Research Awards, National Dental Olympiad",
           certifications="Advanced Dental Implant Certification, Laser Dentistry Training"),

    Degree(name="BVSc (Veterinary Science)",
           courses="Animal Anatomy, Veterinary Surgery, Livestock Management, Wildlife Medicine",
           competitions="National Vet Quiz, International Animal Health Hackathon",
           certifications="Wildlife Rehabilitation Certification, Veterinary Ultrasound Training"),

    Degree(name="BAMS (Ayurvedic Medicine)",
           courses="Ayurvedic Pharmacology, Panchakarma, Herbal Medicine, Yoga Therapy",
           competitions="National Ayurveda Quiz, Ayurvedic Research Paper Contest",
           certifications="Certified Ayurvedic Practitioner, Yoga Instructor Certification"),

    Degree(name="BHMS (Homeopathy)",
           courses="Homeopathic Pharmacy, Materia Medica, Organon of Medicine",
           competitions="National Homeopathy Olympiad, CCRH Research Challenge",
           certifications="Certified Homeopath, Advanced Homeopathic Prescriber"),

    Degree(name="BPT (Physiotherapy)",
           courses="Exercise Therapy, Musculoskeletal Physiotherapy, Neuro Rehabilitation",
           competitions="National Physiotherapy Case Study Challenge, Sports PT Olympiad",
           certifications="Certified Sports Physiotherapist, Dry Needling Certification"),

    Degree(name="B.Optom (Optometry)",
           courses="Ocular Diseases, Contact Lens Practice, Binocular Vision",
           competitions="National Optometry Quiz, Vision Science Hackathon",
           certifications="Certified Optometrist, Low Vision Specialist"),

    Degree(name="B.Sc Microbiology",
           courses="Medical Microbiology, Industrial Microbiology, Immunology",
           competitions="ASM Agar Art Competition, National Microbe Hunt",
           certifications="Clinical Microbiology Certification, Biosafety Level Training"),

    Degree(name="B.Sc Environmental Science",
           courses="Climate Change, Waste Management, Biodiversity Conservation",
           competitions="UNEP Young Champions of the Earth, National Green Olympiad",
           certifications="LEED Green Associate, Environmental Impact Assessment Certification"),

    Degree(name="B.Sc Geology",
           courses="Mineralogy, Petroleum Geology, Remote Sensing, Hydrogeology",
           competitions="National GeoQuiz, ISRO Space Challenge",
           certifications="GIS Certification, Petroleum Geoscience Training"),

    Degree(name="B.Sc Food Technology",
           courses="Food Chemistry, Food Processing, Quality Assurance",
           competitions="National Food Innovation Challenge, Nestlé R&D Competitions",
           certifications="HACCP Certification, Food Safety Supervisor"),

    Degree(name="B.Sc Fashion Technology",
           courses="Apparel Production, Fashion Merchandising, Sustainable Textiles",
           competitions="National Fashion Tech Hackathon, Texfusion Design Contest",
           certifications="Garment Manufacturing Certification, CAD for Fashion Design"),

    Degree(name="B.Sc Animation & VFX",
           courses="3D Modeling, Motion Graphics, Visual Effects, Game Design",
           competitions="Annecy Animation Festival, Adobe Design Achievement Awards",
           certifications="Autodesk Maya Certified, Unity Developer Certification")
]


# Bulk Insert
session.bulk_save_objects(degrees)
session.commit()
session.close()

print("✅ Data inserted successfully!")

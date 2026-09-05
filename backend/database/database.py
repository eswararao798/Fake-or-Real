import os
import datetime
import json
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./phishnet.db')

engine = create_engine(
    DATABASE_URL,
    connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = 'scan_history'

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False, index=True)
    prediction = Column(String(50), nullable=False)
    phishing_probability = Column(Float, nullable=False)
    legitimate_probability = Column(Float, nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(50), nullable=False)
    recommendation = Column(Text, nullable=False)
    features_json = Column(Text, nullable=True)
    explanation_json = Column(Text, nullable=True)
    security_review_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'prediction': self.prediction,
            'phishing_probability': self.phishing_probability,
            'legitimate_probability': self.legitimate_probability,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'recommendation': self.recommendation,
            'features': json.loads(self.features_json) if self.features_json else {},
            'explanation': json.loads(self.explanation_json) if self.explanation_json else [],
            'security_review': json.loads(self.security_review_json) if self.security_review_json else {},
            'timestamp': self.created_at.isoformat() if self.created_at else None
        }

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

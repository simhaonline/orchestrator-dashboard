from app import db
from sqlalchemy.orm import relationship


class User(db.Model):
    __tablename__ = 'users'
    sub = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(128), nullable=True)
    username = db.Column(db.String(64), nullable=False)
    given_name = db.Column(db.String(64), nullable=True)
    family_name = db.Column(db.String(64), nullable=True)
    email = db.Column(db.String(64), nullable=False)
    organisation_name = db.Column(db.String(64), nullable=True)
    picture = db.Column(db.String(128), nullable=True)
    role = db.Column(db.String(32), nullable=False, default='user')
    sshkey = db.Column(db.Text, nullable=True)
    active = db.Column(db.Integer, nullable=False, default='1')
    deployments = relationship("Deployment", back_populates="user")

    def __repr__(self):
        return '<User {}>'.format(self.sub)


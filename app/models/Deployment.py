from app import db
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship


class Deployment(db.Model):
    __tablename__ = 'deployments'
    uuid = db.Column(db.String(36), primary_key=True)
    creation_time = db.Column(db.DateTime, nullable=True)
    update_time = db.Column(db.DateTime, nullable=True)
    physicalId = db.Column(db.String(36), nullable=True)
    description = db.Column(db.String(256), nullable=True)
    status = db.Column(db.String(128), nullable=True)
    status_reason = db.Column(db.Text, nullable=True)
    outputs = db.Column(db.Text, nullable=True)
    task = db.Column(db.String(64), nullable=True)
    links = db.Column(db.Text, nullable=True)
    provider_name = db.Column(db.String(128), nullable=True)
    endpoint = db.Column(db.String(256), nullable=True)
    template = db.Column(db.Text, nullable=True)
    inputs = db.Column(db.Text, nullable=True)
    stinputs = db.Column(db.Text, nullable=True)
    params = db.Column(db.Text, nullable=True)
    locked = db.Column(db.Integer, nullable=True, default=0)
    feedback_required = db.Column(db.Integer, nullable=True, default=1)
    keep_last_attempt = db.Column(db.Integer, nullable=True, default=0)
    remote = db.Column(db.Integer, nullable=True, default='0')
    issuer = db.Column(db.String(256), nullable=True)
    storage_encryption = db.Column(db.Integer, nullable=True, default=0)
    vault_secret_uuid = db.Column(db.String(36), nullable=True)
    vault_secret_key = db.Column(db.String(36), nullable=True)
    elastic = db.Column(db.Integer, nullable=True, default=0)
    updatable = db.Column(db.Integer, nullable=True, default=0)
    sub = db.Column(db.String(36), ForeignKey('users.sub'))
    user = relationship("User", back_populates="deployments")

    def __repr__(self):
        return '<Deployment {}>'.format(self.uuid)

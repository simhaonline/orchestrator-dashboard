from app import db
from sqlalchemy.orm import relationship

class UserMixin(object):

    @classmethod
    def get_user(cls, subject):
        return cls.query.get(subject)

    @classmethod
    def get_users(cls):
        users = cls.query.order_by(User.family_name.desc(), User.given_name.desc()).all()
        return users

    @classmethod
    def update_user(cls, subject, data):
        cls.query.filter_by(sub=subject).update(data)
        db.session.commit()

    @classmethod
    def get_ssh_pub_key(self, subject):
        user = self.get_user(subject)
        return user.sshkey

    @classmethod
    def delete_ssh_key(self, subject):
        self.query.get(subject).sshkey = None
        db.session.commit()



class User(UserMixin, db.Model):
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


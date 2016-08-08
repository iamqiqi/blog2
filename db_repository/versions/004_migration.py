from sqlalchemy import *
from migrate import *


from migrate.changeset import schema
pre_meta = MetaData()
post_meta = MetaData()
user = Table('user', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('nickname', String(length=64), nullable=False),
    Column('email', String(length=120), nullable=False),
    Column('password', String(length=255), nullable=False),
)

post = Table('post', post_meta,
    Column('id', Integer, primary_key=True, nullable=False),
    Column('body', String(length=140), nullable=False),
    Column('timestamp', DateTime, nullable=False),
    Column('user_id', Integer, nullable=False)
)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['user'].columns['password'].create()
    post_meta.tables['user'].columns['nickname'].alter(nullable=False)
    post_meta.tables['user'].columns['email'].alter(nullable=False)
    post_meta.tables['post'].columns['body'].alter(nullable=False)
    post_meta.tables['post'].columns['timestamp'].alter(nullable=False)
    post_meta.tables['post'].columns['user_id'].alter(nullable=False)

def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    post_meta.tables['user'].columns['password'].drop()
    post_meta.tables['user'].columns['nickname'].alter(nullable=True)
    post_meta.tables['user'].columns['email'].alter(nullable=True)
    post_meta.tables['post'].columns['body'].alter(nullable=True)
    post_meta.tables['post'].columns['timestamp'].alter(nullable=True)
    post_meta.tables['post'].columns['user_id'].alter(nullable=True)

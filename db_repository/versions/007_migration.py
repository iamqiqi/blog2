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
    Column('about_me', String(length=140)),
    Column('last_seen', DateTime),
)

last_seen_idx = Index("last_seen_idx", user.c.last_seen)


def upgrade(migrate_engine):
    # Upgrade operations go here. Don't create your own engine; bind
    # migrate_engine to your metadata
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    # post_meta.tables['user'].columns['id'].alter(index=True)
    # post_meta.tables['user'].columns['last_seen'].alter(index=True)
    last_seen_idx.create()


def downgrade(migrate_engine):
    # Operations to reverse the above upgrade go here.
    pre_meta.bind = migrate_engine
    post_meta.bind = migrate_engine
    # post_meta.tables['user'].columns['id'].alter(index=False)
    # post_meta.tables['user'].columns['last_seen'].alter(index=False)
    last_seen_idx.drop()
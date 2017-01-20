"""empty message

Revision ID: 3079cce1852
Revises: 51636ccaa63
Create Date: 2017-01-17 15:45:18.621101

"""

# revision identifiers, used by Alembic.
revision = '3079cce1852'
down_revision = '51636ccaa63'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('posts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('author_id', sa.Integer(), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('body', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['author_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_posts_timestamp', 'posts', ['timestamp'], unique=False)
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('ix_posts_timestamp', 'posts')
    op.drop_table('posts')
    ### end Alembic commands ###

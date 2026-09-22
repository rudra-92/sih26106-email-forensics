"""initial_schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-09-22 14:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0001_initial_schema'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.String(length=50), nullable=False),
        sa.Column('updated_at', sa.String(length=50), nullable=False),
        sa.Column('last_login_at', sa.String(length=50), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # Cases table
    op.create_table(
        'cases',
        sa.Column('case_id', sa.String(length=100), nullable=False),
        sa.Column('owner_user_id', sa.String(length=36), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.String(length=50), nullable=False),
        sa.Column('updated_at', sa.String(length=50), nullable=False),
        sa.Column('original_filename', sa.String(length=255), nullable=True),
        sa.Column('file_sha256', sa.String(length=64), nullable=True),
        sa.Column('file_path', sa.String(length=1024), nullable=True),
        sa.Column('file_size_bytes', sa.Integer(), nullable=True),
        sa.Column('analysis_status', sa.String(length=50), nullable=False),
        sa.Column('threat_label', sa.String(length=100), nullable=True),
        sa.Column('threat_confidence', sa.Float(), nullable=True),
        sa.Column('threat_confidence_metric', sa.String(length=100), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('evidence_count', sa.Integer(), nullable=False),
        sa.Column('entity_count', sa.Integer(), nullable=False),
        sa.Column('relationship_count', sa.Integer(), nullable=False),
        sa.Column('hypothesis_count', sa.Integer(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['owner_user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('case_id'),
    )
    op.create_index(op.f('ix_cases_analysis_status'), 'cases', ['analysis_status'], unique=False)
    op.create_index(op.f('ix_cases_created_at'), 'cases', ['created_at'], unique=False)
    op.create_index(op.f('ix_cases_owner_user_id'), 'cases', ['owner_user_id'], unique=False)

    # Case analysis data table
    op.create_table(
        'case_analysis_data',
        sa.Column('case_id', sa.String(length=100), nullable=False),
        sa.Column('origin_json', sa.Text(), nullable=False),
        sa.Column('summary_json', sa.Text(), nullable=False),
        sa.Column('full_case_json', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.case_id']),
        sa.PrimaryKeyConstraint('case_id'),
    )

    # Case entities table
    op.create_table(
        'case_entities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.String(length=100), nullable=False),
        sa.Column('entity_id', sa.String(length=100), nullable=False),
        sa.Column('entity_type', sa.String(length=100), nullable=False),
        sa.Column('canonical_value', sa.Text(), nullable=False),
        sa.Column('source_modules_json', sa.Text(), nullable=True),
        sa.Column('first_observed_timestamp', sa.String(length=50), nullable=True),
        sa.Column('attributes_json', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.case_id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_case_entities_case_id'), 'case_entities', ['case_id'], unique=False)

    # Case evidence table
    op.create_table(
        'case_evidence',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.String(length=100), nullable=False),
        sa.Column('evidence_id', sa.String(length=100), nullable=False),
        sa.Column('source_module', sa.String(length=100), nullable=False),
        sa.Column('rule_id', sa.String(length=100), nullable=False),
        sa.Column('trust_state', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('entity_ids_json', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.String(length=50), nullable=True),
        sa.Column('provenance_json', sa.Text(), nullable=True),
        sa.Column('supporting_fields_json', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.case_id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_case_evidence_case_id'), 'case_evidence', ['case_id'], unique=False)

    # Case hypotheses table
    op.create_table(
        'case_hypotheses',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.String(length=100), nullable=False),
        sa.Column('hypothesis_id', sa.String(length=100), nullable=False),
        sa.Column('hypothesis_type', sa.String(length=100), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('confidence_metric', sa.String(length=100), nullable=False),
        sa.Column('supporting_evidence_ids_json', sa.Text(), nullable=True),
        sa.Column('contradicting_evidence_ids_json', sa.Text(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('provenance_json', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.case_id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_case_hypotheses_case_id'), 'case_hypotheses', ['case_id'], unique=False)

    # Case relationships table
    op.create_table(
        'case_relationships',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.String(length=100), nullable=False),
        sa.Column('relationship_id', sa.String(length=100), nullable=False),
        sa.Column('source_entity_id', sa.String(length=100), nullable=False),
        sa.Column('target_entity_id', sa.String(length=100), nullable=False),
        sa.Column('relationship_type', sa.String(length=100), nullable=False),
        sa.Column('evidence_ids_json', sa.Text(), nullable=True),
        sa.Column('source_modules_json', sa.Text(), nullable=True),
        sa.Column('trust_state', sa.String(length=50), nullable=False),
        sa.Column('timestamp', sa.String(length=50), nullable=True),
        sa.Column('provenance_json', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.case_id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_case_relationships_case_id'), 'case_relationships', ['case_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_case_relationships_case_id'), table_name='case_relationships')
    op.drop_table('case_relationships')
    op.drop_index(op.f('ix_case_hypotheses_case_id'), table_name='case_hypotheses')
    op.drop_table('case_hypotheses')
    op.drop_index(op.f('ix_case_evidence_case_id'), table_name='case_evidence')
    op.drop_table('case_evidence')
    op.drop_index(op.f('ix_case_entities_case_id'), table_name='case_entities')
    op.drop_table('case_entities')
    op.drop_table('case_analysis_data')
    op.drop_index(op.f('ix_cases_owner_user_id'), table_name='cases')
    op.drop_index(op.f('ix_cases_created_at'), table_name='cases')
    op.drop_index(op.f('ix_cases_analysis_status'), table_name='cases')
    op.drop_table('cases')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')

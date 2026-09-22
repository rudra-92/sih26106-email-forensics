"""Backend schemas package."""

from .cases import (
    AnalysisTriggerResponse,
    CaseCreateRequest,
    CaseListResponse,
    CaseResponse,
    FileUploadResponse,
)
from .analysis import (
    EntityItem,
    EntityListResponse,
    EvidenceItem,
    EvidenceListResponse,
    HypothesisItem,
    HypothesisListResponse,
    OriginResponse,
    RelationshipItem,
    RelationshipListResponse,
    SummaryResponse,
)

from .auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    UserListResponse,
    UserStatusUpdateRequest,
    UserSummaryResponse,
)

__all__ = [
    "CaseCreateRequest",
    "CaseResponse",
    "CaseListResponse",
    "FileUploadResponse",
    "AnalysisTriggerResponse",
    "EvidenceItem",
    "EvidenceListResponse",
    "EntityItem",
    "EntityListResponse",
    "RelationshipItem",
    "RelationshipListResponse",
    "HypothesisItem",
    "HypothesisListResponse",
    "OriginResponse",
    "SummaryResponse",
    "RegisterRequest",
    "RegisterResponse",
    "LoginRequest",
    "LoginResponse",
    "UserSummaryResponse",
    "UserStatusUpdateRequest",
    "UserListResponse",
]

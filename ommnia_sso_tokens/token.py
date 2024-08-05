from typing import Annotated, List, Literal, Optional, Union
from pydantic import BaseModel, Field

from ommnia_permission_tree.permission_tree import PermissionTreeData


class RestoreSessionToken(BaseModel):
    kind: Literal["RESTORE_SESSION"] = "RESTORE_SESSION"
    session_uid: int


class LoginSessionToken(BaseModel):
    kind: Literal["LOGIN_SESSION"] = "LOGIN_SESSION"
    session_uid: int


class BearerToken(BaseModel):
    kind: Literal["BEARER"] = "BEARER"
    user_uid: int
    permissions: PermissionTreeData


class LoginSessionCreationToken(BaseModel):
    kind: Literal["LOGIN_SESSION_CREATION"] = "LOGIN_SESSION_CREATION"
    app_name: str
    optional_permissions: List[str]
    required_permissions: List[str]
    target_app_name: Optional[str] = None  # If not specified, it is meant for the initiating app.
    redirect_url: str


type TokenValue = Annotated[
    Union[
        RestoreSessionToken,
        LoginSessionToken,
        BearerToken,
        LoginSessionCreationToken,
    ],
    Field(discriminator="kind"),
]


class Token(BaseModel):
    value: TokenValue


from abc import ABC
import asyncio
from typing import ClassVar, Optional
import jwt

from ommnia_sso_tokens.token import Token, TokenValue


class _TokenVerifier:
    ALGORITHM: ClassVar[str] = "RS256"

    def verify(
        self,
        token: str,
        public_key: Optional[str] = None,
        verify: bool = True,
    ) -> TokenValue:
        return Token.model_validate(
            jwt.decode(
                token,
                public_key if public_key is not None else "",
                algorithms=[self.ALGORITHM],
                options={"verify_signature": verify},
            )
        ).value

    async def averify(
        self,
        token: str,
        public_key: Optional[str] = None,
        verify: bool = True,
    ) -> TokenValue:
        return await asyncio.get_running_loop().run_in_executor(
            None, self.verify, token, public_key, verify
        )


class TokenVerifier(ABC):
    _instance: Optional[_TokenVerifier] = None

    def __new__(cls) -> _TokenVerifier:
        if cls._instance is None:
            cls._instance = _TokenVerifier()

        return cls._instance

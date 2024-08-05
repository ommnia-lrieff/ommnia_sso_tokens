from abc import ABC
import asyncio
from typing import Any, ClassVar, Optional
import jwt

from ommnia_sso_tokens.token import Token


class _TokenVerifier:
    _ALGORITHM: ClassVar[str] = "RS256"

    async def verify(
        self,
        token: str,
        public_key: Optional[str] = None,
        verify: bool = True,
    ) -> Token:
        def inner_verify() -> Any:
            return jwt.decode(
                token,
                public_key if public_key is not None else "",
                algorithms=[self._ALGORITHM],
                options={
                    "verify_signature": verify,
                },
            )

        return Token.model_validate(
            await asyncio.get_running_loop().run_in_executor(None, inner_verify)
        )


class TokenVerifier(ABC):
    _instance: Optional[_TokenVerifier] = None

    def __new__(cls) -> _TokenVerifier:
        if cls._instance is None:
            cls._instance = _TokenVerifier()

        return cls._instance

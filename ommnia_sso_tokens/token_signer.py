from typing import ClassVar, Optional
from abc import ABC
import asyncio
import jwt

from ommnia_sso_tokens.token import Token, TokenValue


class _TokenSigner:
    _ALGORITHM: ClassVar[str] = "RS256"

    async def sign(self, token_value: TokenValue, private_key: str) -> str:
        def inner_sign() -> str:
            return jwt.encode(
                Token(value=token_value).model_dump(),
                private_key,
                algorithm=self._ALGORITHM,
            )

        return await asyncio.get_running_loop().run_in_executor(None, inner_sign)


class TokenSigner(ABC):
    _instance: ClassVar[Optional[_TokenSigner]] = None

    def __new__(cls) -> _TokenSigner:
        if cls._instance is None:
            cls._instance = _TokenSigner()

        return cls._instance

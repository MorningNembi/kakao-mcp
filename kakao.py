from __future__ import annotations

import time
from typing import Any

import httpx
from pydantic import AnyHttpUrl, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from fastmcp.server.auth import TokenVerifier
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.utilities.auth import parse_scopes
from fastmcp.utilities.logging import get_logger
from fastmcp.utilities.types import NotSet, NotSetT
import logging

logger = get_logger(__name__)

class KakaoProviderSettings(BaseSettings):
    """Settings for Kakao OAuth provider."""

    model_config = SettingsConfigDict(
        env_prefix="FASTMCP_SERVER_AUTH_KAKAO_",
        env_file=".env",
        extra="ignore",
    )

    client_id: str | None = None
    client_secret: SecretStr | None = None
    base_url: AnyHttpUrl | str | None = None
    redirect_path: str | None = None
    required_scopes: list[str] | None = None
    timeout_seconds: int | None = None
    allowed_client_redirect_uris: list[str] | None = None

    @field_validator("required_scopes", mode="before")
    @classmethod
    def _parse_scopes(cls, v):
        return parse_scopes(v)


class KakaoTokenVerifier(TokenVerifier):
    """Token verifier for Kakao OAuth tokens using OpenID Connect.

    카카오의 OpenID Connect 사용자 정보 API를 호출하여 검증해야 합니다.
    이 검증기는 카카오 OIDC API 사양에 따라 토큰 검증과 사용자 정보 추출을 처리합니다.
    
    주요 특징:
    - 카카오 OIDC 사용자 정보 API (/v1/oidc/userinfo)를 사용한 토큰 검증
    - OIDC 표준 클레임 (sub, iss, email, nickname, picture 등) 추출
    - OIDC 프로토콜을 통한 OpenID 스코프 검증
    - PKCE (Proof Key for Code Exchange) S256 메서드 지원
    """

    def __init__(
        self,
        *,
        required_scopes: list[str] | None = None,
        timeout_seconds: int = 10,
    ):
        """카카오 토큰 검증기를 초기화합니다.

        Args:
            required_scopes: 필수 OAuth 스코프. 카카오 OIDC는 'openid'가 필수입니다.
            timeout_seconds: API 호출을 위한 HTTP 요청 타임아웃 (기본값: 10초)
        """
        super().__init__(required_scopes=required_scopes)
        self.timeout_seconds = timeout_seconds

    async def verify_token(self, token: str) -> AccessToken | None:
        """카카오 OAuth 토큰을 검증하고 사용자 정보를 추출합니다.
        
        이 메서드는 카카오 OpenID Connect 사용자 정보 API를 호출하여 토큰을 검증하고,
        성공할 경우 사용자 클레임이 포함된 AccessToken을 반환합니다.
        
        Args:
            token: 검증할 액세스 토큰
            
        Returns:
            유효한 경우 사용자 클레임이 포함된 AccessToken, 무효한 경우 None
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                # 카카오 OIDC 사용자 정보 API 호출
                response = await client.get(
                    "https://kapi.kakao.com/v1/oidc/userinfo",
                    headers={
                        "Authorization": f"Bearer {token}",
                    },
                )

                # HTTP 상태 코드 확인
                if response.status_code != 200:
                    logger.debug(
                        "Kakao user info API returned HTTP %d for token verification",
                        response.status_code,
                    )
                    return None

                # JSON 응답 파싱
                try:
                    api_response = response.json()
                except Exception as e:
                    logger.debug("Failed to parse Kakao API response as JSON: %s", e)
                    return None

                # 필수 사용자 ID 검증 (OIDC의 sub 클레임)
                user_id = api_response.get("sub")
                if not user_id:
                    logger.debug("Kakao OIDC userinfo missing required 'sub' field")
                    return None

                # 스코프 검증
                # OIDC 프로토콜 사용 시 openid 스코프는 자동으로 검증됨
                validated_scopes = self.required_scopes or ["openid"]

                if self.required_scopes:
                    if "openid" in self.required_scopes:
                        logger.debug("Kakao openid scope validated via successful OIDC userinfo access")
                    else:
                        logger.warning(
                            "Kakao OIDC requires openid scope - please include it in required_scopes"
                        )

                # OIDC 표준 클레임으로부터 사용자 클레임 구성
                # OIDC userinfo 응답은 표준 클레임 + 카카오 커스텀 클레임 포함
                user_claims = {
                    "sub": user_id,
                    "iss": api_response.get("iss", "kakao"),
                }

                # OIDC 표준 클레임 및 카카오 제공 클레임
                profile_fields = {
                    "email": api_response.get("email"),
                    "nickname": api_response.get("nickname"),
                    "picture": api_response.get("picture"),
                    "auth_time": api_response.get("auth_time"),
                    "nonce": api_response.get("nonce"),
                }

                # 값이 있는 필드만 클레임에 추가
                for field, value in profile_fields.items():
                    if value is not None and value != "":
                        user_claims[field] = value

                # 원본 OIDC 응답 데이터 보존
                user_claims["oidc_userinfo"] = api_response

                # AccessToken 생성
                # Note: 카카오는 토큰 검증 API에서 만료 정보를 제공하지 않음
                # 토큰 교환 시점에서 expires_in 정보를 별도로 추적해야 함
                access_token = AccessToken(
                    token=token,
                    client_id="kakao-verified",  # 카카오 검증된 토큰 식별자
                    scopes=validated_scopes,
                    expires_at=None,  # 토큰 교환 시 설정됨
                    claims=user_claims,
                )

                logger.debug(
                    "Kakao token verified successfully for user %s (nickname: %s)",
                    user_id,
                    api_response.get("nickname", "unknown"),
                )
                return access_token

        except httpx.TimeoutException:
            logger.debug(
                "Kakao token verification timed out after %d seconds",
                self.timeout_seconds,
            )
            return None
        except httpx.RequestError as e:
            logger.debug("Network error during Kakao token verification: %s", e)
            return None
        except Exception as e:
            logger.error(
                "Unexpected error during Kakao token verification: %s",
                e,
                exc_info=True,
            )
            return None


class KakaoProvider(OAuthProxy):
    """FastMCP용 카카오 OAuth 프로바이더.

    이 프로바이더는 모든 FastMCP 서버에 카카오 OAuth 보호 기능을
    쉽게 추가할 수 있게 합니다. 카카오 OAuth 앱 자격 증명과 기본 URL만
    제공하면 바로 사용할 수 있습니다.

    주요 기능:
    - 카카오에 대한 OAuth Proxy (OIDC 프로토콜 지원)
    - PKCE를 활용한 보안 강화된 인증 흐름
    - 카카오 사용자 정보 API를 통한 자동 토큰 검증
    - 카카오 프로필 API로부터 사용자 정보 추출
    - PKCE, DCR 인터페이스, 메타데이터 제공 등 카카오 로그인이 MCP 표준을 준수하도록 기능 제공

    사용 예시:
        ```python
        from fastmcp import FastMCP
        from fastmcp.server.auth.providers.kakao import KakaoProvider

        auth = KakaoProvider(
            client_id="your_kakao_client_id",
            client_secret="your_kakao_client_secret",
            base_url="https://my-server.com"
        )

        mcp = FastMCP("My App", auth=auth)
        ```
    """

    def __init__(
        self,
        *,
        client_id: str | NotSetT = NotSet,
        client_secret: str | NotSetT = NotSet,
        base_url: AnyHttpUrl | str | NotSetT = NotSet,
        redirect_path: str | NotSetT = NotSet,
        required_scopes: list[str] | NotSetT = NotSet,
        timeout_seconds: int | NotSetT = NotSet,
        allowed_client_redirect_uris: list[str] | NotSetT = NotSet,
        forward_pkce: bool = True,
    ):
        """카카오 OAuth 프로바이더를 초기화합니다.

        Args:
            client_id: 카카오 개발자센터에서 발급받은 OAuth 클라이언트 ID.
            client_secret: 카카오 개발자센터에서 발급받은 OAuth 클라이언트 시크릿.
            base_url: FastMCP 서버의 공개 URL (OAuth 콜백용).
            redirect_path: OAuth 리다이렉트 경로 (기본값: "/auth/callback").
            required_scopes: 필수 카카오 스코프. OIDC 사용 시 'openid'가 필수입니다.
            timeout_seconds: 카카오 API 호출 타임아웃 (기본값: 10초).
            allowed_client_redirect_uris: MCP 클라이언트용 허용된 리다이렉트 URI 패턴.
                None인 경우 모든 URI 허용, 빈 목록인 경우 URI 허용 안함.
            forward_pkce: PKCE 전달 여부 (기본값: True). 카카오 OIDC API는 PKCE를 지원합니다.
        """

        settings = KakaoProviderSettings.model_validate(
            {
                k: v
                for k, v in {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "base_url": base_url,
                    "redirect_path": redirect_path,
                    "required_scopes": required_scopes,
                    "timeout_seconds": timeout_seconds,
                    "allowed_client_redirect_uris": allowed_client_redirect_uris,
                }.items()
                if v is not NotSet
            }
        )

        # 기본값 적용
        redirect_path_final = settings.redirect_path or "/auth/callback"
        timeout_seconds_final = settings.timeout_seconds or 10
        required_scopes_final = settings.required_scopes or ["openid"]

        allowed_client_redirect_uris_final = settings.allowed_client_redirect_uris

        # 카카오 토큰 검증기 생성
        token_verifier = KakaoTokenVerifier(
            required_scopes=required_scopes_final,
            timeout_seconds=timeout_seconds_final,
        )

        # SecretStr에서 문자열 추출
        client_secret_str = (
            settings.client_secret.get_secret_value() if settings.client_secret else ""
        )

        # 카카오 엔드포인트로 OAuth Proxy 초기화
        super().__init__(
            upstream_authorization_endpoint="https://kauth.kakao.com/oauth/authorize",
            upstream_token_endpoint="https://kauth.kakao.com/oauth/token",
            upstream_client_id=settings.client_id,
            upstream_client_secret=client_secret_str,
            token_verifier=token_verifier,
            base_url=settings.base_url,
            redirect_path=redirect_path_final,
            issuer_url=settings.base_url,  # We act as the issuer for client registration
            allowed_client_redirect_uris=allowed_client_redirect_uris_final,
            forward_pkce=forward_pkce,  # Enable PKCE forwarding to Kakao OIDC
            token_endpoint_auth_method="client_secret_post",
        )

        logger.info(
            "Initialized Kakao OAuth provider for client %s with scopes: %s (PKCE: %s)",
            settings.client_id,
            required_scopes_final,
            "enabled" if forward_pkce else "disabled",
        )
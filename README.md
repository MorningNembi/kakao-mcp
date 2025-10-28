# Kakao MCP Server

카카오 OAuth 인증을 통해 카카오톡 메시지 발송 및 친구 목록 조회 기능을 제공하는 FastMCP 기반 MCP 서버입니다.  
MCP 서버를 연결하면 자동으로 카카오 로그인 페이지로 리다이렉트 됩니다. 로그인과 권한 부여를 통해 에이전트에서 카카오톡 메세지를 전달 할 수 있습니다.  

<img width="400" height="500" alt="image" src="https://github.com/user-attachments/assets/fda081d5-e378-48bc-bbee-c443f7599365" />
<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/cf3114cf-1587-454c-bd22-76ddaca945e3" />


## 🎯 Tool List
- `send_message_to_me`: 나와의 채팅방에 메세지 전송
- `send_message`: UUID로 특정 친구에게 메시지 전송
- `search_kakao_friends`: 친구 이름, UUID, 프로필 닉네임 반환

## 🛠️ 기술 스택

- FastMCP, Starlette, httpx
- 카카오 OAuth 2.0 + OpenID Connect

## 📦 설치

```bash
# 의존성 설치
pip install requirements.txt

# .env 파일 생성
KAKAO_CLIENT_ID=your_rest_api_key
KAKAO_CLIENT_SECRET=your_client_secret
BASE_URL=https://your-ngrok-url
# 클라이언트에서 네이버 HCX-005 모델 사용
CLOVA_API_KEY=your_clova_studio_api_key
```

## 🚀 실행
**FastMCP 서버 실행**
```bash
python remote_auth_server.py
```
**FastMCP 클라이언트 실행**
```bash
python fastmcp_client.py
```

ngrok 설정 (동시에 다른 터미널에서):
```bash
ngrok http 8000
```

---

## 📋 카카오 Developers 설정

### 1. 앱 생성 및 기본 설정
- https://developers.kakao.com/ 접속
- "내 애플리케이션" → "애플리케이션 추가" → 앱 생성
- "앱 설정" → "기본 정보"에서 **REST API 키** 복사 (= KAKAO_CLIENT_ID)
- 비즈니스 설정: 개인 개발자는 https://business.kakao.com/cold-start/check-business-number에서 비즈앱 설정

### 2. 카카오 로그인 활성화
- "카카오 로그인" → "활성화 설정" → "활성화"
- OpenID Connect 활성화

### 3. Redirect URI 등록
- "카카오 로그인" → "설정" → "Redirect URI" → 다음 2개 추가:
```
https://your-ngrok-url/auth/callback
https://your-ngrok-url/friends/callback
```

### 4. Client Secret 생성
- "보안" 탭 → "Client Secret" → "생성"
- 발급받은 키를 KAKAO_CLIENT_SECRET에 저장

### 5. 동의항목 설정
- "카카오 로그인" → "동의항목"
- 필수: `openid`, `profile`
- 선택: `talk_message` (나에게 보내기), `friends` (친구 목록)
- talk_message, friends는 "이용중 동의" 선택

### 6. 테스터 추가 (필수)
- "앱 설정" → "팀 관리" → "테스터 초대"
- 본인 카카오 계정 이메일로 초대장 수락
- 메시지를 받을 친구도 테스터 추가 필요 (친구가 REST API 테스트에서 권한 설정)

### 7. (선택) 앱 심사
- "배포" → "앱 심사 신청" → 검수 승인 후 모든 사용자 이용 가능

---

## 💡 사용 방법

### 1. MCP 클라이언트 설정

FastMCP 서버를 실행한 후, Claude Desktop 등 MCP 클라이언트의 설정 파일에 다음 추가:

```json
{
  "mcpServers": {
    "kakao-remote-mcp": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://your-ngrok-url/mcp"]
    }
  }
}
```

### 2. 기본 흐름

**친구에게 메시지 보내기:**
1. `search_kakao_friends(limit=10)` → 친구 UUID 획득
2. `send_message(uuid="...", message="내용")` → 메시지 발송
3. 수신자가 링크 클릭 → `/message` 엔드포인트에서 전체 메시지 표시

**나에게 메시지 보내기:**
- `send_message_to_me(message="내용")` → 바로 발송

---

## 🏗️ 기술 구조

### kakao.py

**KakaoTokenVerifier**: OIDC 표준에 따른 JWT 토큰 검증
- 카카오 공개키 서명 검증
- 클레임 유효성 확인

**KakaoProvider**: OAuthProxy 상속, 카카오 OAuth 구현
- PKCE (Proof Key for Code Exchange) 지원
- OpenID Connect 프로토콜 준수
- 토큰 저장/갱신 관리
- 사용자 정보 추출

### remote_auth_server.py

**MCP 서버** (FastMCP 기반)
- 3개 도구: `send_message_to_me`, `send_message`, `search_kakao_friends`
- 커스텀 엔드포인트:
  - `GET /message`: 메시지를 HTML로 표시 (모바일/데스크톱 반응형)
  - `GET /friends/callback`: OAuth 콜백 처리 → friends 스코프 토큰 자동 저장

### fastmcp_client.py

**FastMCP OAuth 지원 클라이언트**
- OAuth가 적용된 fastmcp 서버에 호환되는 fastmcp 클라이언트
- 네이버의 `HCX-005` 모델 활용


---

## ⚙️ 주요 특징

✅ **자동 동의 처리**: friends 권한 없으면 브라우저 자동 띄우기  
✅ **장문 메시지**: 200자 이상도 링크로 웹 표시  
✅ **반응형 HTML**: 모바일/데스크톱 모두 최적화  
✅ **환경변수 토큰 관리**: 동의 후 토큰 자동 저장/사용  
✅ **OIDC 준수**: 카카오 OAuth 표준 구현


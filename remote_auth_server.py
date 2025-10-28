import os
import re
import uuid
import httpx
from datetime import datetime
from fastmcp import FastMCP
from kakao import KakaoProvider
from dotenv import load_dotenv

load_dotenv()

KAKAO_CLIENT_ID = os.getenv("KAKAO_CLIENT_ID")
KAKAO_CLIENT_SECRET = os.getenv("KAKAO_CLIENT_SECRET")
BASE_URL = os.getenv("BASE_URL")

# 카카오 OAuth Provider 초기화
auth = KakaoProvider(
    client_id=KAKAO_CLIENT_ID,              
    client_secret=KAKAO_CLIENT_SECRET,      
    base_url=BASE_URL,
)

mcp = FastMCP(name="Kakao Remote MCP", auth=auth) # Naver OAuth 인증 적용

# 현재 시간 도구 정의
@mcp.tool(
    name="get_current_time",
    description="현재 시간을 반환하는 도구입니다. 한국 시간(KST, UTC+9) 기준으로 현재 날짜와 시간을 제공합니다. 사용자가 최신의 내용물을 원할 때 반드시 활용합니다."
)
# openAI API는 빈 properties를 허용하지 않으므로 더미 파라미터 설정
async def get_current_time(format: str = "default") -> dict:
    """현재 시간을 조회합니다.
    Args:
        format (str): 사용하지 않음 (호환성을 위한 더미 파라미터)
    
    Returns:
        {
            "datetime": str,  # ISO 8601 형식 (YYYY-MM-DDTHH:MM:SS)
            "date": str,  # 현재 날짜 (YYYY-MM-DD)
            "time": str,  # 현재 시간 (HH:MM:SS)
            "weekday": str,  # 요일 (한글)
            "timestamp": int  # Unix timestamp
        }
    """
    import pytz
    
    # 한국 시간대 설정
    kst = pytz.timezone('Asia/Seoul')
    now = datetime.now(kst)
    
    weekdays = ['월요일', '화요일', '수요일', '목요일', '금요일', '토요일', '일요일']
    
    return {
        "datetime": now.strftime("%Y-%m-%dT%H:%M:%S"),
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "weekday": weekdays[now.weekday()],
        "timestamp": int(now.timestamp())
    }

@mcp.tool(
    name="send_message_to_me",
    description="카카오톡으로 **나에게** 텍스트 메시지를 발송하는 도구입니다."
)
async def send_message_to_me(message: str) -> dict:
    from fastmcp.server.dependencies import get_access_token
    from urllib.parse import quote
    import httpx
    import json
    
    try:
        token = get_access_token()
        access_token = token.token
        
        url = "https://kapi.kakao.com/v2/api/talk/memo/default/send"
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8"
        }

        # 메시지를 URL 인코딩
        encoded_message = quote(message)
        data_uri = f"{BASE_URL}/message?msg={encoded_message}"

        template_object = {
            "object_type": "text",
            "text": message[:200] if len(message) > 200 else message,
            "link": {
                "web_url": data_uri,
                "mobile_web_url": data_uri
            }
        }
        
        # 나에게 보내는 API는 receiver_uuids 없음!
        data = {
            "template_object": json.dumps(template_object)
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, data=data)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get("result_code") == 0:
                    return {
                        "success": True,
                        "message": "메시지가 성공적으로 발송되었습니다.",
                        "result_code": result.get("result_code")
                    }
                else:
                    return {
                        "success": False,
                        "error": f"result_code: {result.get('result_code')}",
                        "message": "메시지 발송에 실패했습니다."
                    }
            else:
                error_msg = response.text
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {error_msg}",
                    "message": "메시지 발송 중 오류가 발생했습니다."
                }
            
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "메시지 발송 중 오류가 발생했습니다."
        }

@mcp.tool(
    name="send_message",
    description="카카오톡으로 **친구에게** 텍스트 메시지를 발송하는 도구입니다. 친구 목록 조회를 통해 메세지를 보낼 친구의 UUID를 필요로 합니다."
)
async def send_message(uuid: str, message: str) -> dict:
    from fastmcp.server.dependencies import get_access_token
    import httpx
    import json
    from urllib.parse import quote
    
    try:
        token = get_access_token()
        access_token = token.token
        
        # url = "https://kapi.kakao.com/v1/api/talk/friends/message/send"
        url = "https://kapi.kakao.com/v1/api/talk/friends/message/default/send"
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8"
        }
        
        # 메시지를 URL 인코딩
        encoded_message = quote(message)
        message_link = f"{BASE_URL}/message?msg={encoded_message}"
        
        # 템플릿 객체
        template_object = {
            "object_type": "text",
            "text": message[:200] if len(message) > 200 else message,
            "link": {
                "web_url": message_link,
                "mobile_web_url": message_link
            }
        }
        
        data = {
            "receiver_uuids": json.dumps([uuid]),
            "template_object": json.dumps(template_object)
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, data=data)
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "success": True,
                    "message": "메시지가 성공적으로 발송되었습니다.",
                    "successful_uuids": result.get("successful_receiver_uuids")
                }
            else:
                error_msg = response.text
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {error_msg}",
                    "message": "메시지 발송 중 오류가 발생했습니다."
                }
            
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "메시지 발송 중 오류가 발생했습니다."
        }

@mcp.custom_route("/message", methods=["GET"])
async def show_message(request):
    """메시지 전체 표시"""
    from starlette.responses import HTMLResponse
    from urllib.parse import unquote
    
    msg = unquote(request.query_params.get("msg", "메시지 없음"))
    
    html = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>메시지</title>
        <style>
            body {{ 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 20px;
                line-height: 1.6;
                background: #f5f5f5;
            }}
            .container {{ 
                max-width: 100%;
                margin: 0 auto;
                padding: 20px;
                background: white;
                border-radius: 8px;
                word-break: break-word;
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
            p {{ 
                margin: 0;
                white-space: pre-wrap;
                word-break: break-word;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <p>{msg}</p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html)

@mcp.tool(
    name="search_kakao_friends",
    description="카카오톡 친구목록을 가져옵니다. 친구 이름과 UUID를 반환하므로 메시지 발송할 때 사용할 수 있습니다."
)
async def search_kakao_friends(limit: int = 10) -> dict:
    
    from fastmcp.server.dependencies import get_access_token
    import httpx
    import webbrowser
    from urllib.parse import urlencode
    
    try:
        token = get_access_token()
        access_token = token.token
        
        # 환경변수에서 저장된 friends 토큰이 있으면 사용
        friends_token = os.getenv("KAKAO_FRIENDS_ACCESS_TOKEN")
        if friends_token:
            access_token = friends_token

        url = "https://kapi.kakao.com/v1/api/talk/friends"
        
        headers = {
            "Authorization": f"Bearer {access_token}",
        }
        
        params = {
            "limit": limit,
            "friend_order": "name"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                result = response.json()
                
                # 친구 목록 정렬 및 포맷팅
                friends = result.get("elements", [])
                formatted_friends = [
                    {
                        "name": friend.get("name", "Unknown"),
                        "uuid": friend.get("uuid", ""),
                        "profile_nickname": friend.get("profile_nickname", "")
                    }
                    for friend in friends
                ]
                
                return {
                    "success": True,
                    "message": f"친구 {len(formatted_friends)}명 조회 완료",
                    "total_count": result.get("total_count", 0),
                    "friends": formatted_friends,
                    "result": result
                }
            elif response.status_code == 403:
                error_data = response.json()
                if error_data.get("code") == -402:
                    # 동의 요청 필요
                    redirect_uri = BASE_URL + "/friends/callback"
                    scope = "openid,friends"
                    
                    auth_url_params = {
                        "client_id": KAKAO_CLIENT_ID,
                        "redirect_uri": redirect_uri,
                        "response_type": "code",
                        "scope": scope
                    }
                    
                    auth_url = f"https://kauth.kakao.com/oauth/authorize?{urlencode(auth_url_params)}"
                    
                    # 브라우저에서 자동으로 동의 화면 열기
                    webbrowser.open(auth_url)
                    
                    return {
                        "success": False,
                        "error": "friends_scope_required",
                        "message": "브라우저에서 동의 화면이 열렸습니다. 동의 후 자동으로 처리됩니다.",
                        "consent_url": auth_url
                    }
                else:
                    return {
                        "success": False,
                        "error": f"code: {error_data.get('code')}",
                        "message": error_data.get("msg", "친구 목록 조회 실패")
                    }
            else:
                error_msg = response.text
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {error_msg}",
                    "message": "친구 목록 조회중 오류가 발생"
                }
            
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "친구 목록 조회중 오류 발생"
        }

# 친구 목록 동의 콜백 엔드포인트
@mcp.custom_route("/friends/callback", methods=["GET"])
async def friends_callback(request):
    """카카오 동의 후 콜백받아서 토큰 발급"""
    from starlette.responses import JSONResponse
    
    code = request.query_params.get("code")
    error = request.query_params.get("error")
    
    if error:
        return JSONResponse({
            "success": False,
            "error": error,
            "message": "동의 취소됨"
        }, status_code=400)
    
    if not code:
        return JSONResponse({
            "success": False,
            "error": "missing_code",
            "message": "code 파라미터 누락"
        }, status_code=400)
    
    # code로 토큰 요청
    try:
        redirect_uri = BASE_URL + "/friends/callback"
        
        token_data = {
            "grant_type": "authorization_code",
            "client_id": KAKAO_CLIENT_ID,
            "client_secret": KAKAO_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
            "code": code
        }
        
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                "https://kauth.kakao.com/oauth/token",
                data=token_data
            )
        
        if token_response.status_code == 200:
            token_result = token_response.json()
            new_token = token_result.get("access_token")
            
            # 환경변수에 저장
            os.environ["KAKAO_FRIENDS_ACCESS_TOKEN"] = new_token
            
            return JSONResponse({
                "success": True,
                "message": "토큰이 저장되었습니다. 친구 목록 조회를 다시 시도해주세요.",
                "token_saved": True
            })
        else:
            return JSONResponse({
                "success": False,
                "error": f"token_request_failed",
                "message": f"토큰 요청 실패: {token_response.text}"
            }, status_code=400)
            
    except Exception as e:
        return JSONResponse({
            "success": False,
            "error": str(e),
            "message": "토큰 발급 중 오류 발생"
        }, status_code=500)

    
if __name__ == "__main__":

    mcp.run(transport="streamable-http", path="/mcp")
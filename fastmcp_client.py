import os
import json
import glob
import asyncio
from typing import List, Optional
from pathlib import Path
from fastmcp import Client # https://gofastmcp.com/clients/client#the-fastmcp-client
from langgraph.prebuilt import create_react_agent
from langchain.schema.messages import HumanMessage, SystemMessage, AIMessage
from langchain_naver import ChatClovaX
from langchain_core.tools import StructuredTool
from pydantic import create_model
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

async def main(clova_api_key: str, server_url: str):
    """
    Args:
        clova_api_key: CLOVA Studio API Key.
        server_url: MCP 서버의 URL.
    """

    model = ChatClovaX(model="HCX-005", api_key=clova_api_key)

    # FastMCP 클라이언트 생성 및 OAuth 인증
    async with Client(server_url, auth="oauth") as auth_client:
        print("✓ Authenticated with OAuth!")
        
        # MCP 도구를 LangChain 형식으로 변환
        structured_tools = await load_tools(auth_client)

        agent = create_react_agent(model, structured_tools)

        state = {
            "messages": [
                SystemMessage(content=(
                    "당신은 비서입니다. 사용자가 원하는 것을 도와주세요."
                    "당신은 현재 시간을 알 수 있고, 웹 검색을 하거나 캘린더에 일정을 추가 할 수 있습니다."
                    "사용자 요청에 대해 현재 시간이 필요한 경우에는 정확한 시간을 활용해 주세요."
                    "예를 들어 '지금 몇 시야?' 라고 물어보면 현재 시간을 알려주고, '내일 일정은 어때?','3일 뒤로 일정 잡아줘' 라고 물어보면 현재 시간을 기준으로 날짜를 확인해 활용해주세요."
                ))
            ]
        }

        print("\nAI: 안녕하세요. 저는 당신의 비서입니다. 무엇을 도와드릴까요?")

        while True:
            user_input = input("\n\nUser: ")
            if user_input.lower() in ["종료", "exit"]:
                print("AI: 대화를 종료합니다. 이용해주셔서 감사합니다.")
                break
            
            state["messages"].append(HumanMessage(content=user_input))

            # astream_events를 사용하여 스트리밍으로 결과 처리
            try:
                final_answer = ""
                
                async for event in agent.astream_events(state, version="v1"):
                    kind = event["event"]
                    if kind == "on_chat_model_stream":
                        chunk = event["data"]["chunk"]
                        if chunk.content:
                            print(chunk.content, end="", flush=True)
                            final_answer += chunk.content

                    elif kind == "on_tool_start":
                        print(f"\n[도구 선택]: {event['name']}\n[도구 호출]: {event['data'].get('input')}")

                    elif kind == "on_tool_end":
                        print(f"[도구 응답]: {event['data'].get('output')}\n")

                # 스트리밍이 끝나면 최종 답변을 AIMessage로 만들어 상태에 추가
                state["messages"].append(AIMessage(content=final_answer))

            except Exception as e:
                print(f"\nAI: 요청을 처리하는 중에 오류가 발생했습니다. 오류: {e}")
                pass 


async def load_tools(client: Client) -> List[StructuredTool]:
    """
    FastMCP 클라이언트로부터 도구를 로드하여 LangChain StructuredTool로 변환
    
    Args:
        client: FastMCP Client 인스턴스 (인증된 세션 유지)
    
    Returns:
        List[StructuredTool]: LangChain 호환 도구 목록
    """
    
    # MCP 서버에서 도구 목록 가져오기
    tools = await client.list_tools()
    
    structured_tools = []
    for tool in tools:
        # 도구의 입력 스키마 추출
        schema = tool.inputSchema or {}
        props = schema.get("properties", {})
        
        # 파라미터 없는 도구 제외
        if not props:
            continue
        
        # Pydantic 모델 동적 생성 - MCP 스키마를 Pydantic 필드로 변환
        field_definitions = {}
        for key, prop in props.items():
            # JSON Schema 타입을 Python 타입으로 변환
            field_type = _get_python_type(prop.get("type", "string"))
            # 모든 필드를 required로 설정 (... = Ellipsis)
            field_definitions[key] = (field_type, ...)
        
        # 동적으로 Pydantic 모델 클래스 생성
        # 예: "web_search" -> "web_searchInput" 클래스
        InputModel = create_model(
            f"{tool.name}Input",
            **field_definitions
        )
        
        # 각 도구마다 고유한 async 함수 생성
        # tool_name과 mcp_client를 캡처하여 각 도구마다 고유한 함수 생성
        def create_async_func(tool_name=tool.name, mcp_client=client):
            async def func(**kwargs):
                # 실제 MCP 서버의 도구 호출
                result = await mcp_client.call_tool(tool_name, kwargs)
                return result
            return func
        
        # LangChain StructuredTool 생성
        # coroutine 파라미터를 사용하여 async 함수 지원
        structured_tool = StructuredTool.from_function(
            coroutine=create_async_func(),      
            name=tool.name,                    
            description=tool.description or "", 
            args_schema=InputModel,             
        )
        
        structured_tools.append(structured_tool)
    
    return structured_tools


def _get_python_type(json_type: str) -> type:
    """JSON Schema 타입을 Python 타입으로 변환합니다."""

    type_mapping = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    return type_mapping.get(json_type, str)


if __name__ == "__main__":
    CLOVA_API_KEY = os.getenv("CLOVA_API_KEY")
    BASE_URL = os.getenv("BASE_URL")
    SERVER_URL = BASE_URL + "/mcp/"

    asyncio.run(main(CLOVA_API_KEY, SERVER_URL))

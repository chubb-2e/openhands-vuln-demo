"""
OpenHands Event Stream — 실시간 시각화 대시보드
================================================

목적
----
OpenHands 공식 아키텍처 다이어그램의 3개 박스
    User Interface  |  Event Stream  |  Agent Runtime (Docker Sandbox)
와 똑같은 레이아웃의 웹페이지를 띄우고,
실제 openhands-sdk Conversation을 백그라운드에서 돌리면서
그 안에서 벌어지는 이벤트(Message / Action / Observation / Error)를
Server-Sent Events(SSE)로 브라우저에 실시간으로 흘려보냅니다.

즉, 화면에 보이는 모든 것은 "그럴듯한 연출"이 아니라
실제 SDK가 실제 LLM을 호출해서 만들어내는 진짜 이벤트입니다.
(터미널 버전 openhands_event_stream_demo.py와 이벤트 소스는 동일하고,
 이번엔 그걸 브라우저 3분할 화면 + 루프 카운터로 보여준다는 점만 다릅니다.)

사전 준비
--------
    cd openhands-live-demo
    python3 -m pip install -U flask openhands-sdk openhands-tools
    export LLM_API_KEY="sk-ant-..."      # Claude API 키

실행
----
    python3 app.py
    → 브라우저에서 http://localhost:5050 접속
    → 화면의 입력창에 태스크를 쓰거나(비워두면 기본 취약점 스캔 태스크 사용)
      "데모 시작" 버튼 클릭
    → 3분할 화면에서 루프가 도는 걸 실시간으로 보고, 원하는 순간에 캡쳐

기본적으로 이 대시보드는 같은 폴더 안의 vuln-app/ 을 워크스페이스로 잡고
그 안의 app.py를 실제로 스캔·수정합니다. (vuln-app/app.py 를 실행 전/후로
직접 열어봐도 실제로 코드가 바뀐 걸 확인할 수 있습니다.)
"""

import json
import os
import queue
import sys
import threading
import time
import uuid

from flask import Flask, Response, jsonify, render_template, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 워크스페이스 자동 감지:
#   1) 같은 폴더에 vuln-app/ 이 있으면 그걸 사용 (독립 실행용 zip 배포 형태)
#   2) 없으면 한 단계 위 폴더를 사용 (이 app.py가 깃허브 저장소 안의
#      dashboard/ 서브폴더로 들어가 있고, 실제 취약점 코드(app.py)는
#      저장소 루트에 있는 형태)
_sibling_vuln_app = os.path.join(BASE_DIR, "vuln-app")
if os.getenv("WORKSPACE_DIR"):
    DEFAULT_WORKSPACE = os.path.abspath(os.getenv("WORKSPACE_DIR"))
elif os.path.isdir(_sibling_vuln_app):
    DEFAULT_WORKSPACE = _sibling_vuln_app
else:
    DEFAULT_WORKSPACE = os.path.abspath(os.path.join(BASE_DIR, os.pardir))

DEFAULT_TASK = (
    "이 프로젝트 코드를 스캔해서 보안 취약점(예: SQL 인젝션, 하드코딩된 시크릿, "
    "안전하지 않은 subprocess/eval/os.system 사용 등)을 찾아줘. 문제를 찾으면 각각 "
    "어떤 파일의 몇 번째 줄인지 설명하고, 바로 코드를 고쳐줘. 고친 후에는 다시 한번 "
    "스캔해서 문제가 해결됐는지 확인해줘."
)

# --- openhands-sdk는 없을 수도 있으니, 앱이 뜨는 것 자체는 막지 않는다 ---
OPENHANDS_IMPORT_ERROR = None
try:
    from openhands.sdk import LLM, Agent, Conversation, Tool
    from openhands.sdk.event import (
        ActionEvent,
        AgentErrorEvent,
        MessageEvent,
        ObservationEvent,
    )
    from openhands.tools.file_editor import FileEditorTool
    from openhands.tools.terminal import TerminalTool

    OPENHANDS_AVAILABLE = True
except ImportError as e:  # pragma: no cover
    OPENHANDS_AVAILABLE = False
    OPENHANDS_IMPORT_ERROR = str(e)


app = Flask(__name__)

# ---------------------------------------------------------------------------
# 아주 단순한 pub/sub: 백그라운드 스레드가 만든 이벤트를 모든 SSE 클라이언트에 방송
# ---------------------------------------------------------------------------
_subscribers = []
_subscribers_lock = threading.Lock()
_event_history = []          # 새로 접속한 브라우저에 재생해줄 지금까지의 전체 이벤트
_history_lock = threading.Lock()
_run_lock = threading.Lock()  # 한 번에 하나의 데모만 실행
_run_state = {"running": False}


def broadcast(step: dict) -> None:
    step.setdefault("id", str(uuid.uuid4()))
    step.setdefault("ts", time.time())
    with _history_lock:
        _event_history.append(step)
    with _subscribers_lock:
        for q in _subscribers:
            q.put(step)


def reset_history() -> None:
    with _history_lock:
        _event_history.clear()


# ---------------------------------------------------------------------------
# 실제 OpenHands SDK Conversation을 돌리면서, 콜백에서 들어오는 실제 이벤트를
# 대시보드가 이해하는 "step" 메시지로 바꿔서 broadcast() 한다.
# ---------------------------------------------------------------------------
def run_conversation(task: str, workspace: str) -> None:
    state = {"event_count": 0, "loop": 0}

    def bump():
        state["event_count"] += 1
        return state["event_count"]

    def on_event(event) -> None:
        cls_name = type(event).__name__
        source = str(getattr(event, "source", "?"))

        if cls_name == "MessageEvent" and source == "user":
            n = bump()
            broadcast({
                "type": "event",
                "event_type": "message_user",
                "loop": state["loop"],
                "n": n,
                "title": "사용자 태스크",
                "body": task,
            })
            return

        if cls_name == "ActionEvent":
            state["loop"] += 1
            loop_n = state["loop"]

            broadcast({
                "type": "phase",
                "phase": "history_review",
                "loop": loop_n,
                "n": state["event_count"],
                "message": f"Event History 재검토 중... (지금까지 누적 이벤트 {state['event_count']}개)",
            })
            broadcast({
                "type": "loop_start",
                "loop": loop_n,
                "message": f"Loop {loop_n} 시작",
            })

            thought = str(getattr(event, "thought", "") or "")
            action = str(getattr(event, "action", "") or "")
            tool = getattr(event, "tool_name", None) or "?"

            n = bump()
            broadcast({
                "type": "event",
                "event_type": "action",
                "loop": loop_n,
                "n": n,
                "tool": tool,
                "title": f"Action → {tool}",
                "body": (f"[생각]\n{thought}\n\n[액션]\n{action}").strip()[:1500],
            })

            broadcast({
                "type": "runtime",
                "loop": loop_n,
                "n": state["event_count"],
                "tool": tool,
                "message": f"Agent Runtime(Docker Sandbox): '{tool}' 도구 실행 중...",
            })
            return

        if cls_name == "ObservationEvent":
            obs = str(getattr(event, "observation", "") or "")
            tool = getattr(event, "tool_name", None) or "?"
            n = bump()
            broadcast({
                "type": "event",
                "event_type": "observation",
                "loop": state["loop"],
                "n": n,
                "tool": tool,
                "title": f"Observation ← {tool}",
                "body": obs.strip()[:1500] or "(빈 출력)",
            })
            broadcast({
                "type": "phase",
                "phase": "observation_added",
                "loop": state["loop"],
                "n": n,
                "message": "실행 결과가 Event Stream에 새로 추가됨 → 다음 루프에서 다시 읽힘",
            })
            return

        if cls_name == "AgentErrorEvent":
            n = bump()
            broadcast({
                "type": "event",
                "event_type": "error",
                "loop": state["loop"],
                "n": n,
                "title": "Agent Error",
                "body": str(getattr(event, "error", event)),
            })
            return

        if cls_name == "MessageEvent":  # 에이전트가 사용자에게 남기는 최종 메시지 등
            n = bump()
            content = getattr(event, "llm_message", event)
            broadcast({
                "type": "event",
                "event_type": "message_agent",
                "loop": state["loop"],
                "n": n,
                "title": "Agent 메시지",
                "body": str(content).strip()[:1500],
            })
            return

        # 그 외 알 수 없는 이벤트 타입도 최대한 보여준다
        n = bump()
        broadcast({
            "type": "event",
            "event_type": "other",
            "loop": state["loop"],
            "n": n,
            "title": cls_name,
            "body": str(event)[:1500],
        })

    try:
        broadcast({"type": "status", "message": "🤖 에이전트를 불러오는 중..."})

        api_key = os.getenv("LLM_API_KEY")
        model = os.getenv("LLM_MODEL", "anthropic/claude-sonnet-4-5-20250929")

        llm = LLM(model=model, api_key=api_key, base_url=os.getenv("LLM_BASE_URL", None))
        agent = Agent(
            llm=llm,
            tools=[
                Tool(name=TerminalTool.name),
                Tool(name=FileEditorTool.name),
            ],
        )

        broadcast({
            "type": "status",
            "message": f"✅ 에이전트 로드 완료 (model={model}, tools=terminal+file_editor, workspace={workspace})",
        })

        conversation = Conversation(agent=agent, workspace=workspace, callbacks=[on_event])

        conversation.send_message(task)
        conversation.run()

        broadcast({
            "type": "done",
            "loop": state["loop"],
            "event_count": state["event_count"],
            "message": f"🏁 완료 — 총 Loop {state['loop']}회, Event Stream에 {state['event_count']}개 이벤트 누적",
        })
    except Exception as e:  # pragma: no cover
        broadcast({"type": "error_fatal", "message": f"실행 중 오류: {e}"})
    finally:
        _run_state["running"] = False


@app.route("/")
def index():
    return render_template(
        "index.html",
        default_task=DEFAULT_TASK,
        default_workspace=DEFAULT_WORKSPACE,
        openhands_available=OPENHANDS_AVAILABLE,
        import_error=OPENHANDS_IMPORT_ERROR,
    )


@app.route("/start", methods=["POST"])
def start():
    if not OPENHANDS_AVAILABLE:
        return jsonify({
            "ok": False,
            "error": (
                "openhands-sdk / openhands-tools 가 설치되어 있지 않습니다. "
                "'pip install -U openhands-sdk openhands-tools' 실행 후 서버를 재시작하세요. "
                f"(원본 에러: {OPENHANDS_IMPORT_ERROR})"
            ),
        }), 400

    if not os.getenv("LLM_API_KEY"):
        return jsonify({
            "ok": False,
            "error": "LLM_API_KEY 환경변수가 설정되어 있지 않습니다. 서버 실행 전에 export LLM_API_KEY=... 를 해주세요.",
        }), 400

    if _run_state["running"]:
        return jsonify({"ok": False, "error": "이미 데모가 실행 중입니다. 완료 후 다시 시도하세요."}), 409

    payload = request.get_json(silent=True) or {}
    task = (payload.get("task") or "").strip() or DEFAULT_TASK
    workspace = (payload.get("workspace") or "").strip() or DEFAULT_WORKSPACE

    reset_history()
    _run_state["running"] = True
    broadcast({"type": "status", "message": "▶ 데모 시작"})
    broadcast({
        "type": "event",
        "event_type": "message_user_pending",
        "loop": 0,
        "n": 0,
        "title": "User Interface → Event Stream",
        "body": task,
    })

    t = threading.Thread(target=run_conversation, args=(task, workspace), daemon=True)
    t.start()
    return jsonify({"ok": True})


@app.route("/events")
def events():
    def gen():
        q = queue.Queue()
        with _subscribers_lock:
            _subscribers.append(q)
        try:
            with _history_lock:
                backlog = list(_event_history)
            for step in backlog:
                yield f"data: {json.dumps(step, ensure_ascii=False)}\n\n"
            while True:
                try:
                    step = q.get(timeout=15)
                    yield f"data: {json.dumps(step, ensure_ascii=False)}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            with _subscribers_lock:
                if q in _subscribers:
                    _subscribers.remove(q)

    return Response(gen(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


if __name__ == "__main__":
    if not OPENHANDS_AVAILABLE:
        print(
            "[경고] openhands-sdk / openhands-tools 를 import하지 못했습니다.\n"
            "  pip install -U openhands-sdk openhands-tools\n"
            "페이지는 뜨지만 '데모 시작'은 설치 후에만 동작합니다.\n"
            f"(원본 에러: {OPENHANDS_IMPORT_ERROR})",
            file=sys.stderr,
        )
    port = int(os.getenv("PORT", "5050"))
    print(f"\n🚀 http://localhost:{port} 에서 대시보드를 확인하세요\n")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)

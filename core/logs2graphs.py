"""
logs2graphs.py
==============
将 OpenClaw 的 sessions JSONL 日志（logs/sessions/）和系统层底层交互日志
（logs/output.json）构建成异构图。

图结构
------
节点类型:
  - User        : 向 main agent 发消息的真实用户
  - Task        : 每个 Agent Session（main / subagent / subtask）
                  subtask 由 Minimax 模型对 Tool 调用聚类自动生成
  - Tool        : 每次工具调用（toolCall）
  - Data        : 工具返回结果（toolResult）
  - File        : 系统层记录的文件访问路径
  - Process     : 系统层记录的子进程（EXEC 事件）
  - Network     : 网络访问

边类型:
  - USER_REQUESTS  : User -> Task
  - SPAWNS         : Task -> Task  (sessions_spawn / subtask 聚类)
  - REPORTS_TO     : Task -> Task  (subagent 完成后汇报)
  - CALLS          : Task(subtask) -> Tool  (聚类后由 SubTask 发起)
  - RETURNS        : Tool -> Data
  - CONSUMES       : Data -> Task(subtask)
  - SPAWNS_PROCESS : Tool -> Process  (时间窗口匹配)
  - ACCESSES_FILE  : Tool -> File     (时间窗口匹配)
  - CALLS_NETWORK  : Tool -> Network  (时间窗口匹配)
  - CHILD_OF       : Process -> Process (ppid 关系)
  - PROCESS_ACCESSES : Process -> File
  - PROCESS_CONNECTS : Process -> Network

用法
----
  python logs2graphs.py [--sessions-dir SESSIONS_DIR] [--output-json OUTPUT_JSON]
                        [--out OUT] [--format {json,jsonl}]

默认路径（相对于此脚本所在目录的上级）:
  sessions-dir : logs/sessions/
  output-json  : logs/output.json
  out          : logs/graph.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import glob
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple
from openai import OpenAI

# ─────────────────────────────────────────────────────────────────────────────
# 工具函数 & 预定义数据
# ─────────────────────────────────────────────────────────────────────────────

TOOL_DESCRIPTIONS = {
    "read": "Read the contents of a file. Supports text files and images (jpg, png, gif, webp). Images are sent as attachments. For text files, output is truncated to 2000 lines or 50KB (whichever is hit first). Use offset/limit for large files. When you need the full file, continue with offset until complete.",
    "edit": "Edit a file by replacing exact text. The oldText must match exactly (including whitespace). Use this for precise, surgical edits.",
    "write": "Write content to a file. Creates the file if it doesn't exist, overwrites if it does. Automatically creates parent directories.",
    "exec": "Execute shell commands with background continuation. Use yieldMs/background to continue later via process tool. Use pty=true for TTY-required commands (terminal UIs, coding agents).",
    "process": "Manage running exec sessions: list, poll, log, write, send-keys, submit, paste, kill.",
    "cron": "Manage Gateway cron jobs (status/list/add/update/remove/run/runs) and send wake events.\\n\\nACTIONS:\\n- status: Check cron scheduler status\\n- list: List jobs (use includeDisabled:true to include disabled)\\n- add: Create job (requires job object, see schema below)\\n- update: Modify job (requires jobId + patch object)\\n- remove: Delete job (requires jobId)\\n- run: Trigger job immediately (requires jobId)\\n- runs: Get job run history (requires jobId)\\n- wake: Send wake event (requires text, optional mode)\\n\\nJOB SCHEMA (for add action):\\n{\\n  \"name\": \"string (optional)\",\\n  \"schedule\": { ... },      // Required: when to run\\n  \"payload\": { ... },       // Required: what to execute\\n  \"delivery\": { ... },      // Optional: announce summary or webhook POST\\n  \"sessionTarget\": \"main\" | \"isolated\",  // Required\\n  \"enabled\": true | false   // Optional, default true\\n}\\n\\nSCHEDULE TYPES (schedule.kind):\\n- \"at\": One-shot at absolute time\\n  { \"kind\": \"at\", \"at\": \"<ISO-8601 timestamp>\" }\\n- \"every\": Recurring interval\\n  { \"kind\": \"every\", \"everyMs\": <interval-ms>, \"anchorMs\": <optional-start-ms> }\\n- \"cron\": Cron expression\\n  { \"kind\": \"cron\", \"expr\": \"<cron-expression>\", \"tz\": \"<optional-timezone>\" }\\n\\nISO timestamps without an explicit timezone are treated as UTC.\\n\\nPAYLOAD TYPES (payload.kind):\\n- \"systemEvent\": Injects text as system event into session\\n  { \"kind\": \"systemEvent\", \"text\": \"<message>\" }\\n- \"agentTurn\": Runs agent with message (isolated sessions only)\\n  { \"kind\": \"agentTurn\", \"message\": \"<prompt>\", \"model\": \"<optional>\", \"thinking\": \"<optional>\", \"timeoutSeconds\": <optional, 0 means no timeout> }\\n\\nDELIVERY (top-level):\\n  { \"mode\": \"none|announce|webhook\", \"channel\": \"<optional>\", \"to\": \"<optional>\", \"bestEffort\": <optional-bool> }\\n  - Default for isolated agentTurn jobs (when delivery omitted): \"announce\"\\n  - announce: send to chat channel (optional channel/to target)\\n  - webhook: send finished-run event as HTTP POST to delivery.to (URL required)\\n  - If the task needs to send to a specific chat/recipient, set announce delivery.channel/to; do not call messaging tools inside the run.\\n\\nCRITICAL CONSTRAINTS:\\n- sessionTarget=\"main\" REQUIRES payload.kind=\"systemEvent\"\\n- sessionTarget=\"isolated\" REQUIRES payload.kind=\"agentTurn\"\\n- For webhook callbacks, use delivery.mode=\"webhook\" with delivery.to set to a URL.\\nDefault: prefer isolated agentTurn jobs unless the user explicitly wants a main-session system event.\\n\\nWAKE MODES (for wake action):\\n- \"next-heartbeat\" (default): Wake on next heartbeat\\n- \"now\": Wake immediately\\n\\nUse jobId as the canonical identifier; id is accepted for compatibility. Use contextMessages (0-10) to add previous messages as context to the job text.",
    "sessions_list": "List sessions with optional filters and last messages.",
    "sessions_history": "Fetch message history for a session.",
    "sessions_send": "Send a message into another session. Use sessionKey or label to identify the target.",
    "sessions_spawn": "Spawn an isolated session (runtime=\"subagent\" or runtime=\"acp\"). mode=\"run\" is one-shot and mode=\"session\" is persistent/thread-bound. Subagents inherit the parent workspace directory automatically.",
    "subagents": "List, kill, or steer spawned sub-agents for this requester session. Use this for sub-agent orchestration.",
    "session_status": "Show a /status-equivalent session status card (usage + time + cost when available). Use for model-use questions (📊 session_status). Optional: set per-session model override (model=default resets overrides).",
    "memory_search": "Mandatory recall step: semantically search MEMORY.md + memory/*.md (and optional session transcripts) before answering questions about prior work, decisions, dates, people, preferences, or todos; returns top snippets with path + lines. If response has disabled=true, memory retrieval is unavailable and should be surfaced to the user.",
    "memory_get": "Safe snippet read from MEMORY.md or memory/*.md with optional from/lines; use after memory_search to pull only the needed lines and keep context small."
}

def _ts_ms(ts) -> int:
    """确保时间戳为毫秒整数。支持 ISO 字符串和数值两种格式。"""
    if ts is None:
        return 0
    if isinstance(ts, str):
        # ISO 8601: "2026-03-17T05:09:59.236Z" 或 "2026-03-17T05:09:59.236+00:00"
        from datetime import datetime, timezone
        ts_str = ts.rstrip("Z")
        if "+" in ts_str[10:]:
            ts_str = ts_str[:ts_str.rfind("+")]
        dt = datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    ts = int(ts)
    if ts < 2_000_000_000_000:
        # seconds 级（Unix epoch < ~63年后） → 转 ms
        if ts < 2_000_000_000:
            return ts * 1000
        return ts   # 已经是 ms
    # 纳秒级 → ms
    return ts // 1_000_000


def _text_preview(text: str, limit: int = 300) -> str:
    if not text:
        return ""
    text = text.strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def _extract_urls_from_args(args: dict) -> List[str]:
    """从 tool arguments 中提取 URL（支持 exec / read 工具中包含 curl 的情况）。"""
    urls: List[str] = []
    url_pattern = re.compile(r'https?://[^\s\'"<>]+')
    for v in args.values():
        if isinstance(v, str):
            urls.extend(url_pattern.findall(v))
        elif isinstance(v, dict):
            urls.extend(_extract_urls_from_args(v))
    return list(set(urls))


def _host_from_url(url: str) -> str:
    m = re.match(r'https?://([^/]+)', url)
    return m.group(1) if m else url


def _is_system_lib(path: str) -> bool:
    """过滤系统库路径（libc, ld, python stdlib 等），减少图噪音。"""
    skip_prefixes = (
        '/lib/', '/usr/lib/', '/lib64/', '/usr/bin/pyvenv',
        '/usr/bin/pybuilddir', '/usr/share/locale', '/etc/ld.so',
        '/usr/lib/x86_64', '/usr/lib/python3.10/encodings',
        '/usr/lib/python3.10/__pycache__',
    )
    skip_suffixes = (
        '.so', '.so.0', '.so.1', '.so.2', '.so.3', '.so.4',
        '.so.5', '.so.6', '.so.8', '.so.9', '.so.10',
        '.pyc',
    )
    for p in skip_prefixes:
        if path.startswith(p):
            return True
    for s in skip_suffixes:
        if path.endswith(s):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 图容器
# ─────────────────────────────────────────────────────────────────────────────

class Graph:
    def __init__(self):
        self.nodes: Dict[str, dict] = {}   # id -> node dict
        self.edges: List[dict] = []
        self._edge_set: set = set()        # 去重用

    def add_node(self, node_id: str, node_type: str, **attrs):
        if node_id not in self.nodes:
            self.nodes[node_id] = {"id": node_id, "type": node_type, **attrs}
        else:
            # 更新非 None 属性
            for k, v in attrs.items():
                if v is not None:
                    self.nodes[node_id][k] = v

    def add_edge(self, src: str, dst: str, rel: str, **attrs):
        key = (src, dst, rel)
        if key not in self._edge_set:
            self._edge_set.add(key)
            self.edges.append({"src": src, "dst": dst, "rel": rel, **attrs})

    def to_dict(self) -> dict:
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "stats": {
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
                "node_types": _count_types(self.nodes.values(), "type"),
                "edge_types": _count_types(self.edges, "rel"),
            }
        }


def _count_types(items, key: str) -> dict:
    c: Dict[str, int] = defaultdict(int)
    for item in items:
        c[item.get(key, "unknown")] += 1
    return dict(c)


# ─────────────────────────────────────────────────────────────────────────────
# 读取 sessions JSONL
# ─────────────────────────────────────────────────────────────────────────────

def load_sessions(sessions_dir: str) -> Dict[str, List[dict]]:
    """
    返回 {session_id: [jsonl_entry, ...]} 的字典。
    同时读取 sessions.json 以获取 session key → session id 映射。
    """
    sessions: Dict[str, List[dict]] = {}

    # 读取所有 .jsonl 文件
    jsonl_files = glob.glob(os.path.join(sessions_dir, "*.jsonl"))
    for fpath in sorted(jsonl_files):
        session_id = os.path.basename(fpath).replace(".jsonl", "")
        entries = []
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entries.append(json.loads(line))
        sessions[session_id] = entries

    return sessions


def load_sessions_meta(sessions_dir: str) -> Dict[str, dict]:
    """
    读取 sessions.json，返回 {session_key: meta_dict}。
    meta_dict 含 sessionId, label, spawnedBy, spawnDepth 等字段。
    """
    path = os.path.join(sessions_dir, "sessions.json")
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return raw  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# 读取 output.json（系统层）
# ─────────────────────────────────────────────────────────────────────────────

def load_output_events(output_json: str) -> List[dict]:
    """逐行读取 output.json（每行一个 JSON 对象）。"""
    events = []
    with open(output_json, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


# ─────────────────────────────────────────────────────────────────────────────
# 解析 session JSONL → 提取图元素
# ─────────────────────────────────────────────────────────────────────────────

def parse_sessions(
    sessions: Dict[str, List[dict]],
    sessions_meta: Dict[str, dict],
    graph: Graph,
):
    """
    从 sessions 中提取:
      - User 节点
      - Task 节点
      - Tool 节点
      - Data 节点
      - 边: USER_REQUESTS, SPAWNS, REPORTS_TO, CALLS, RETURNS, CONSUMES
    """

    # 建立 session_id → session_key 的反向映射
    sid_to_skey: Dict[str, str] = {}
    for skey, meta in sessions_meta.items():
        sid = meta.get("sessionId", "")
        if sid:
            sid_to_skey[sid] = skey

    # 建立 toolCallId → (tool_node_id, task_id, called_at, result_at)
    tool_call_map: Dict[str, dict] = {}

    for session_id, entries in sessions.items():
        skey = sid_to_skey.get(session_id, f"unknown:{session_id}")
        meta = sessions_meta.get(skey, {})

        # ── Task 节点 ──────────────────────────────────────────────────────
        is_subagent = "subagent" in skey
        task_id = f"task:{skey}"

        # 「输入的任务」和「收到的任务结果」先置空，遍历 entries 时填充
        task_input_text: Optional[str] = None
        received_data_returns: List[str] = []  # 收集 Data 节点返回
        received_task_returns: List[str] = []  # 收集 subagent 返回

        spawned_by = meta.get("spawnedBy")
        spawned_by_label = None
        if spawned_by:
            parent_meta = sessions_meta.get(spawned_by)
            if parent_meta:
                spawned_by_label = parent_meta.get("label", "main" if parent_meta.get("spawnDepth", 0) == 0 else "subagent")
            else:
                spawned_by_label = f"task:{spawned_by}"

        graph.add_node(
            task_id,
            "Task",
            session_key=skey,
            session_id=session_id,
            label=meta.get("label", "main" if not is_subagent else "subagent"),
            task_type="original",
            spawned_by=spawned_by_label,
            input_task=task_input_text,
            received_returns=None,
            started_at=None,
            ended_at=None,
        )

        # 父子 Task 边：SPAWNS（稍后通过 sessions_spawn toolCall 完善）
        spawned_by_key = meta.get("spawnedBy")
        if spawned_by_key:
            parent_task_id = f"task:{spawned_by_key}"
            graph.add_edge(
                parent_task_id, task_id, "SPAWNS",
                timestamp=meta.get("updatedAt"),
                child_session_key=skey,
            )
            graph.add_edge(
                task_id, parent_task_id, "REPORTS_TO",
                timestamp=meta.get("updatedAt"),
                status="completed" if not meta.get("abortedLastRun") else "aborted",
            )

        # ── 遍历条目 ──────────────────────────────────────────────────────
        # 先收集所有 toolCall 和 toolResult，方便配对
        tool_calls_in_session: Dict[str, dict] = {}   # toolCallId → toolCall entry
        tool_results_in_session: Dict[str, dict] = {}  # toolCallId → toolResult entry

        ts_first = None
        ts_last = None

        for entry in entries:
            etype = entry.get("type")
            ts = entry.get("timestamp")
            if ts:
                ts = _ts_ms(ts)
                if ts_first is None or ts < ts_first:
                    ts_first = ts
                if ts_last is None or ts > ts_last:
                    ts_last = ts

            if etype != "message":
                continue

            msg = entry.get("message", {})
            role = msg.get("role")
            msg_ts = _ts_ms(msg.get("timestamp") or ts or 0)

            # ── User 消息 ────────────────────────────────────────────────
            if role == "user":
                provenance = msg.get("provenance", {})
                is_inter_session = provenance.get("kind") == "inter_session"

                content = msg.get("content", [])
                text_parts = [
                    c.get("text", "") for c in content
                    if isinstance(c, dict) and c.get("type") == "text"
                ]
                full_text = " ".join(text_parts)

                # 先处理 inter_session（在过滤之前）
                if is_inter_session:
                    # main agent: 子任务上报 → 收集到 received_task_returns
                    if full_text.strip():
                        # 提取子任务名称
                        m_task = re.search(r'^task:\s*(.+)$', full_text, re.MULTILINE)
                        subtask_label = m_task.group(1).strip() if m_task else provenance.get("sourceSessionKey", "unknown_subtask")
                        
                        # 提取 BEGIN_UNTRUSTED_CHILD_RESULT 和 END_UNTRUSTED_CHILD_RESULT 之间的内容
                        match = re.search(
                            r'<<<BEGIN_UNTRUSTED_CHILD_RESULT>>>(.*?)<<<END_UNTRUSTED_CHILD_RESULT>>>',
                            full_text,
                            re.DOTALL
                        )
                        if match:
                            child_result = match.group(0).strip()
                            received_task_returns.append(f"[{subtask_label}]\n{child_result}")
                        else:
                            # 如果没有找到标记，保存完整内容
                            received_task_returns.append(f"[{subtask_label}]\n{full_text}")
                    continue

                # 过滤系统注入内容（仅对非 inter_session 消息）
                if "[OpenClaw runtime context (internal)]" in full_text:
                    continue
                if "Post-compaction context refresh" in full_text:
                    real_text = _extract_real_user_text(full_text)
                    if not real_text:
                        continue
                    full_text = real_text

                # 「输入的任务」：第一条 user 消息（main 或 subagent 均适用）
                if task_input_text is None and full_text.strip():
                    task_input_text = full_text

                # 提取 sender 信息
                sender_label = "unknown"
                for c in content:
                    if isinstance(c, dict) and c.get("type") == "text":
                        m = re.search(r'"label":\s*"([^"]+)"', c.get("text", ""))
                        if m:
                            sender_label = m.group(1)
                            break

                # 跳过 unknown 用户：不创建节点也不创建边
                if sender_label == "unknown":
                    continue

                user_id = f"user:{sender_label}"
                graph.add_node(user_id, "User",
                    label=sender_label,
                    name=sender_label,
                    channel=meta.get("lastChannel", "unknown")
                )

                msg_id = entry.get("id", f"msg:{session_id}:{msg_ts}")
                graph.add_edge(
                    user_id, task_id, "USER_REQUESTS",
                    timestamp=msg_ts,
                    message_id=msg_id,
                    content_preview=_text_preview(full_text, 200),
                )

            # ── Assistant 消息（含 toolCall）────────────────────────────
            elif role == "assistant":
                content = msg.get("content", [])
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") == "toolCall":
                        tc_id = part.get("id", "")
                        tool_calls_in_session[tc_id] = {
                            "entry": entry,
                            "part": part,
                            "msg_ts": msg_ts,
                        }

            # ── toolResult ────────────────────────────────────────────────
            elif role == "toolResult":
                tc_id = msg.get("toolCallId", "")
                if tc_id:
                    tool_results_in_session[tc_id] = {
                        "entry": entry,
                        "msg": msg,
                        "msg_ts": msg_ts,
                    }

        # （Task 字段在工具循环后回填）

        # ── 构建 Tool / Data 节点 ────────────────────────────────────────
        call_order = 0
        for tc_id, tc_info in tool_calls_in_session.items():
            part = tc_info["part"]
            called_at = tc_info["msg_ts"]
            tc_name = part.get("name", "unknown")
            tc_args = part.get("arguments", {})

            result_info = tool_results_in_session.get(tc_id)
            result_at = result_info["msg_ts"] if result_info else called_at
            is_error = result_info["msg"].get("isError", False) if result_info else False

            # ── sessions_spawn：只保留 SPAWNS 边，跳过 Tool/Data 节点 ───
            if tc_name == "sessions_spawn":
                if result_info:
                    result_content = result_info["msg"].get("content", [])
                    for c in result_content:
                        if isinstance(c, dict) and c.get("type") == "text":
                            spawn_result = json.loads(c.get("text", "{}"))
                            child_skey = spawn_result.get("childSessionKey", "")
                            run_id = spawn_result.get("runId", "")
                            if child_skey:
                                child_task_id = f"task:{child_skey}"
                                graph.add_edge(
                                    task_id, child_task_id, "SPAWNS",
                                    timestamp=called_at,
                                    tool_call_id=tc_id,
                                    run_id=run_id,
                                    child_session_key=child_skey,
                                )
                continue  # 不创建 Tool/Data 节点

            tool_node_id = f"tool:{tc_id}"
            data_node_id = f"data:{tc_id}"

            # Tool 节点
            graph.add_node(
                tool_node_id, "Tool",
                tool_call_id=tc_id,
                name=tc_name,
                description=TOOL_DESCRIPTIONS.get(tc_name, ""),
                arguments=tc_args,
                session_id=session_id,
                called_at=called_at,
                result_at=result_at,
                duration_ms=(result_at - called_at) if result_at and called_at else None,
                is_error=is_error,
            )

            # Data 节点
            full_result = ""
            if result_info:
                result_content = result_info["msg"].get("content", [])
                text_parts = []
                for c in result_content:
                    if isinstance(c, dict) and c.get("type") == "text":
                        text_parts.append(c.get("text", ""))
                full_result = "\n".join(text_parts)

                graph.add_node(
                    data_node_id, "Data",
                    tool_call_id=tc_id,
                    tool_name=tc_name,
                    content=full_result,
                    content_length=len(full_result),
                    is_error=is_error,
                    timestamp=result_at,
                )

                # 收集 tool data 到 received_data_returns
                if full_result.strip() and not is_error:
                    received_data_returns.append(
                        f"[{tc_name}] {full_result}"
                    )

            # 边
            call_order += 1
            graph.add_edge(task_id, tool_node_id, "CALLS",
                timestamp=called_at, call_order=call_order)
            graph.add_edge(tool_node_id, data_node_id, "RETURNS",
                timestamp=result_at, is_error=is_error)
            graph.add_edge(data_node_id, task_id, "CONSUMES",
                timestamp=result_at)

            # 保存映射供后续系统层关联
            tool_call_map[tc_id] = {
                "tool_node_id": tool_node_id,
                "task_id": task_id,
                "tool_name": tc_name,
                "tool_args": tc_args,
                "called_at": called_at,
                "result_at": result_at,
            }

        # ── 回填 Task「输入的任务」「收到的任务结果」──────────────────────
        all_returns = received_data_returns + received_task_returns
        combined_returns = "\n---\n".join(all_returns) if all_returns else None

        graph.add_node(task_id, "Task",
            started_at=ts_first,
            ended_at=ts_last,
            input_task=task_input_text,
            received_returns=combined_returns,
        )

    return tool_call_map


def _extract_real_user_text(full_text: str) -> str:
    """从包含 System: 前缀的 compaction 消息中提取真实用户文本。"""
    # 匹配 [时间] 真实用户消息 模式
    m = re.search(r'\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[^\]]+\]\s+(.+)$', full_text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# 解析 output.json → 提取系统层图元素
# ─────────────────────────────────────────────────────────────────────────────

def parse_output_events(
    events: List[dict],
    tool_call_map: Dict[str, dict],
    graph: Graph,
):
    """
    从系统层事件中提取:
      - Process 节点（EXEC + EXIT 配对）
      - File 节点（FILE_OPEN，过滤系统库）
      - Network 节点（从 curl 进程 + tool args URL 推断）
      - 边: CHILD_OF, PROCESS_ACCESSES, PROCESS_CONNECTS
      - 边（时间窗口匹配）: SPAWNS_PROCESS, ACCESSES_FILE, CALLS_NETWORK
    """

    # ── 构建进程生命周期 ─────────────────────────────────────────────────
    # pid → {exec_event, exit_event, file_events}
    process_info: Dict[int, dict] = {}

    for ev in events:
        data = ev.get("data", {})
        evt_type = data.get("event")
        pid = ev.get("pid")
        ts = _ts_ms(ev.get("timestamp", 0))

        if pid is None:
            continue

        if evt_type == "EXEC":
            process_info.setdefault(pid, {"files": [], "exit": None, "exec": None})
            process_info[pid]["exec"] = {
                "pid": pid,
                "ppid": data.get("ppid"),
                "comm": data.get("comm") or ev.get("comm"),
                "filename": data.get("filename", ""),
                "full_command": data.get("full_command", ""),
                "started_at": ts,
            }

        elif evt_type == "EXIT":
            process_info.setdefault(pid, {"files": [], "exit": None, "exec": None})
            process_info[pid]["exit"] = {
                "exit_code": data.get("exit_code"),
                "duration_ms": data.get("duration_ms"),
                "ended_at": ts,
                "ppid": data.get("ppid"),
            }

        elif evt_type == "FILE_OPEN":
            filepath = data.get("filepath", "")
            count = data.get("count", 1)
            flags = data.get("flags", 0)
            process_info.setdefault(pid, {"files": [], "exit": None, "exec": None})
            process_info[pid]["files"].append({
                "filepath": filepath,
                "count": count,
                "flags": flags,
                "timestamp": ts,
            })

    # ── 构建 Process 节点 + File 节点 + PROCESS_ACCESSES 边 ─────────────
    # 同时记录 pid → 时间范围用于后续匹配
    pid_time_range: Dict[int, Tuple[int, int]] = {}  # pid → (start_ts, end_ts)

    for pid, pinfo in process_info.items():
        exec_ev = pinfo.get("exec")
        exit_ev = pinfo.get("exit")

        comm = (exec_ev or {}).get("comm") or "unknown"
        ppid = (exec_ev or exit_ev or {}).get("ppid")
        started_at = (exec_ev or {}).get("started_at", 0)
        ended_at = (exit_ev or {}).get("ended_at", started_at)

        pid_time_range[pid] = (started_at, ended_at)

        if exec_ev:
            proc_id = f"process:{pid}"
            graph.add_node(
                proc_id, "Process",
                pid=pid,
                ppid=ppid,
                comm=comm,
                filename=exec_ev.get("filename"),
                full_command=exec_ev.get("full_command"),
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=(exit_ev or {}).get("duration_ms"),
                exit_code=(exit_ev or {}).get("exit_code"),
            )

            # 父子进程边
            if ppid and ppid in process_info and process_info[ppid].get("exec"):
                parent_proc_id = f"process:{ppid}"
                graph.add_edge(proc_id, parent_proc_id, "CHILD_OF",
                    timestamp=started_at)

        # File 和 PROCESS_ACCESSES 边
        for fev in pinfo.get("files", []):
            filepath = fev["filepath"]
            if _is_system_lib(filepath):
                continue
            file_id = f"file:{filepath}"
            graph.add_node(
                file_id, "File",
                path=filepath,
                basename=os.path.basename(filepath),
                extension=os.path.splitext(filepath)[1],
                access_count=fev["count"],
                flags=fev["flags"],
            )
            # 累计访问次数
            existing = graph.nodes.get(file_id, {})
            if "access_count" in existing:
                graph.nodes[file_id]["access_count"] = (
                    existing["access_count"] + fev["count"]
                )

            if exec_ev:
                proc_id = f"process:{pid}"
                graph.add_edge(
                    proc_id, file_id, "PROCESS_ACCESSES",
                    timestamp=fev["timestamp"],
                    count=fev["count"],
                    flags=fev["flags"],
                )

        # curl 不再推断 Network 节点，仅保留为 Process。
        # 真实的 Network 节点将由下方的 http_parser 事件来构建。

    # ── 解析 http_parser 事件 → 真实 Network 节点 ────────────────────
    # source == "http_parser" 且 data.message_type == "request" 的记录
    # 包含完整的 HTTP 请求信息（host/url/method/headers/body）
    # 对应的 pid 就是发起请求的进程
    for ev in events:
        if ev.get("source") != "http_parser":
            continue
        data = ev.get("data", {})
        if data.get("message_type") != "request":
            continue

        pid = ev.get("pid")
        ts = _ts_ms(ev.get("timestamp", 0))
        headers = data.get("headers", {})
        host = headers.get("host") or headers.get("Host") or "unknown"
        path = data.get("path", "/")
        protocol_line = data.get("protocol", "HTTP/1.1")
        original_source = data.get("original_source", "")
        method = data.get("method", "GET")
        protocol = "https" if original_source == "ssl" else "http"
        url = f"{protocol}://{host}{path}"

        net_id = f"network:{host}"
        graph.add_node(
            net_id, "Network",
            host=host,
            url=url,
            protocol=protocol,
            method=method,
            path=path,
            inferred=False,
            inferred_from_pid=pid,
        )

        # Process → Network
        if pid is not None:
            proc_id = f"process:{pid}"
            if proc_id in graph.nodes:
                graph.add_edge(
                    proc_id, net_id, "PROCESS_CONNECTS",
                    timestamp=ts,
                    method=method,
                    url=url,
                    inferred=False,
                )

    # ── 时间窗口匹配：Tool → Process / File / Network ────────────────────
    #
    # 策略：对每个 toolCall，取 [called_at, data_timestamp] 时间窗口，
    # 其中 data_timestamp 是对应 Data 节点的 timestamp（工具返回时刻），
    # 寻找在该窗口内 EXEC 的进程；对这些进程的文件访问也关联到 tool。
    #
    for tc_id, tc in tool_call_map.items():
        tool_node_id = tc["tool_node_id"]
        called_at = tc["called_at"] or 0
        tc_name = tc["tool_name"]
        tc_args = tc["tool_args"]

        # 获取对应 Data 节点的 timestamp 作为时间窗口上界
        data_node = graph.nodes.get(f"data:{tc_id}")
        data_ts = data_node.get("timestamp", 0) if data_node else 0
        # 如果 Data 节点没有 timestamp，回退到 result_at
        window_end = data_ts if data_ts else (tc["result_at"] or called_at)

        # 提取 URL（从 exec/exec_with 工具的 command 参数）
        urls = _extract_urls_from_args(tc_args)

        for pid, (start_ts, end_ts) in pid_time_range.items():
            if start_ts is None:
                continue
            # 进程在 [called_at, data_timestamp] 窗口内启动
            if called_at <= start_ts <= window_end:
                pinfo = process_info.get(pid, {})
                exec_ev = pinfo.get("exec")
                if not exec_ev:
                    continue
                proc_id = f"process:{pid}"
                comm = exec_ev.get("comm", "")

                graph.add_edge(
                    tool_node_id, proc_id, "SPAWNS_PROCESS",
                    tool_call_id=tc_id,
                    time_delta_ms=start_ts - called_at,
                    timestamp=start_ts,
                )

                # 关联 Tool → File（通过该进程的文件访问，仅包含窗口内的）
                for fev in pinfo.get("files", []):
                    filepath = fev["filepath"]
                    if _is_system_lib(filepath):
                        continue
                    # 文件访问时间也必须在 [called_at, window_end] 内
                    fev_ts = fev.get("timestamp", 0)
                    if fev_ts and not (called_at <= fev_ts <= window_end):
                        continue
                    file_id = f"file:{filepath}"
                    graph.add_edge(
                        tool_node_id, file_id, "ACCESSES_FILE",
                        tool_call_id=tc_id,
                        time_delta_ms=fev_ts - called_at,
                        count=fev["count"],
                        timestamp=fev_ts,
                    )

                # 关联 Tool → Network（通过该进程已建立的 PROCESS_CONNECTS 边）
                for edge in graph.edges:
                    if edge["src"] == proc_id and edge["rel"] == "PROCESS_CONNECTS":
                        edge_ts = edge.get("timestamp", 0)
                        # 网络连接时间也必须在 [called_at, window_end] 内
                        if edge_ts and not (called_at <= edge_ts <= window_end):
                            continue
                        net_tgt = edge["dst"]
                        graph.add_edge(
                            tool_node_id, net_tgt, "CALLS_NETWORK",
                            tool_call_id=tc_id,
                            time_delta_ms=edge_ts - called_at if edge_ts else 0,
                            timestamp=edge_ts,
                        )

        # 直接文件路径匹配（read/write/edit 工具）
        # 从工具参数中提取 file_path
        file_path_keys = ["file_path", "path", "filepath", "filename", "file"]
        for k in file_path_keys:
            fp = tc_args.get(k)
            if fp and isinstance(fp, str) and not _is_system_lib(fp):
                file_id = f"file:{fp}"
                graph.add_node(
                    file_id, "File",
                    path=fp,
                    basename=os.path.basename(fp),
                    extension=os.path.splitext(fp)[1],
                )
                graph.add_edge(
                    tool_node_id, file_id, "ACCESSES_FILE",
                    tool_call_id=tc_id,
                    direct=True,       # 直接从 tool args 获取（非时间窗口推断）
                    timestamp=called_at,
                )
                break


# ─────────────────────────────────────────────────────────────────────────────
# Minimax 聚类：对 Task 下的 Tool 调用进行语义分组，生成 SubTask 节点
# ─────────────────────────────────────────────────────────────────────────────

def _call_minimax_cluster(tools_info: List[dict], api_key: str) -> List[dict]:
    """
    调用 Minimax 模型对工具调用列表进行语义聚类。

    参数:
        tools_info: [{"index": int, "name": str, "arguments_summary": str}, ...]
        api_key: Minimax API Key

    返回:
        [{"label": "子任务描述", "input_task": "对子任务的总结", "tool_indices": [0, 1, 2]}, ...]
    """
    client = OpenAI(
        base_url="https://api.minimaxi.com/v1",
        api_key=api_key,
    )

    tools_desc_lines = []
    for t in tools_info:
        tools_desc_lines.append(
            f"  [{t['index']}] tool={t['name']}, args={t['arguments_summary']}"
        )
    tools_desc = "\n".join(tools_desc_lines)

    prompt = (
        "你是一个任务分析助手。下面是一个 AI Agent 在执行过程中依次调用的工具列表。"
        "请根据工具的名称和参数，将这些工具调用按语义分组为若干子任务簇。"
        "每个簇应该代表一个有意义的子任务（例如：'读取配置文件'、'执行数据查询脚本'、'写入报告'等）。\n\n"
        f"工具调用列表:\n{tools_desc}\n\n"
        "请严格按照以下 JSON 格式输出，不要包含任何其他文字：\n"
        '[{"label": "子任务简短标签", "input_task": "用一两句话总结该子任务的具体目标和操作内容", "tool_indices": [0, 1]}, ...]\n'
        "其中 tool_indices 是上面列表中工具的 index 编号。每个工具必须且只能属于一个簇。"
        "label 是子任务的简短标签名，input_task 是对该子任务目标的总结性描述。"
    )

    response = client.chat.completions.create(
        model="MiniMax-Text-01",
        messages=[
            {"role": "system", "content": "你是一个精确的任务分析助手，只输出 JSON。"},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
    )

    result_text = response.choices[0].message.content.strip()
    # 去掉可能的 markdown 代码块标记
    if result_text.startswith("```"):
        lines = result_text.split("\n")
        # 去掉首行 ```json 和末行 ```
        lines = [l for l in lines if not l.strip().startswith("```")]
        result_text = "\n".join(lines)

    clusters = json.loads(result_text)
    return clusters


def cluster_tools_to_subtasks(graph: Graph, api_key: str):
    """
    遍历图中每个 Task 节点，收集其直接 CALLS 的 Tool 节点，
    调用 Minimax 模型进行语义聚类，为每个簇创建一个新的 SubTask 节点，
    将原来的 Task->Tool 边替换为 Task->SubTask->Tool。
    """
    # 收集每个 task_id 对应的 CALLS 边
    task_tool_edges: Dict[str, List[dict]] = defaultdict(list)
    for edge in graph.edges:
        if edge["rel"] == "CALLS":
            task_tool_edges[edge["src"]].append(edge)

    # 只处理有 Tool 调用的 Task
    for task_id, calls_edges in task_tool_edges.items():
        task_node = graph.nodes.get(task_id)
        if not task_node or task_node.get("type") != "Task":
            continue

        # 如果该 Task 只有 0 个 tool，跳过
        if len(calls_edges) == 0:
            continue

        # 按 call_order 排序
        calls_edges_sorted = sorted(calls_edges, key=lambda e: e.get("call_order", 0))

        # 收集工具信息用于发送给 Minimax
        tools_info = []
        tool_node_ids = []
        for idx, edge in enumerate(calls_edges_sorted):
            tool_node_id = edge["dst"]
            tool_node = graph.nodes.get(tool_node_id, {})
            tool_name = tool_node.get("name", "unknown")
            tool_args = tool_node.get("arguments", {})
            # 生成参数摘要（限制长度避免 token 过多）
            args_str = json.dumps(tool_args, ensure_ascii=False)
            if len(args_str) > 200:
                args_str = args_str[:200] + "..."
            tools_info.append({
                "index": idx,
                "name": tool_name,
                "arguments_summary": args_str,
            })
            tool_node_ids.append(tool_node_id)

        # 调用 Minimax 聚类
        print(f"  🔄 对 {task_id} 的 {len(tools_info)} 个工具调用进行聚类...")
        clusters = _call_minimax_cluster(tools_info, api_key)
        print(f"     → 生成 {len(clusters)} 个子任务簇")

        # 从图中移除原有的 CALLS 边（Task -> Tool）
        original_calls = {(e["src"], e["dst"], e["rel"]) for e in calls_edges_sorted}
        graph.edges = [e for e in graph.edges if (e["src"], e["dst"], e["rel"]) not in original_calls]
        graph._edge_set -= original_calls

        # 为每个簇创建 SubTask 节点和新边
        for cluster_idx, cluster in enumerate(clusters):
            label = cluster["label"]
            input_task = cluster.get("input_task", label)
            indices = cluster["tool_indices"]

            subtask_id = f"subtask:{task_id}:{cluster_idx}"

            # 计算子任务的时间范围（从簇中工具的时间推断）
            cluster_tool_ids = [tool_node_ids[i] for i in indices if i < len(tool_node_ids)]
            start_times = []
            end_times = []
            for tid in cluster_tool_ids:
                tnode = graph.nodes.get(tid, {})
                if tnode.get("called_at"):
                    start_times.append(tnode["called_at"])
                if tnode.get("result_at"):
                    end_times.append(tnode["result_at"])

            subtask_started = min(start_times) if start_times else None
            subtask_ended = max(end_times) if end_times else None

            # 收集本簇内所有工具的 Data 返回内容，合并为 received_returns
            cluster_tc_ids = set()
            for tid in cluster_tool_ids:
                tnode = graph.nodes.get(tid, {})
                tc_id = tnode.get("tool_call_id", "")
                if tc_id:
                    cluster_tc_ids.add(tc_id)

            cluster_returns = []
            for tc_id in cluster_tc_ids:
                data_node_id = f"data:{tc_id}"
                data_node = graph.nodes.get(data_node_id)
                if data_node and data_node.get("content"):
                    cluster_returns.append(data_node["content"])
            combined_returns = "\n---\n".join(cluster_returns) if cluster_returns else None

            # 创建 SubTask 节点（与普通 Task 节点字段保持一致）
            graph.add_node(
                subtask_id,
                "Task",
                session_key=task_node.get("session_key"),
                session_id=task_node.get("session_id"),
                label=label,
                task_type="generated",
                spawned_by=task_node.get("label", task_id),
                input_task=input_task,
                received_returns=combined_returns,
                started_at=subtask_started,
                ended_at=subtask_ended,
            )

            # Task -> SubTask (SPAWNS)
            graph.add_edge(
                task_id, subtask_id, "SPAWNS",
                timestamp=subtask_started,
                cluster_label=label,
            )

            # SubTask -> Tool (CALLS)
            for order, tid in enumerate(cluster_tool_ids, start=1):
                original_edge = None
                for e in calls_edges_sorted:
                    if e["dst"] == tid:
                        original_edge = e
                        break
                graph.add_edge(
                    subtask_id, tid, "CALLS",
                    timestamp=original_edge.get("timestamp") if original_edge else subtask_started,
                    call_order=order,
                )

            # Data -> SubTask (CONSUMES): 将原本指向 task_id 的 CONSUMES 边
            # 中属于本簇 tool 的 Data 改为指向 subtask_id
            for edge in graph.edges:
                if (edge["rel"] == "CONSUMES"
                        and edge["dst"] == task_id
                        and edge["src"].startswith("data:")):
                    data_tc_id = edge["src"].replace("data:", "")
                    if data_tc_id in cluster_tc_ids:
                        edge["dst"] = subtask_id


# ─────────────────────────────────────────────────────────────────────────────
# 主流程
# ─────────────────────────────────────────────────────────────────────────────

def build_graph(sessions_dir: str, output_json: str) -> Graph:
    graph = Graph()

    # 读取 .env 文件到环境
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    env_path = os.path.join(project_root, ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

    # 读取 Minimax API Key
    api_key = os.environ.get("MINIMAX_API_KEY", "")
    assert api_key, (
        "请设置环境变量 MINIMAX_API_KEY，或配置在 .env 文件中，"
        "可从 https://platform.minimax.io/ 获取"
    )

    print(f"[1/5] 加载 sessions 目录: {sessions_dir}")
    sessions = load_sessions(sessions_dir)
    sessions_meta = load_sessions_meta(sessions_dir)
    print(f"      发现 {len(sessions)} 个 session 文件，"
          f"{len(sessions_meta)} 条 session 元数据")

    print(f"[2/5] 解析 sessions，构建 Task/User/Tool/Data 节点...")
    tool_call_map = parse_sessions(sessions, sessions_meta, graph)
    print(f"      工具调用数: {len(tool_call_map)}")

    print(f"[3/5] 调用 Minimax 模型对 Tool 调用进行聚类，生成 SubTask 节点...")
    cluster_tools_to_subtasks(graph, api_key)

    if os.path.exists(output_json):
        print(f"[4/5] 加载系统层事件: {output_json}")
        events = load_output_events(output_json)
        print(f"      共 {len(events)} 条事件")

        print(f"[5/5] 解析系统层事件，构建 Process/File/Network 节点...")
        parse_output_events(events, tool_call_map, graph)
    else:
        print(f"[4/5] 跳过系统层事件（文件不存在: {output_json}）")

    stats = graph.to_dict()["stats"]
    print(f"\n✅ 图构建完成:")
    print(f"   节点数: {stats['node_count']}")
    print(f"   边数:   {stats['edge_count']}")
    print(f"   节点类型分布: {stats['node_types']}")
    print(f"   边类型分布:   {stats['edge_types']}")

    return graph


def main():
    # 默认路径：相对于本文件所在目录的上级（即项目根）
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    default_sessions = os.path.join(project_root, "logs", "sessions")
    default_output = os.path.join(project_root, "logs", "output.json")
    default_out = os.path.join(project_root, "logs", "graph.json")

    parser = argparse.ArgumentParser(
        description="将 OpenClaw 日志构建成图（节点+边）"
    )
    parser.add_argument("--sessions-dir", default=default_sessions,
                        help=f"sessions JSONL 目录（默认: {default_sessions}）")
    parser.add_argument("--output-json", default=default_output,
                        help=f"系统层 output.json 路径（默认: {default_output}）")
    parser.add_argument("--out", default=default_out,
                        help=f"输出图文件路径（默认: {default_out}）")
    parser.add_argument("--format", choices=["json"], default="json",
                        help="输出格式（默认: json）")
    args = parser.parse_args()

    graph = build_graph(args.sessions_dir, args.output_json)

    out_path = args.out
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(graph.to_dict(), f, ensure_ascii=False, indent=2)

    print(f"\n💾 图已保存到: {out_path}")


if __name__ == "__main__":
    main()

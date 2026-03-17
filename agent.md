# 面向智能体应用的多层攻击检测方案

## 1. 背景与问题定义

1. 新一代 Agent 系统，例如 OpenClaw 一类的智能体运行框架，已经不再是“单轮问答模型”，而是具备如下复合能力的**自治执行系统**：

   - **会规划**：能够根据用户目标拆解任务、生成中间步骤、调度子 Agent、循环反思并继续执行。
   - **会调用工具**：能够访问本地 shell、文件系统、浏览器、网络接口、数据库、Python 解释器等外部能力。
   - **有持久状态**：具备上下文缓存、长期记忆、工具配置、认证信息与环境变量。
   - **可扩展技能**：在 Skills 生态中，能力可通过 `SKILL.md` 描述并以目录或插件形式注入运行环境，技能内部还可能包含可执行脚本或依赖。

   这类系统的攻击面显著区别于传统 Web 应用或单模型推理服务。其风险不只来自“输入内容恶意”，更来自：

   1. **意图层污染**：攻击者通过 Prompt Injection、上下文污染、记忆投毒等方式改变 Agent 的中间规划；
   2. **调用层劫持**：攻击者诱导 Agent 选择不应被调用的工具，或在调用时污染参数；
   3. **执行层逸出**：工具表面上声明良性，但真实落地到 OS/文件/网络层时执行了与任务无关甚至恶意的操作。

   因此，仅看**最终回答**，无法知道 Agent 是否在中间做了越权行为；仅看**系统日志**，又无法恢复“为什么调用这个工具、这个行为是否符合任务语义”；单步调用往往看似合理，但**多步串联之后才显现攻击意图**。

   基于此，本文提出一套面向智能体应用的**多层观测、多层关联、多层规则检测框架**，同时覆盖：

   - **计划层（Planning Layer）**：Agent 的任务理解、拆分与意图演化；
   - **调用层（Tool Invocation Layer）**：工具调用链、参数、返回值与调用上下文；
   - **系统执行层（System Execution Layer）**：进程、文件、网络等真实行为。

   核心目标是解决：
    **如何把“任务语义”与“真实系统行为”建立因果关联，从而检测多阶段、跨层次的 Agent 攻击。**



## 2. 相关工作



## 3. 威胁模型与风险分析

### 3.1 威胁模型

假设攻击者可具备以下一种或多种能力：

- 向 Agent 输入恶意 Prompt、文档、网页内容或工具返回内容；
- 控制某个插件、Skill、第三方依赖或其描述文件；
- 污染记忆、缓存或跨 Agent 传递的中间信息；

不假设攻击者一定能够直接突破操作系统隔离，而是主要关注**通过 Agent 逻辑链条间接触发危险行为**。

### 3.2 风险分类

| **类别**                     | **节点名称**                                                 | **描述**                          |
| ---------------------------- | ------------------------------------------------------------ | --------------------------------- |
| 意图修改/组合攻击            | agent goal hijack、insecure communication、cascade、human trust | 改变 planning agent 的任务规划    |
| agent妥协                    | privilege abuse、memory poisoning、rogue agent、RCE          | agent被对手控制，错误的去调用工具 |
| 工具含有恶意逻辑或被错误利用 | tool misuse、supply chain                                    | 工具中包含恶意的代码逻辑          |



## 4. 三类检测规则

![](./Snipaste_2026-03-09_10-08-41.png)

### 规则 1：动态规划偏离检测

- **检测逻辑**：比对 **初始任务树** 与 **执行流图**。
- 当系统出现未在初始 Plan 中的 **Task_new** 时，计算该任务的语义与初始意图的相似度分数。在多步攻击当中，可能会创建若干个 **Task_new** ，如果 **Task_new** 持续在阈值附近，也会判断为攻击
- **异常场景**：
  - 某个子agent返回给planning agent要求新建一个 task_new下载带有病毒的安装包，planning agent对比原始任务并不需要下载额外的安装包，因此发出报警

### 规则 2：Agent 行为劫持检测 持续分析

- **检测逻辑**：对比**预期任务**与**工具调用链及其参数**
- `Task`节点缓存子任务，并且比对 `Task` 节点缓存的预期任务与 agent调用的工具和参数，如果工具或者工具的参数不符合预期则告警，`Agent→Task1→tool1 (arg) + Agent→Task2→tool2 (arg)` 对比 `task预期任务`
- **异常场景**：
  1. **功能越权**：一个被定义为 **Translator** 的子 Agent 在处理一段包含恶意指令的文本时，未执行翻译任务，而是向系统请求调用 **`Intranet_Scanner`** 工具。
  2. **参数污染**：**File_Reader（文件读取）** 子 Agent 收到了读取 `book.txt` 的合法任务。但在执行阶段，子 Agent 在调用底层 `read_file` 工具时，将参数 `filename` 篡改成了系统的敏感文件 `/etc/api_key.txt`。

### 规则 3：供应链/恶意工具检测 数据源

- **检测逻辑**：对比工具任务和实际执行情况。

- `task` 缓存工具描述和任务输入的参数，对比工具的描述、任务和从 `Tool` 出发的所有物理路径。

  `Tool → Process → File` 对比 `task预期任务`

- **异常场景**：

  - *示例*：一个 `Calculator` 工具启动了一个 `powershell.exe` 并尝试修改注册表。即使应用层的任务逻辑看起来正常，系统层捕获的这种不相符的操作即可判定该工具为**恶意供应链插件**。 

## 5. 任务语义表示

自然语言任务必须被结构化，否则很难自动比对。

### 5.1 任务表示格式

将任务抽取为：

- `Action Type`：资源访问 / 数据流转 / 系统变更 / 推理分析
- `Action`：read / list / search / write / delete / upload / execute / summarize
- `Object Type`：file / url / database / email / process / key / config
- `Object`：具体目标对象或对象集合

### 5.2 敏感对象抽取

| 大类     | 子类                                     | 示例                              |
| -------- | ---------------------------------------- | --------------------------------- |
| 身份隐私 | 姓名、邮箱、手机号、地址、账号标识       | `user@example.com`                |
| 凭据密钥 | API Key、Token、SSH Key、Session、Cookie | `sk-...`, `BEGIN RSA PRIVATE KEY` |
| 系统配置 | 环境变量、配置文件、内核/版本信息        | `.env`, `/etc/*`, registry        |
| 代码载荷 | shell/python/js/sql 脚本、反序列化数据   | `subprocess`, `eval`, base64 blob |
| 财务文件 | 银行账号、支付卡、交易流水、账单         | 16-19 位卡号、财务表              |
| 内部资源 | 内网地址、白名单外域名、内部 API、数据库 | `10.x.x.x`, corp domain           |



## 6. 观测层面与数据采集

### 6.1 三个观测表面

| 表面   | 描述               | 记录内容                                           | 作用                   |
| ------ | ------------------ | -------------------------------------------------- | ---------------------- |
| 计划层 | LLM 交互与规划摘要 | 原始任务、子任务、规划说明、反思摘要、角色信息     | 识别目标偏离、意图劫持 |
| 调用层 | 工具调用追踪       | 工具名、参数、返回值、调用者、调用上下文、工具声明 | 识别工具误用、参数污染 |
| 系统层 | 外部系统与 OS 行为 | 进程、文件、网络、DB/API I/O、环境访问             | 恢复真实执行路径       |

## 7. 图模型设计

## 7.1 节点定义

将节点分为三类：**逻辑主体、执行实体**。

| 类别     | 节点    | 描述                           | 关键字段                                                     |
| -------- | ------- | ------------------------------ | ------------------------------------------------------------ |
| 逻辑主体 | User    | 用户请求发起者                 | {"**record_type**":"node","**id**":"openclaw-tui","**node_type**":"User",**properties**":{} |
| 逻辑主体 | Agent   | Planner / Executor / Sub-agent | {"**record_type**":"node","**id**":"agent:main:main","**node_type**":"Agent","**properties**":{"session_id": "774a4b0c-09d0-4848-a595-dd317139c231", "config": {"provider": "qwen-portal", "model": "coder-model", "skills": ["feishu-doc", "feishu-drive", "feishu-perm", "feishu-wiki", "clawhub", "healthcheck", "mcporter", "oracle", "skill-creator", "tmux", "weather"], "tools": ["read", "edit", "write", "exec", "process", "browser", "canvas", "nodes", "message", "tts", "agents_list", "sessions_list", "sessions_history", "sessions_send", "sessions_spawn", "subagents", "session_status", "web_search", "web_fetch", "image", "pdf", "memory_search", "memory_get"]}}} |
| 逻辑主体 | Task    | 任务锚点，缓存预期目标与约束   | {"**record_type**":"node","**id**":"55c8fe55-aaab-4264-a261-b2c6b60208bd","**node_type**":"Task","**properties**":{"expected_goal":"读取 book.txt 并总结内容","return_result":[],  calling_chain":[]}} |
| 逻辑主体 | Tool    | 工具/skills                    | {"**record_type**":"node","**id**":"write_file","**node_type**":"Tool","**properties**":{"tool_name":"write_file","tool_desc":"写入文本到指定文件"}} |
| 执行实体 | Process | OS 进程                        | {"**record_type**":"node","**id**":"4201","**node_type**":"Process","**properties**":{{"comm":"python3","data":{"comm":"python3","event":"EXEC","filename":"/usr/bin/python3","full_command":"python3","pid":13520,"ppid":13417,"timestamp":1585457111542},"pid":13520,"source":"process","timestamp":1772866693457}}} |
| 执行实体 | File    | 文件/目录资源                  | {"**record_type**":"node","**id**":"file:f_book","**node_type**":"File","**properties**":{{"comm":"python3","data":{"comm":"python3","count":1,"event":"FILE_OPEN","filepath":"/etc/ld.so.cache","flags":524288,"pid":13520,"timestamp":1585458025846},"pid":13520,"source":"process","timestamp":1772866693458}}} |
| 执行实体 | SSL     | 网络端点                       | {"**record_type**":"node","**id**":"network:n_evil","**node_type**":"Network","**properties**":{{"comm":"python3","data":{"buf_size":696,"comm":"python3","data":"{\n  \"args\": {}, \n  \"data\": \"{\\\"model\\\": \\\"gpt-4\\\", \\\"messages\\\": [{\\\"role\\\": \\\"user\\\", \\\"content\\\": \\\"Exfiltrating data: MASCOPE_12345\\\"}]}\", \n  \"files\": {}, \n  \"form\": {}, \n  \"headers\": {\n   \"Accept\": \"*/*\", \n   \"Accept-Encoding\": \"gzip, deflate\", \n   \"Content-Length\": \"97\", \n   \"Content-Type\": \"application/json\", \n   \"Host\": \"httpbin.org\", \n   \"User-Agent\": \"python-requests/2.25.1\", \n   \"X-Amzn-Trace-Id\": \"Root=1-69abd0d5-2208bfcd3d0f3e542d4a2047\"\n  }, \n  \"json\": {\n   \"messages\": [\n    {\n     \"content\": \"Exfiltrating data: MASCOPE_12345\", \n     \"role\": \"user\"\n    }\n   ], \n   \"model\": \"gpt-4\"\n  }, \n  \"origin\": \"188.253.121.54\", \n  \"url\": \"https://httpbin.org/post\"\n}\n","function":"READ/RECV","is_handshake":false,"latency_ms":0.033,"len":696,"pid":14496,"tid":14496,"timestamp_ns":2689703227465,"truncated":false,"uid":1000},"pid":14496,"source":"ssl","timestamp":1772867797703}}} |

### 7.2 边定义

#### A. 应用层关系

- `User → Agent`：用户给main agent发布任务

{"**record_type**":"edge","**id**":"e_001","**edge_type**":"USER_TO_AGENT","**src**":"openclaw-tui","**dst**":"agent:main:main","**properties**":{"raw_task":"读取 book.txt 并总结内容","result":"已完成 book.txt 的总结，并写入 /workspace/output/summary.txt"},"**timestamp**":"2026-03-06T21:00:00Z"}

- `Agent → Task`：把main agent派发给sub agent的任务在task节点做一个缓存，以及缓存sub agent返回的消息/如果是sub agent，则缓存发给tool的消息

{"**record_type**":"edge","**id**":"e_002","**edge_type**":"AGENT_TO_TASK","**src**":"agent:main:12345461242362","**dst**":"read_file","**properties**":{"expected_goal":"读取 book.txt 并总结内容","result":"已完成 book.txt 的总结，并写入 /workspace/output/summary.txt"},"timestamp":"2026-03-06T21:00:05Z"}

{"**record_type**":"edge","**id**":"e_003","**edge_type**":"AGENT_TO_TASK","**src**":"agent:main:main","**dst**":"55c8fe55-aaab-4264-a261-b2c6b60208bd","**properties**":{"tool_calls": [{"name": "write","arguments": {"path": "~/Desktop/calculator.py", "content": "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n\"\"\"\n},"result": "Successfully wrote 2131 bytes to ~/Desktop/calculator.py"}]},"timestamp":"2026-03-06T21:00:05Z"}

- `Task → Agent`：把任务派发给sub agent

{"**record_type**":"edge","**id**":"e_004","**edge_type**":"TASK_TO_AGENT","**src**":"55c8fe55-aaab-4264-a261-b2c6b60208bd","**dst**":"agent:a_root","**properties**":{"task":"读取 book.txt 并总结内容"，"result":"已完成 book.txt 的总结，并写入 /workspace/output/summary.txt"},"timestamp":"2026-03-06T21:00:03Z"}

- `Task → Tool`：执行工具

{"**record_type**":"edge","**id**":"e_005","**edge_type**":"TASK_TO_TOOL","**src**":"task:t_read","**dst**":"tool:read_file","**properties**":{"tool_calls": [{"name": "write","arguments": {"path": "~/Desktop/calculator.py", "content": "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n\"\"\"\n},"result": "Successfully wrote 2131 bytes to ~/Desktop/calculator.py"}]},"timestamp":"2026-03-06T21:00:03Z"}

#### B. 系统层关系

- `Tool → Process`：该工具触发的入口进程

{"**record_type**":"edge","**id**":"e_006","**edge_type**":"TOOL_TO_PROCESS","**src**":"read_file","**dst**":"process:p_4202","properties":{"call_id":"call_001","spawned":true,"entrypoint":"subprocess"},"timestamp":"2026-03-06T21:00:03Z"}

- `Process → Process`：进程派生

{"record_type":"edge","id":"e_012","edge_type":"PROCESS_TO_PROCESS","src":"process:p_4201","dst":"process:p_4202","layer":"system","properties":{"relation":"spawn","cmdline":"cat /workspace/book.txt"},"timestamp":"2026-03-06T21:00:03Z"}

- `Process → File`：进程进行物理文件操作

{"record_type":"edge","id":"e_013","edge_type":"PROCESS_TO_FILE","src":"process:p_4202","dst":"file:f_book","layer":"system","properties":{"operation":"read","bytes":18432,"result":"success"},"timestamp":"2026-03-06T21:00:03Z"}

- `Process → Network`：进程进行网络连接

{"record_type":"edge","id":"e_015","edge_type":"PROCESS_TO_NETWORK","src":"process:p_4203","dst":"network:n_evil","layer":"system","properties":{"operation":"connect","bytes_out":1024,"bytes_in":256,"result":"success"},"timestamp":"2026-03-06T21:00:07Z"}

- `Tool → File`：工具直接进行文件访问

{"record_type":"edge","id":"e_010","edge_type":"TOOL_TO_FILE","src":"tool:write_file","dst":"file:f_summary","layer":"system","properties":{"operation":"write","bytes":512,"result":"success"},"timestamp":"2026-03-06T21:00:05Z"}

- `Tool → Network`：工具直接发起网络访问

{"record_type":"edge","id":"e_011","edge_type":"TOOL_TO_NETWORK","src":"tool:http_post","dst":"network:n_evil","layer":"system","properties":{"operation":"connect","method":"POST","result":"success"},"timestamp":"2026-03-06T21:00:07Z"}

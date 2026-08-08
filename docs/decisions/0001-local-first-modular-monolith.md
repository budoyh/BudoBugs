# ADR 0001：本地优先模块化单体

状态：已接受

## 决策

核心采用 Python 3.12 模块化单体：Pydantic v2 Schema、SQLAlchemy/SQLite
物化状态、JSONL 不可变事件、Typer CLI、Rich/Textual UI。外部扫描器、代理、
浏览器与 AI 框架以适配器连接。

## 理由

授权漏洞研究需要断点续跑、证据追溯和本地秘密边界；微服务会增加部署、网络、
一致性和审计面。单体仍按 models/storage/policy/tools/traffic/validation/evidence/
reporting 分层，后续可在明确性能边界处拆分。

## 后果

SQLite 是单机协调器的默认数据库，不承诺多主写入。大型第三方框架不会污染
core 依赖。

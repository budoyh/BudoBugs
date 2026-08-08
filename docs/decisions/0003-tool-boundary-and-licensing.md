# ADR 0003：工具边界与许可证隔离

状态：已接受

## 决策

所有工具由 YAML registry 声明能力、许可、版本、网络、变更、资源、模式、并发、
超时、解析器和脱敏规则。执行器只使用参数向量且在运行前注入当前 engagement
target。GPL/AGPL、商业软件和大规模 lab-ai 框架位于进程/容器边界；
NOASSERTION 项目不纳入。

## 理由

任意 shell 拼接会把不可信目标内容升级为执行指令；直接混入强 copyleft 或商业
代码会产生不可控分发义务。

## 后果

适配器完整度与第三方软件实际可用状态分开报告。缺 GUI、token、license 或
container runtime 时，healthcheck 返回准确的需要项。

# ADR 0002：证据门由制品推导

状态：已接受

## 决策

候选状态不能由 agent、工具或调用方直接设置为通过。executor 生成含 run id、
命令参数向量、退出码、时间、输入/输出制品引用和观测的收据；Evidence Gate
重新读取制品并计算 A-I 结果。只有所有必需门通过且独立 critic 为 CONFIRMED，
finding 才能进入人工复核报告。

## 理由

强提示词不能防止 self-reported pass、ghost run、stale artifact 或 demo/formal
混用。状态必须绑定可重复检查的现实制品。

## 后果

失败测试和负结果也保留；缺少外部运行时产生 blocked receipt，而不是伪造成功。

# WebAttacker_Agent
## 1. 简介
1. WebAttacker_Agent 是一个使用 Claude Code 编写的，基于 Java SpringAI Alibaba 的，多 Agent 联合的 Web 渗透测试系统。

## 暂时性成果
1. 经过几轮测试，目前主要的渗透功能初见雏形，报告请看 [WebAttacker_Agent 渗透测试报告](2766f613-8fe6-4c18-a619-f22230fa229b_20260415_170147.md)。即项目下的 2766f613-8fe6-4c18-a619-f22230fa229b_20260415_170147.md 文件。

## 项目架构

## 与 AI 交互的流程总结


## TODO
- [ ] 比较烧 token，qwen-plus 直接干掉 50k token，后续需要优化模型的使用，减少不必要的调用。
- [ ] 目标完成后上下文压缩
- [ ] 计划减少模型可使用的扫描工具数量，减少模型的选择范围，降低模型的决策难度。
- [ ] SSE 功能还没有打通。
- [ ] 持久化存储还未实现，目前数据存放在 Redis 当中。
- [ ] 还未测试 ElasticSearch 的功能。

## 参考
1. https://github.com/yhy0/CHYing-agent
2. https://github.com/lzy756/pen-agents?tab=readme-ov-file
package com.endlessshw.webattacker_agent.config;

import com.alibaba.cloud.ai.dashscope.chat.DashScopeChatOptions;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 分层 LLM 配置
 *
 * 4 个 ChatClient Bean，分别对应 4 个 Agent 角色：
 * - decisionChatClient  → qwen-max（高质量规划 + 顾问模式）
 * - infoChatClient      → qwen-plus（信息收集，快速工具调用）
 * - attackChatClient    → qwen-plus（主攻手，快速工具调用）
 * - reportChatClient    → qwen-long（报告撰写，长文本生成）
 */
@Configuration
public class DashScopeModelConfig {

    @Value("${app.llm.decision-model:qwen-max}")
    private String decisionModel;

    @Value("${app.llm.info-model:qwen-plus}")
    private String infoModel;

    @Value("${app.llm.attack-model:qwen-plus}")
    private String attackModel;

    @Value("${app.llm.report-model:qwen-long}")
    private String reportModel;

    /**
     * 决策 Agent 的 ChatClient（qwen-max）
     * 职责：规划下一步行动 + 顾问模式（应对下游 Agent 的求助）
     */
    @Bean("decisionChatClient")
    public ChatClient decisionChatClient(ChatModel chatModel) {
        return ChatClient.builder(chatModel)
                .defaultOptions(DashScopeChatOptions.builder()
                        .withModel(decisionModel)
                        .build())
                .build();
    }

    /**
     * 信息收集 Agent 的 ChatClient（qwen-plus）
     * 职责：端口扫描、服务识别、Web 指纹等信息收集
     */
    @Bean("infoChatClient")
    public ChatClient infoChatClient(ChatModel chatModel) {
        return ChatClient.builder(chatModel)
                .defaultOptions(DashScopeChatOptions.builder()
                        .withModel(infoModel)
                        .build())
                .build();
    }

    /**
     * 主攻手 Agent 的 ChatClient（qwen-plus）
     * 职责：漏洞利用、渗透攻击
     */
    @Bean("attackChatClient")
    public ChatClient attackChatClient(ChatModel chatModel) {
        return ChatClient.builder(chatModel)
                .defaultOptions(DashScopeChatOptions.builder()
                        .withModel(attackModel)
                        .build())
                .build();
    }

    /**
     * 报告撰写 Agent 的 ChatClient（qwen-long）
     * 职责：生成结构化 Markdown 渗透测试报告
     */
    @Bean("reportChatClient")
    public ChatClient reportChatClient(ChatModel chatModel) {
        return ChatClient.builder(chatModel)
                .defaultOptions(DashScopeChatOptions.builder()
                        .withModel(reportModel)
                        .build())
                .build();
    }
}

package com.endlessshw.webattacker_agent.tools.mcp;

import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;
import java.util.List;

/**
 * MCP 客户端配置
 *
 * 仅搭建客户端基础设施，不实现 MCP 服务器。
 * 当 MCP 被启用时（spring.ai.mcp.client.enabled=true），
 * Spring AI 会自动注入所有已注册的 MCP ToolCallback Bean。
 *
 * 用法：
 * 1. 在 application.yaml 中配置 spring.ai.mcp.client.servers
 * 2. 将注入的 mcpToolCallbacks 传入 ChatClient.prompt().tools(...)
 */
@Slf4j
@Configuration
public class McpClientConfig {

    /**
     * 聚合所有 MCP 工具回调
     *
     * Spring AI MCP Client 会自动注册来自各 MCP 服务器的 ToolCallback Bean。
     * 此 Bean 将它们收集为列表，供 InfoGatheringNode 和 AttackerNode 注入使用。
     *
     * 如果 MCP 未启用或无服务器配置，则返回空列表（不影响启动）。
     */
    @Bean("mcpToolCallbacks")
    public List<ToolCallback> mcpToolCallbacks(
            @Autowired(required = false) List<ToolCallback> autoRegisteredCallbacks) {
        if (autoRegisteredCallbacks == null || autoRegisteredCallbacks.isEmpty()) {
            log.info("[McpClientConfig] 无 MCP 工具已注册（MCP 未启用或无服务器配置）");
            return Collections.emptyList();
        }
        log.info("[McpClientConfig] 已加载 {} 个 MCP 工具", autoRegisteredCallbacks.size());
        return autoRegisteredCallbacks;
    }
}

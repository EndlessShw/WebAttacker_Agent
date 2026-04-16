package com.endlessshw.webattacker_agent.agent.node;

import com.alibaba.cloud.ai.graph.OverAllState;
import com.alibaba.cloud.ai.graph.action.AsyncNodeAction;
import com.endlessshw.webattacker_agent.agent.state.PentestStateKeys;
import com.endlessshw.webattacker_agent.model.Finding;
import com.endlessshw.webattacker_agent.model.PentestLog;
import com.endlessshw.webattacker_agent.rag.RagService;
import com.endlessshw.webattacker_agent.service.log.LogStore;
import com.endlessshw.webattacker_agent.tools.docker.DockerCommandTool;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * 信息收集 Agent 节点（InfoGatheringNode）
 *
 * 职责：
 * - 从 RAG 加载约束规则（按 targetEnvironment 过滤）
 * - 注入 DecisionNode 给出的策略建议
 * - 调用 DockerCommandTool 执行 nmap / nikto / ffuf 等工具
 * - 工具调用循环直到 LLM 停止发起工具调用
 * - 遇到困境时设置 requestAdvisorHelp=true 求助 DecisionNode
 * - 将所有发现追加到 infoFindings
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class InfoGatheringNode {

    private static final Executor VIRTUAL = Executors.newVirtualThreadPerTaskExecutor();

    private static final String PHASE = "info_gathering";
    private static final int MAX_TOOL_CALLS = 15;

    @Qualifier("infoChatClient")
    private final ChatClient infoChatClient;

    private final DockerCommandTool dockerCommandTool;
    private final RagService ragService;
    private final LogStore logStore;

    public AsyncNodeAction action() {
        return state -> CompletableFuture.supplyAsync(() -> execute(state), VIRTUAL);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> execute(OverAllState state) {
        String targetUrl = (String) state.value(PentestStateKeys.TARGET_URL, "");
        String targetEnv = (String) state.value(PentestStateKeys.TARGET_ENVIRONMENT, "test");
        String description = (String) state.value(PentestStateKeys.DESCRIPTION, "");
        String suggestion = state.<String>value(PentestStateKeys.DECISION_SUGGESTION).orElse(null);
        List<Finding> existingFindings = state.<List<Finding>>value(PentestStateKeys.INFO_FINDINGS, List.of());
        int iterationCount = (int) state.value(PentestStateKeys.ITERATION_COUNT, 0);

        log.info("[InfoGatheringNode] 开始信息收集，目标: {}, iteration={}", targetUrl, iterationCount);

        // 1. 从 RAG 获取约束规则
        List<String> constraints = ragService.retrieveConstraints(targetEnv, PHASE);
        // 2. 从 RAG 获取目标文档
        String taskId = (String) state.value(PentestStateKeys.TASK_ID, "");
        List<String> targetDocs = ragService.retrieveTargetDocs(taskId, targetUrl);

        // 3. 构建 System Prompt
        String systemPrompt = buildSystemPrompt(targetUrl, targetEnv, description,
                constraints, targetDocs, suggestion, existingFindings);

        // 4. 工具调用
        List<Finding> newFindings = new ArrayList<>();
        List<Message> messages = new ArrayList<>();
        messages.add(new UserMessage(buildUserPrompt(targetUrl, existingFindings)));

        boolean requestHelp = false;
        String helpContext = null;
        int consecutiveFailures = (int) state.value(PentestStateKeys.CONSECUTIVE_FAILURES, 0);

        // 记录节点启动日志
        saveLog(taskId, "INFO", "开始信息收集，目标: " + targetUrl + ", iteration=" + iterationCount, null, null, null);

        // 设置工具上下文，使 DockerCommandTool 能将每次命令执行记录到当前任务日志
        DockerCommandTool.setToolContext(taskId, PHASE);
        try {
            // 直接传入 Bean 对象，Spring AI 自动扫描 @Tool 方法
            ChatResponse response = infoChatClient.prompt()
                    .system(systemPrompt)
                    .messages(messages)
                    .tools(dockerCommandTool)
                    .call()
                    .chatResponse();

            String content = response.getResult().getOutput().getText();
            log.debug("[InfoGatheringNode] LLM 初始响应（前200字）: {}",
                    content != null ? content.substring(0, Math.min(200, content.length())) : "null");

            // 记录 LLM 最终响应（截断避免日志过大）
            String logContent = content != null
                    ? content.substring(0, Math.min(2000, content.length()))
                    : "(无输出)";
            saveLog(taskId, "INFO", "信息收集 LLM 分析完成", "llm_response", null, logContent);

            // 处理工具调用（Spring AI 自动执行工具并返回最终文本）
            // 解析结果中的发现
            Finding finding = parseFinding(content, PHASE);
            if (finding != null) {
                newFindings.add(finding);
                if (finding.isSuccess()) {
                    consecutiveFailures = 0;
                } else {
                    consecutiveFailures++;
                }
                saveLog(taskId, finding.isSuccess() ? "INFO" : "WARN",
                        "发现: " + finding.getSummary(), "finding", null, null);
            } else {
                // 无法解析也算 partial 成功
                String summary = content != null ? content.substring(0, Math.min(500, content.length())) : "无输出";
                newFindings.add(Finding.builder()
                        .phase(PHASE)
                        .toolName("info_gathering")
                        .summary(summary)
                        .success(true)
                        .timestamp(Instant.now())
                        .build());
                consecutiveFailures = 0;
            }

            // 检查是否请求顾问帮助
            if (content != null && content.contains("[REQUEST_ADVISOR_HELP]")) {
                requestHelp = true;
                helpContext = extractHelpContext(content);
                log.info("[InfoGatheringNode] Agent 请求顾问帮助: {}", helpContext);
                saveLog(taskId, "WARN", "请求顾问帮助: " + helpContext, null, null, null);
            }

        } catch (Exception e) {
            log.error("[InfoGatheringNode] LLM 调用失败", e);
            consecutiveFailures++;
            newFindings.add(Finding.builder()
                    .phase(PHASE)
                    .toolName("error")
                    .summary("LLM 调用失败: " + e.getMessage())
                    .success(false)
                    .timestamp(Instant.now())
                    .build());
            saveLog(taskId, "ERROR", "LLM 调用失败: " + e.getMessage(), null, null, null);

            if (consecutiveFailures >= 3) {
                requestHelp = true;
                helpContext = "信息收集连续失败 " + consecutiveFailures + " 次，最后错误: " + e.getMessage();
            }
        } finally {
            DockerCommandTool.clearToolContext();
        }

        saveLog(taskId, "INFO",
                "信息收集完成，新发现 " + newFindings.size() + " 条，连续失败 " + consecutiveFailures + " 次",
                null, null, null);

        return buildResult(newFindings, consecutiveFailures, requestHelp, helpContext);
    }

    private void saveLog(String taskId, String level, String message,
                         String toolName, String toolInput, String toolOutput) {
        if (taskId == null || taskId.isBlank()) return;
        logStore.save(PentestLog.builder()
                .taskId(taskId)
                .agentName("InfoGatheringNode")
                .phase(PHASE)
                .level(level)
                .message(message)
                .toolName(toolName)
                .toolInput(toolInput)
                .toolOutput(toolOutput)
                .build());
    }

    @SuppressWarnings("unchecked")
    private String buildSystemPrompt(String targetUrl, String targetEnv, String description,
                                      List<String> constraints, List<String> targetDocs,
                                      String suggestion, List<Finding> existingFindings) {
        StringBuilder sb = new StringBuilder();
        sb.append("你是一名专业的 Web 渗透测试信息收集专家。\n\n");
        sb.append("## 目标信息\n");
        sb.append("- 目标 URL: ").append(targetUrl).append("\n");
        sb.append("- 环境类型: ").append(targetEnv).append("\n");
        if (!description.isBlank()) {
            sb.append("- 任务描述: ").append(description).append("\n");
        }
        sb.append("\n");

        if (!constraints.isEmpty()) {
            sb.append("## 信息收集阶段约束规则（必须严格遵守）\n");
            constraints.forEach(c -> sb.append("- ").append(c).append("\n"));
            sb.append("\n");
        }

        if (suggestion != null && !suggestion.isBlank()) {
            sb.append("## 策略建议（来自决策 Agent）\n");
            sb.append(suggestion).append("\n\n");
        }

        if (!targetDocs.isEmpty()) {
            sb.append("## 目标参考文档\n");
            targetDocs.forEach(d -> sb.append(d).append("\n---\n"));
            sb.append("\n");
        }

        if (!existingFindings.isEmpty()) {
            sb.append("## 已有信息收集发现\n");
            existingFindings.stream()
                    .filter(Finding::isSuccess)
                    .forEach(f -> sb.append("- [").append(f.getToolName()).append("] ").append(f.getSummary()).append("\n"));
            sb.append("\n");
        }

        sb.append("## 工作指南\n");
        sb.append("1. 使用 executeCommand 工具执行渗透测试命令（nmap、nikto、whatweb、ffuf、gobuster、curl 等）\n");
        sb.append("2. 重点收集：开放端口、服务版本、Web 框架、API 接口、目录结构、CMS 类型\n");
        sb.append("3. 每次工具调用后分析结果，决定下一步行动\n");
        sb.append("4. 如果遇到困境（无法继续、连续工具失败），在输出中包含 [REQUEST_ADVISOR_HELP] 标记\n");
        sb.append("5. 最后总结发现，以 [FINDING_SUMMARY:...] 格式输出关键发现\n");

        return sb.toString();
    }

    private String buildUserPrompt(String targetUrl, List<Finding> existingFindings) {
        if (existingFindings.isEmpty()) {
            return "请对目标 " + targetUrl + " 进行全面的信息收集，包括端口扫描、Web 指纹识别、目录探测等。";
        }
        return "请基于已有发现，继续深入信息收集目标 " + targetUrl
                + "。重点关注尚未探索的方向，避免重复已有工作。";
    }

    private Finding parseFinding(String content, String phase) {
        if (content == null || content.isBlank()) return null;

        // 尝试解析 [FINDING_SUMMARY:...] 标记
        int start = content.indexOf("[FINDING_SUMMARY:");
        if (start >= 0) {
            int end = content.indexOf("]", start);
            if (end > start) {
                String summary = content.substring(start + "[FINDING_SUMMARY:".length(), end).trim();
                return Finding.builder()
                        .phase(phase)
                        .toolName("info_gathering")
                        .summary(summary)
                        .success(!summary.toLowerCase().contains("failed") && !summary.toLowerCase().contains("error"))
                        .timestamp(Instant.now())
                        .build();
            }
        }
        return null;
    }

    private String extractHelpContext(String content) {
        int start = content.indexOf("[REQUEST_ADVISOR_HELP]");
        if (start < 0) return "信息收集遇到困境，需要指导";
        // 取标记后的一段文字作为上下文
        String after = content.substring(start + "[REQUEST_ADVISOR_HELP]".length()).trim();
        return after.length() > 300 ? after.substring(0, 300) : after;
    }

    private Map<String, Object> buildResult(List<Finding> newFindings, int consecutiveFailures,
                                             boolean requestHelp, String helpContext) {
        Map<String, Object> result = new HashMap<>();
        result.put(PentestStateKeys.INFO_FINDINGS, newFindings);
        result.put(PentestStateKeys.CURRENT_PHASE, PHASE);
        result.put(PentestStateKeys.CONSECUTIVE_FAILURES, consecutiveFailures);

        if (requestHelp) {
            result.put(PentestStateKeys.REQUEST_ADVISOR_HELP, true);
            result.put(PentestStateKeys.HELP_CONTEXT, helpContext != null ? helpContext : "信息收集遇到困境");
        }

        return result;
    }
}

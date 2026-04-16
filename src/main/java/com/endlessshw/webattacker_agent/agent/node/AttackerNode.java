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
 * 主攻手 Agent 节点（AttackerNode）
 *
 * 职责：
 * - 从 RAG 加载攻击阶段约束规则（如生产环境禁止高危漏洞利用）
 * - 注入 DecisionNode 给出的策略建议
 * - 基于信息收集结果，执行漏洞利用（SQL 注入、XSS、SSRF、文件上传等）
 * - 工具调用循环直到 LLM 停止发起工具调用
 * - 遇到困境时设置 requestAdvisorHelp=true 求助 DecisionNode
 * - 将所有攻击发现追加到 attackFindings
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AttackerNode {

    private static final Executor VIRTUAL = Executors.newVirtualThreadPerTaskExecutor();

    private static final String PHASE = "attack";

    @Qualifier("attackChatClient")
    private final ChatClient attackChatClient;

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
        String taskId = (String) state.value(PentestStateKeys.TASK_ID, "");
        String suggestion = state.<String>value(PentestStateKeys.DECISION_SUGGESTION).orElse(null);
        List<Finding> infoFindings = state.<List<Finding>>value(PentestStateKeys.INFO_FINDINGS, List.of());
        List<Finding> existingAttackFindings = state.<List<Finding>>value(PentestStateKeys.ATTACK_FINDINGS, List.of());
        int iterationCount = (int) state.value(PentestStateKeys.ITERATION_COUNT, 0);
        int consecutiveFailures = (int) state.value(PentestStateKeys.CONSECUTIVE_FAILURES, 0);

        log.info("[AttackerNode] 开始攻击阶段，目标: {}, iteration={}", targetUrl, iterationCount);

        // 1. 从 RAG 获取攻击阶段约束规则
        List<String> constraints = ragService.retrieveConstraints(targetEnv, PHASE);

        // 2. 构建 System Prompt
        String systemPrompt = buildSystemPrompt(targetUrl, targetEnv, description,
                constraints, suggestion, infoFindings, existingAttackFindings);

        // 3. 执行攻击
        List<Finding> newFindings = new ArrayList<>();
        boolean requestHelp = false;
        String helpContext = null;

        // 记录节点启动日志
        saveLog(taskId, "INFO", "开始攻击阶段，目标: " + targetUrl + ", iteration=" + iterationCount, null, null, null);

        // 设置工具上下文，使 DockerCommandTool 能将每次命令执行记录到当前任务日志
        DockerCommandTool.setToolContext(taskId, PHASE);
        try {
            // 直接传入 Bean 对象，Spring AI 自动扫描 @Tool 方法
            String content = attackChatClient.prompt()
                    .system(systemPrompt)
                    .user(buildUserPrompt(targetUrl, infoFindings, existingAttackFindings))
                    .tools(dockerCommandTool)
                    .call()
                    .content();

            log.debug("[AttackerNode] LLM 响应（前200字）: {}",
                    content != null ? content.substring(0, Math.min(200, content.length())) : "null");

            // 记录 LLM 最终响应（截断避免日志过大）
            String logContent = content != null
                    ? content.substring(0, Math.min(2000, content.length()))
                    : "(无输出)";
            saveLog(taskId, "INFO", "攻击阶段 LLM 分析完成", "llm_response", null, logContent);

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
                // 无法解析标记，将整个响应作为发现摘要
                newFindings.add(Finding.builder()
                        .phase(PHASE)
                        .toolName("attack")
                        .summary(content != null ? content.substring(0, Math.min(500, content.length())) : "无输出")
                        .success(true)
                        .timestamp(Instant.now())
                        .build());
                consecutiveFailures = 0;
            }

            // 检查是否请求顾问帮助
            if (content != null && content.contains("[REQUEST_ADVISOR_HELP]")) {
                requestHelp = true;
                helpContext = extractHelpContext(content);
                log.info("[AttackerNode] Agent 请求顾问帮助: {}", helpContext);
                saveLog(taskId, "WARN", "请求顾问帮助: " + helpContext, null, null, null);
            }

        } catch (Exception e) {
            log.error("[AttackerNode] LLM 调用失败", e);
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
                helpContext = "攻击阶段连续失败 " + consecutiveFailures + " 次，最后错误: " + e.getMessage();
            }
        } finally {
            DockerCommandTool.clearToolContext();
        }

        saveLog(taskId, "INFO",
                "攻击阶段完成，新发现 " + newFindings.size() + " 条，连续失败 " + consecutiveFailures + " 次",
                null, null, null);

        return buildResult(newFindings, consecutiveFailures, requestHelp, helpContext);
    }

    private void saveLog(String taskId, String level, String message,
                         String toolName, String toolInput, String toolOutput) {
        if (taskId == null || taskId.isBlank()) return;
        logStore.save(PentestLog.builder()
                .taskId(taskId)
                .agentName("AttackerNode")
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
                                      List<String> constraints, String suggestion,
                                      List<Finding> infoFindings, List<Finding> existingAttackFindings) {
        StringBuilder sb = new StringBuilder();
        sb.append("你是一名专业的 Web 渗透测试攻击专家（主攻手）。\n\n");
        sb.append("## 目标信息\n");
        sb.append("- 目标 URL: ").append(targetUrl).append("\n");
        sb.append("- 环境类型: ").append(targetEnv).append("\n");
        if (!description.isBlank()) {
            sb.append("- 任务描述: ").append(description).append("\n");
        }
        sb.append("\n");

        if (!constraints.isEmpty()) {
            sb.append("## 攻击阶段约束规则（必须严格遵守）\n");
            constraints.forEach(c -> sb.append("- ").append(c).append("\n"));
            sb.append("\n");
        }

        if (suggestion != null && !suggestion.isBlank()) {
            sb.append("## 策略建议（来自决策 Agent）\n");
            sb.append(suggestion).append("\n\n");
        }

        if (!infoFindings.isEmpty()) {
            sb.append("## 信息收集结果（攻击依据）\n");
            infoFindings.stream()
                    .filter(Finding::isSuccess)
                    .forEach(f -> sb.append("- [").append(f.getToolName()).append("] ").append(f.getSummary()).append("\n"));
            sb.append("\n");
        }

        if (!existingAttackFindings.isEmpty()) {
            sb.append("## 已执行的攻击（避免重复）\n");
            existingAttackFindings.stream()
                    .filter(Finding::isSuccess)
                    .forEach(f -> sb.append("- [").append(f.getToolName()).append("] ").append(f.getSummary()).append("\n"));
            sb.append("\n");
        }

        sb.append("## 工作指南\n");
        sb.append("1. 使用 executeCommand 工具执行攻击命令（sqlmap、xsser、nikto、burpsuite-cli、python3 等）\n");
        sb.append("2. 重点攻击方向：SQL 注入、XSS、SSRF、文件上传、命令注入、反序列化、路径穿越\n");
        sb.append("3. 每次工具调用后分析结果，判断是否成功利用\n");
        sb.append("4. 如果遇到困境（无法继续、连续失败），在输出中包含 [REQUEST_ADVISOR_HELP] 标记\n");
        sb.append("5. 最后以 [FINDING_SUMMARY:...] 格式总结攻击发现（包含漏洞类型、影响、利用证明）\n");

        return sb.toString();
    }

    private String buildUserPrompt(String targetUrl, List<Finding> infoFindings,
                                    List<Finding> existingAttackFindings) {
        if (existingAttackFindings.isEmpty()) {
            return "请基于信息收集结果，对目标 " + targetUrl + " 发起漏洞探测和利用攻击。";
        }
        return "请继续对目标 " + targetUrl + " 进行深入攻击，探索新的漏洞向量，避免重复已有攻击路径。";
    }

    private Finding parseFinding(String content, String phase) {
        if (content == null || content.isBlank()) return null;

        int start = content.indexOf("[FINDING_SUMMARY:");
        if (start >= 0) {
            int end = content.indexOf("]", start);
            if (end > start) {
                String summary = content.substring(start + "[FINDING_SUMMARY:".length(), end).trim();
                boolean isSuccess = !summary.toLowerCase().contains("failed")
                        && !summary.toLowerCase().contains("error")
                        && !summary.toLowerCase().contains("未发现");
                return Finding.builder()
                        .phase(phase)
                        .toolName("attack")
                        .summary(summary)
                        .success(isSuccess)
                        .timestamp(Instant.now())
                        .build();
            }
        }
        return null;
    }

    private String extractHelpContext(String content) {
        int start = content.indexOf("[REQUEST_ADVISOR_HELP]");
        if (start < 0) return "攻击阶段遇到困境，需要指导";
        String after = content.substring(start + "[REQUEST_ADVISOR_HELP]".length()).trim();
        return after.length() > 300 ? after.substring(0, 300) : after;
    }

    private Map<String, Object> buildResult(List<Finding> newFindings, int consecutiveFailures,
                                             boolean requestHelp, String helpContext) {
        Map<String, Object> result = new HashMap<>();
        result.put(PentestStateKeys.ATTACK_FINDINGS, newFindings);
        result.put(PentestStateKeys.CURRENT_PHASE, PHASE);
        result.put(PentestStateKeys.CONSECUTIVE_FAILURES, consecutiveFailures);

        if (requestHelp) {
            result.put(PentestStateKeys.REQUEST_ADVISOR_HELP, true);
            result.put(PentestStateKeys.HELP_CONTEXT, helpContext != null ? helpContext : "攻击阶段遇到困境");
        }

        return result;
    }
}

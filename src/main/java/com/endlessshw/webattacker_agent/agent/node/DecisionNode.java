package com.endlessshw.webattacker_agent.agent.node;

import com.alibaba.cloud.ai.graph.OverAllState;
import com.alibaba.cloud.ai.graph.action.AsyncNodeAction;
import com.endlessshw.webattacker_agent.agent.state.PentestStateKeys;
import com.endlessshw.webattacker_agent.model.Finding;
import com.endlessshw.webattacker_agent.model.PentestLog;
import com.endlessshw.webattacker_agent.service.log.LogStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 决策 Agent 节点（DecisionNode）
 *
 * 双模式运行：
 * - 规划模式（Planning）：正常决策，分析当前状态，决定下一步行动，并给下游提供策略建议
 * - 顾问模式（Advisory）：当 requestAdvisorHelp=true 时触发，针对下游遇到的困境给出具体指导
 *
 * 顾问模式触发条件（参考 CHYing-agent 机制）：
 * 1. 下游 Agent 连续失败 >= 3 次
 * 2. 下游 Agent 主动输出 [REQUEST_ADVISOR_HELP] 标记
 * 3. 每 advisorInterval 轮决策定期介入
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DecisionNode {

    // 虚拟线程池：专为 I/O 密集型任务（LLM HTTP 调用）设计，避免阻塞 ForkJoinPool
    private static final Executor VIRTUAL = Executors.newVirtualThreadPerTaskExecutor();

    private static final Pattern NEXT_ACTION_PATTERN = Pattern.compile("\\[NEXT_ACTION:(\\w+)\\]");
    private static final Pattern SUGGESTION_PATTERN = Pattern.compile("\\[SUGGESTION:(.*?)\\]", Pattern.DOTALL);

    @Qualifier("decisionChatClient")
    private final ChatClient decisionChatClient;

    private final LogStore logStore;

    @Value("${app.pentest.max-iterations:20}")
    private int maxIterations;

    @Value("${app.pentest.advisor-interval:5}")
    private int advisorInterval;

    /**
     * 作为 AsyncNodeAction 执行节点逻辑
     */
    public AsyncNodeAction action() {
        return state -> CompletableFuture.supplyAsync(() -> execute(state), VIRTUAL);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> execute(OverAllState state) {
        int iterationCount = (int) state.value(PentestStateKeys.ITERATION_COUNT, 0);
        boolean requestHelp = (boolean) state.value(PentestStateKeys.REQUEST_ADVISOR_HELP, false);
        int consecutiveFailures = (int) state.value(PentestStateKeys.CONSECUTIVE_FAILURES, 0);
        int lastAdvisorAt = (int) state.value(PentestStateKeys.LAST_ADVISOR_AT, -advisorInterval);
        String taskId = (String) state.value(PentestStateKeys.TASK_ID, "");

        // 强制结束条件：达到最大 iteration 次数
        if (iterationCount >= maxIterations) {
            log.info("[DecisionNode] 达到最大 iteration 次数 {}，强制进入报告阶段", maxIterations);
            saveLog(taskId, "INFO", "达到最大迭代次数 " + maxIterations + "，进入报告阶段", "report");
            return buildResult("report", "已达最大迭代次数，请基于当前发现生成报告。", iterationCount + 1, false, null, false);
        }

        // 判断是否为顾问模式
        boolean isAdvisoryMode = requestHelp
                || consecutiveFailures >= 3
                || (iterationCount - lastAdvisorAt) >= advisorInterval;

        String mode = isAdvisoryMode ? "Advisory" : "Planning";
        log.info("[DecisionNode] 调用 LLM，模式: {}, iteration={}", mode, iterationCount);
        saveLog(taskId, "INFO", "决策节点启动，模式: " + mode + ", iteration=" + iterationCount, null);

        String systemPrompt = buildSystemPrompt(state, isAdvisoryMode);
        String userPrompt = buildUserPrompt(state, isAdvisoryMode);

        String response;
        try {
            response = decisionChatClient.prompt()
                    .system(systemPrompt)
                    .user(userPrompt)
                    .call()
                    .content();
        } catch (Exception e) {
            log.error("[DecisionNode] LLM 调用失败", e);
            saveLog(taskId, "ERROR", "决策 LLM 调用失败: " + e.getMessage(), null);
            // 失败时默认继续信息收集
            return buildResult("info_gathering", "LLM 调用失败，请重试信息收集。", iterationCount + 1, isAdvisoryMode, null, false);
        }

        // 解析 LLM 输出
        String nextAction = parseNextAction(response);
        String suggestion = parseSuggestion(response);

        log.info("[DecisionNode] 决策结果: nextAction={}, suggestion前50字={}", nextAction,
                suggestion != null ? suggestion.substring(0, Math.min(50, suggestion.length())) : "null");

        // 记录决策结果
        String logMsg = "决策完成: nextAction=" + nextAction
                + (suggestion != null ? ", suggestion=" + suggestion.substring(0, Math.min(200, suggestion.length())) : "");
        saveLog(taskId, "INFO", logMsg, nextAction);

        // 如果是顾问模式，重置标志并记录本次顾问时间
        Integer newLastAdvisorAt = isAdvisoryMode ? iterationCount : null;

        return buildResult(nextAction, suggestion, iterationCount + 1, false, newLastAdvisorAt,
                isAdvisoryMode && requestHelp);
    }

    private void saveLog(String taskId, String level, String message, String toolName) {
        if (taskId == null || taskId.isBlank()) return;
        logStore.save(PentestLog.builder()
                .taskId(taskId)
                .agentName("DecisionNode")
                .phase("decision")
                .level(level)
                .message(message)
                .toolName(toolName)
                .build());
    }

    @SuppressWarnings("unchecked")
    private String buildSystemPrompt(OverAllState state, boolean isAdvisoryMode) {
        String targetUrl = (String) state.value(PentestStateKeys.TARGET_URL, "unknown");
        String targetEnv = (String) state.value(PentestStateKeys.TARGET_ENVIRONMENT, "test");
        int iterationCount = (int) state.value(PentestStateKeys.ITERATION_COUNT, 0);
        List<Finding> infoFindings = state.<List<Finding>>value(PentestStateKeys.INFO_FINDINGS, List.of());
        List<Finding> attackFindings = state.<List<Finding>>value(PentestStateKeys.ATTACK_FINDINGS, List.of());
        String description = (String) state.value(PentestStateKeys.DESCRIPTION, "");

        String stateContext = String.format("""
                ## 当前渗透测试状态
                - 目标 URL: %s
                - 环境类型: %s
                - 已完成轮次: %d / %d
                - 信息收集发现数: %d 条
                - 攻击发现数: %d 条
                - 任务描述: %s
                """,
                targetUrl, targetEnv, iterationCount, maxIterations,
                infoFindings.size(), attackFindings.size(), description);

        // 添加最近的发现摘要
        String findingsSummary = buildFindingsSummary(infoFindings, attackFindings);

        if (isAdvisoryMode) {
            String helpContext = (String) state.value(PentestStateKeys.HELP_CONTEXT, "未指定具体问题");
            return String.format("""
                    你是一位资深渗透测试专家和战术顾问。下游的渗透测试 Agent 遇到了困难，需要你的指导。

                    %s

                    %s

                    ## 下游 Agent 的困境
                    %s

                    ## 你的任务
                    提供具体可行的建议帮助 Agent 克服当前障碍。建议要具体到工具参数、攻击向量或思路调整。
                    并决定下一步行动（通常保持和当前阶段相同，让 Agent 用新思路重试）。

                    输出格式（必须包含在响应末尾）：
                    [NEXT_ACTION:info_gathering] 或 [NEXT_ACTION:attack] 或 [NEXT_ACTION:report]
                    [SUGGESTION:你的具体指导建议]
                    """, stateContext, findingsSummary, helpContext);
        } else {
            return String.format("""
                    你是一个 Web 渗透测试行动的指挥中心。你负责分析当前测试进展，决定下一步行动，并为执行团队提供战略指引。

                    %s

                    %s

                    ## 决策标准
                    - info_gathering：目标信息不足，需继续收集（端口、服务、CMS、API 接口等）
                    - attack：已有足够信息，开始漏洞利用（SQL 注入、XSS、SSRF、文件上传等）
                    - report：已有有价值的发现 或 剩余轮次不多，生成渗透报告
                    - end：必须立即停止（发现授权外目标、可能造成不可逆损害等）

                    ## 输出格式（必须包含在响应末尾）
                    [NEXT_ACTION:action]  <- 其中 action 为上述四选一
                    [SUGGESTION:给下一个执行 Agent 的具体战术建议]
                    """, stateContext, findingsSummary);
        }
    }

    private String buildUserPrompt(OverAllState state, boolean isAdvisoryMode) {
        if (isAdvisoryMode) {
            return "请分析下游 Agent 的困境，提供针对性的指导建议，并决定下一步行动。";
        }
        return "请基于当前渗透测试状态，决定下一步行动，并为执行 Agent 提供战术建议。";
    }

    @SuppressWarnings("unchecked")
    private String buildFindingsSummary(List<Finding> infoFindings, List<Finding> attackFindings) {
        StringBuilder sb = new StringBuilder("## 已有发现摘要\n");

        if (!infoFindings.isEmpty()) {
            sb.append("**信息收集发现（最新 3 条）**:\n");
            infoFindings.stream()
                    .filter(Finding::isSuccess)
                    .skip(Math.max(0, infoFindings.size() - 3))
                    .forEach(f -> sb.append("- [").append(f.getToolName()).append("] ").append(f.getSummary()).append("\n"));
        }

        if (!attackFindings.isEmpty()) {
            sb.append("**攻击发现（最新 3 条）**:\n");
            attackFindings.stream()
                    .filter(Finding::isSuccess)
                    .skip(Math.max(0, attackFindings.size() - 3))
                    .forEach(f -> sb.append("- [").append(f.getToolName()).append("] ").append(f.getSummary()).append("\n"));
        }

        if (infoFindings.isEmpty() && attackFindings.isEmpty()) {
            sb.append("暂无发现（首次运行）。\n");
        }

        return sb.toString();
    }

    private String parseNextAction(String response) {
        Matcher matcher = NEXT_ACTION_PATTERN.matcher(response);
        if (matcher.find()) {
            String action = matcher.group(1).toLowerCase().trim();
            // 验证合法值
            if (List.of("info_gathering", "attack", "report", "end").contains(action)) {
                return action;
            }
        }
        // 默认：没有发现就继续收集信息，有发现就去攻击
        log.warn("[DecisionNode] 无法解析 nextAction，使用默认值 info_gathering");
        return "info_gathering";
    }

    private String parseSuggestion(String response) {
        Matcher matcher = SUGGESTION_PATTERN.matcher(response);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return null;
    }

    private Map<String, Object> buildResult(String nextAction, String suggestion, int newIterationCount,
                                             boolean clearAdvisorHelp, Integer newLastAdvisorAt, boolean wasAdvisory) {
        Map<String, Object> result = new HashMap<>();
        result.put(PentestStateKeys.NEXT_ACTION, nextAction);
        result.put(PentestStateKeys.ITERATION_COUNT, newIterationCount);

        if (suggestion != null) {
            result.put(PentestStateKeys.DECISION_SUGGESTION, suggestion);
        }

        if (clearAdvisorHelp) {
            result.put(PentestStateKeys.REQUEST_ADVISOR_HELP, false);
            result.put(PentestStateKeys.HELP_CONTEXT, null);
            result.put(PentestStateKeys.CONSECUTIVE_FAILURES, 0);
        }

        if (newLastAdvisorAt != null) {
            result.put(PentestStateKeys.LAST_ADVISOR_AT, newLastAdvisorAt);
        }

        return result;
    }
}

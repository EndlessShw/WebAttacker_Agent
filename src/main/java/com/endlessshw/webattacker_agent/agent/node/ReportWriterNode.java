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
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * 报告撰写 Agent 节点（ReportWriterNode）
 *
 * 职责：
 * - 整合 infoFindings + attackFindings
 * - 调用 qwen-long 生成结构化 Markdown 渗透测试报告
 * - 将 Markdown 写入 state.reportMarkdown
 * - 设置 isFinished = true
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ReportWriterNode {

    private static final Executor VIRTUAL = Executors.newVirtualThreadPerTaskExecutor();

    @Qualifier("reportChatClient")
    private final ChatClient reportChatClient;

    private final LogStore logStore;

    public AsyncNodeAction action() {
        return state -> CompletableFuture.supplyAsync(() -> execute(state), VIRTUAL);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> execute(OverAllState state) {
        String targetUrl = (String) state.value(PentestStateKeys.TARGET_URL, "unknown");
        String targetEnv = (String) state.value(PentestStateKeys.TARGET_ENVIRONMENT, "test");
        String description = (String) state.value(PentestStateKeys.DESCRIPTION, "");
        String scope = (String) state.value(PentestStateKeys.SCOPE, "");
        String taskId = (String) state.value(PentestStateKeys.TASK_ID, "");
        int iterationCount = (int) state.value(PentestStateKeys.ITERATION_COUNT, 0);
        List<Finding> infoFindings = state.<List<Finding>>value(PentestStateKeys.INFO_FINDINGS, List.of());
        List<Finding> attackFindings = state.<List<Finding>>value(PentestStateKeys.ATTACK_FINDINGS, List.of());

        log.info("[ReportWriterNode] 开始生成报告，infoFindings={}, attackFindings={}",
                infoFindings.size(), attackFindings.size());
        saveLog(taskId, "INFO",
                "开始生成报告，总 iteration=" + iterationCount
                + ", 信息收集发现=" + infoFindings.size()
                + ", 攻击发现=" + attackFindings.size());

        String systemPrompt = buildSystemPrompt();
        String userPrompt = buildUserPrompt(targetUrl, targetEnv, description, scope,
                iterationCount, infoFindings, attackFindings);

        String reportMarkdown;
        try {
            reportMarkdown = reportChatClient.prompt()
                    .system(systemPrompt)
                    .user(userPrompt)
                    .call()
                    .content();

            if (reportMarkdown == null || reportMarkdown.isBlank()) {
                reportMarkdown = generateFallbackReport(targetUrl, targetEnv, infoFindings, attackFindings);
            }
        } catch (Exception e) {
            log.error("[ReportWriterNode] LLM 调用失败，生成备用报告", e);
            saveLog(taskId, "ERROR", "报告 LLM 调用失败，使用备用模板: " + e.getMessage());
            reportMarkdown = generateFallbackReport(targetUrl, targetEnv, infoFindings, attackFindings);
        }

        log.info("[ReportWriterNode] 报告生成完成，长度: {} 字符", reportMarkdown.length());
        saveLog(taskId, "INFO", "报告生成完成，长度: " + reportMarkdown.length() + " 字符");

        Map<String, Object> result = new HashMap<>();
        result.put(PentestStateKeys.REPORT_MARKDOWN, reportMarkdown);
        result.put(PentestStateKeys.IS_FINISHED, true);
        result.put(PentestStateKeys.CURRENT_PHASE, "report");
        return result;
    }

    private void saveLog(String taskId, String level, String message) {
        if (taskId == null || taskId.isBlank()) return;
        logStore.save(PentestLog.builder()
                .taskId(taskId)
                .agentName("ReportWriterNode")
                .phase("report")
                .level(level)
                .message(message)
                .build());
    }

    private String buildSystemPrompt() {
        return """
                你是一名专业的网络安全报告撰写专家。请根据渗透测试数据生成一份结构完整、专业规范的 Markdown 渗透测试报告。

                报告必须包含以下章节：
                1. **执行摘要** - 测试目标、范围、时间、主要发现概述
                2. **目标信息** - 目标 URL、环境类型、基本信息
                3. **信息收集结果** - 详细的侦察和指纹识别发现
                4. **漏洞发现** - 每个漏洞的详细描述（包含漏洞类型、位置、严重程度、复现步骤、证明截图/输出）
                5. **风险评估** - 按 CVSS 评级或高/中/低分类
                6. **修复建议** - 针对每个漏洞的具体修复措施
                7. **结论** - 总体安全状态评估

                使用规范的 Markdown 格式，包含表格、代码块等元素。严重程度用 🔴高危 🟠中危 🟡低危 🔵信息 标注。
                """;
    }

    private String buildUserPrompt(String targetUrl, String targetEnv, String description,
                                    String scope, int iterationCount,
                                    List<Finding> infoFindings, List<Finding> attackFindings) {
        StringBuilder sb = new StringBuilder();
        sb.append("请根据以下渗透测试数据生成完整报告：\n\n");
        sb.append("## 测试概况\n");
        sb.append("- 目标 URL: ").append(targetUrl).append("\n");
        sb.append("- 环境类型: ").append(targetEnv).append("\n");
        if (!description.isBlank()) sb.append("- 任务描述: ").append(description).append("\n");
        if (!scope.isBlank()) sb.append("- 测试范围: ").append(scope).append("\n");
        sb.append("- 执行轮次: ").append(iterationCount).append("\n\n");

        sb.append("## 信息收集发现（共 ").append(infoFindings.size()).append(" 条）\n");
        if (infoFindings.isEmpty()) {
            sb.append("无信息收集发现。\n");
        } else {
            infoFindings.forEach(f -> {
                sb.append("### [").append(f.getToolName()).append("] ");
                sb.append(f.isSuccess() ? "✓" : "✗").append(" ").append(f.getSummary()).append("\n");
                if (f.getToolInput() != null && !f.getToolInput().isBlank()) {
                    sb.append("- 命令: `").append(f.getToolInput()).append("`\n");
                }
                if (f.getToolOutput() != null && !f.getToolOutput().isBlank()) {
                    String output = f.getToolOutput();
                    sb.append("- 输出:\n```\n")
                            .append(output.length() > 1000 ? output.substring(0, 1000) + "\n...[截断]" : output)
                            .append("\n```\n");
                }
            });
        }
        sb.append("\n");

        sb.append("## 攻击发现（共 ").append(attackFindings.size()).append(" 条）\n");
        if (attackFindings.isEmpty()) {
            sb.append("无攻击发现。\n");
        } else {
            attackFindings.forEach(f -> {
                sb.append("### [").append(f.getToolName()).append("] ");
                sb.append(f.isSuccess() ? "✓" : "✗").append(" ").append(f.getSummary()).append("\n");
                if (f.getToolInput() != null && !f.getToolInput().isBlank()) {
                    sb.append("- 命令: `").append(f.getToolInput()).append("`\n");
                }
                if (f.getToolOutput() != null && !f.getToolOutput().isBlank()) {
                    String output = f.getToolOutput();
                    sb.append("- 输出:\n```\n")
                            .append(output.length() > 1500 ? output.substring(0, 1500) + "\n...[截断]" : output)
                            .append("\n```\n");
                }
            });
        }

        return sb.toString();
    }

    private String generateFallbackReport(String targetUrl, String targetEnv,
                                           List<Finding> infoFindings, List<Finding> attackFindings) {
        long successfulAttacks = attackFindings.stream().filter(Finding::isSuccess).count();

        return String.format("""
                # 渗透测试报告

                ## 执行摘要

                本报告记录了对目标 `%s`（%s 环境）的自动化渗透测试结果。

                | 指标 | 数值 |
                |------|------|
                | 信息收集发现 | %d 条 |
                | 攻击发现 | %d 条 |
                | 成功利用 | %d 项 |

                ## 信息收集结果

                %s

                ## 漏洞发现

                %s

                ## 修复建议

                请根据具体漏洞类型参考 OWASP 修复指南进行修复。

                ---
                *本报告由 WebAttacker Agent 自动生成*
                """,
                targetUrl, targetEnv,
                infoFindings.size(), attackFindings.size(), successfulAttacks,
                formatFindingsMarkdown(infoFindings),
                formatFindingsMarkdown(attackFindings)
        );
    }

    private String formatFindingsMarkdown(List<Finding> findings) {
        if (findings.isEmpty()) return "无发现。";
        return findings.stream()
                .map(f -> "- **[" + f.getToolName() + "]** " + f.getSummary())
                .collect(Collectors.joining("\n"));
    }
}

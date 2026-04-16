package com.endlessshw.webattacker_agent.tools.docker;

import com.endlessshw.webattacker_agent.model.PentestLog;
import com.endlessshw.webattacker_agent.service.log.LogStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Docker 命令执行工具
 *
 * 通过 ProcessBuilder 向已运行的 Kali Linux 容器发送命令，返回 stdout + stderr。
 *
 * 超时兜底策略：
 * - 输出读取在虚拟线程中并行执行，主线程专注 waitFor 超时控制
 * - 超时后强制终止进程，将已收集的部分输出返回给 LLM
 * - LLM 收到超时提示后可自行决定下一步（跳过或换参数重试）
 *
 * 安全防护：
 * - 危险命令模式检测（rm -rf、shutdown 等）
 * - 输出截断（最多 8192 字符）
 */
@Slf4j
@Component
public class DockerCommandTool {

    /** 最大输出长度（字符），防止超大输出塞满上下文 */
    private static final int MAX_OUTPUT_LENGTH = 8192;

    /** 进程终止后等待读取线程收尾的最长时间（ms） */
    private static final long READER_DRAIN_MS = 3_000;

    /** 工具日志中输出截断长度（字符），避免单条日志过大 */
    private static final int LOG_OUTPUT_LIMIT = 3000;

    /** ThreadLocal：存储当前节点设置的任务 ID，供 executeCommand 记录日志 */
    private static final ThreadLocal<String> CURRENT_TASK_ID = new ThreadLocal<>();

    /** ThreadLocal：存储当前执行阶段（info_gathering / attack / ...） */
    private static final ThreadLocal<String> CURRENT_PHASE = new ThreadLocal<>();

    /**
     * 设置工具日志上下文（在节点调用 LLM 之前调用）
     *
     * @param taskId 当前任务 ID
     * @param phase  当前执行阶段
     */
    public static void setToolContext(String taskId, String phase) {
        CURRENT_TASK_ID.set(taskId);
        CURRENT_PHASE.set(phase);
    }

    /**
     * 清除工具日志上下文（在节点完成 LLM 调用后的 finally 块中调用）
     */
    public static void clearToolContext() {
        CURRENT_TASK_ID.remove();
        CURRENT_PHASE.remove();
    }

    /** 危险命令模式（会被拒绝执行）*/
    private static final List<String> DANGEROUS_PATTERNS = Arrays.asList(
            "rm -rf /",
            "rm -rf /*",
            "shutdown",
            "reboot",
            "halt",
            "init 0",
            "dd if=",
            "mkfs",
            "format",
            "> /dev/sda",
            "chmod -R 777 /"
    );

    @Autowired
    private LogStore logStore;

    @Value("${app.docker.container-name:kali-pentest}")
    private String containerName;

    @Value("${app.docker.exec-timeout-seconds:300}")
    private int timeoutSeconds;

    /**
     * 在 Kali Linux 容器中执行 Shell 命令
     *
     * 超时后返回已收集的部分输出 + 超时提示，LLM 可据此决定是否继续或跳过。
     */
    @Tool(description = "在 Kali Linux 渗透测试容器中执行 shell 命令。支持 nmap、sqlmap、nikto、ffuf、gobuster、curl、python3 等常用渗透工具。返回命令的 stdout 和 stderr。超时会返回部分输出。")
    public String executeCommand(
            @ToolParam(description = "要在 Kali 容器内执行的 shell 命令，例如：nmap -sV -p 80,443 192.168.1.1") String command) {

        // 安全检查：拒绝危险命令
        String lowerCommand = command.toLowerCase();
        for (String pattern : DANGEROUS_PATTERNS) {
            if (lowerCommand.contains(pattern.toLowerCase())) {
                log.warn("[DockerTool] 拒绝危险命令: {}", command);
                return "ERROR: 命令包含危险操作模式 '" + pattern + "'，已被安全策略拒绝。";
            }
        }

        ProcessBuilder pb = new ProcessBuilder(
                "docker", "exec", containerName,
                "/bin/bash", "-c", command
        );
        pb.redirectErrorStream(true);

        log.info("[DockerTool] 执行命令 (超时 {}s): {}", timeoutSeconds, command);

        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            log.error("[DockerTool] 启动进程失败", e);
            return "[ERROR] 无法启动 docker exec: " + e.getMessage();
        }

        // 在虚拟线程中并行读取输出，避免 readLine() 阻塞导致 waitFor 超时失效
        StringBuilder output = new StringBuilder();
        Thread readerThread = Thread.ofVirtual().start(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    synchronized (output) {
                        output.append(line).append("\n");
                        if (output.length() >= MAX_OUTPUT_LENGTH) {
                            output.append("\n... [输出过长，已截断] ...");
                            return;
                        }
                    }
                }
            } catch (IOException ignored) {
                // 进程被 destroyForcibly 后流会关闭，属于正常情况
            }
        });

        boolean finished;
        try {
            // 主线程等待进程完成，带超时
            finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return "[ERROR] 等待进程时被中断: " + e.getMessage();
        }

        if (!finished) {
            // 超时：强制终止进程，读取线程会随即收到 EOF
            process.destroyForcibly();
            log.warn("[DockerTool] 命令超时 ({}s)，已强制终止: {}", timeoutSeconds, command);
        }

        // 等待读取线程将缓冲中的剩余输出写完
        try {
            readerThread.join(READER_DRAIN_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        String result = output.toString().trim();
        if (result.isEmpty()) {
            result = "(命令无输出)";
        }

        // 组装最终返回值
        String returnValue;
        if (!finished) {
            log.info("[DockerTool] 返回超时部分输出，长度: {} 字符", result.length());
            returnValue = "[超时: 命令在 " + timeoutSeconds + "s 后被终止，以下为部分输出，请据此判断是否继续]\n" + result;
        } else {
            int exitCode = process.exitValue();
            returnValue = "[退出码: " + exitCode + "]\n" + result;
            log.debug("[DockerTool] 命令完成，输出长度: {} 字符", returnValue.length());
        }

        // 写入任务过程日志（仅当节点设置了 taskId 上下文时）
        String currentTaskId = CURRENT_TASK_ID.get();
        if (currentTaskId != null && !currentTaskId.isBlank()) {
            String truncatedOutput = returnValue.length() > LOG_OUTPUT_LIMIT
                    ? returnValue.substring(0, LOG_OUTPUT_LIMIT) + "\n...[日志截断]"
                    : returnValue;
            String shortCmd = command.length() > 150 ? command.substring(0, 150) + "..." : command;
            logStore.save(PentestLog.builder()
                    .taskId(currentTaskId)
                    .agentName("DockerCommandTool")
                    .phase(CURRENT_PHASE.get() != null ? CURRENT_PHASE.get() : "unknown")
                    .level(!finished ? "WARN" : "INFO")
                    .message("执行命令: " + shortCmd)
                    .toolName("executeCommand")
                    .toolInput(command)
                    .toolOutput(truncatedOutput)
                    .build());
        }

        return returnValue;
    }
}

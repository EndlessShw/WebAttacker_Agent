package com.endlessshw.webattacker_agent.report;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 报告生成与下载服务
 *
 * 职责：
 * - 将 Markdown 报告持久化到本地文件系统
 * - 提供 Markdown 和 PDF 两种格式的读取入口
 * - 清理过期报告文件
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ReportService {

    private final PdfConverter pdfConverter;

    @Value("${app.report.output-dir:reports}")
    private String outputDir;

    /**
     * 保存 Markdown 报告到本地文件
     *
     * @param taskId   任务 ID
     * @param markdown Markdown 内容
     * @return 保存的文件路径
     */
    public Path saveMarkdownReport(String taskId, String markdown) throws IOException {
        Path dir = ensureReportDir();
        String filename = buildFilename(taskId, "md");
        Path filePath = dir.resolve(filename);
        Files.writeString(filePath, markdown, StandardCharsets.UTF_8);
        log.info("[ReportService] Markdown 报告已保存: {}", filePath);
        return filePath;
    }

    /**
     * 读取已保存的 Markdown 报告
     *
     * @param taskId 任务 ID
     * @return Markdown 内容，若文件不存在则返回 null
     */
    public String readMarkdownReport(String taskId) throws IOException {
        Path filePath = findReportFile(taskId, "md");
        if (filePath == null || !Files.exists(filePath)) {
            return null;
        }
        return Files.readString(filePath, StandardCharsets.UTF_8);
    }

    /**
     * 读取已保存的 Markdown 报告并转换为 PDF 字节数组
     *
     * @param taskId 任务 ID
     * @return PDF 字节数组，若报告不存在则返回 null
     */
    public byte[] readPdfReport(String taskId) throws IOException {
        String markdown = readMarkdownReport(taskId);
        if (markdown == null) {
            return null;
        }
        log.info("[ReportService] 开始生成 PDF 报告: taskId={}", taskId);
        return pdfConverter.convertToPdf(markdown);
    }

    /**
     * 获取报告文件路径（任意格式）
     */
    public Path findReportFile(String taskId, String extension) {
        try {
            Path dir = ensureReportDir();
            // 查找以 taskId 开头的对应扩展名文件
            return Files.list(dir)
                    .filter(p -> p.getFileName().toString().startsWith(taskId)
                            && p.getFileName().toString().endsWith("." + extension))
                    .findFirst()
                    .orElse(null);
        } catch (IOException e) {
            log.warn("[ReportService] 查找报告文件失败: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 检查任务报告是否存在
     */
    public boolean reportExists(String taskId) {
        return findReportFile(taskId, "md") != null;
    }

    private Path ensureReportDir() throws IOException {
        Path dir = Paths.get(outputDir);
        if (!Files.exists(dir)) {
            Files.createDirectories(dir);
        }
        return dir;
    }

    private String buildFilename(String taskId, String extension) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        return taskId + "_" + timestamp + "." + extension;
    }
}

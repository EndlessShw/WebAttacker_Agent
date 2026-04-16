package com.endlessshw.webattacker_agent.service.log;

import com.endlessshw.webattacker_agent.model.PentestLog;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 本地文件日志存储（默认实现）
 *
 * 格式：每个任务对应一个 JSONL 文件（{logDir}/{taskId}.jsonl），
 * 每行一条 JSON 序列化的 PentestLog，追加写入。
 * 读取时逐行解析，手动实现分页。
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "app.log.storage", havingValue = "local", matchIfMissing = true)
public class LocalFileLogStore implements LogStore {

    private final ObjectMapper objectMapper;
    private final Path logDir;

    public LocalFileLogStore(ObjectMapper objectMapper,
                              @Value("${app.log.output-dir:logs}") String logOutputDir) {
        this.objectMapper = objectMapper;
        this.logDir = Paths.get(logOutputDir);
        try {
            Files.createDirectories(this.logDir);
            log.info("[LocalFileLogStore] 日志目录: {}", this.logDir.toAbsolutePath());
        } catch (IOException e) {
            log.warn("[LocalFileLogStore] 创建日志目录失败: {}", e.getMessage());
        }
    }

    @Override
    public void save(PentestLog pentestLog) {
        if (pentestLog.getId() == null) {
            pentestLog.setId(UUID.randomUUID().toString());
        }
        Path file = logDir.resolve(pentestLog.getTaskId() + ".jsonl");
        try {
            String line = objectMapper.writeValueAsString(pentestLog) + "\n";
            Files.writeString(file, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            log.warn("[LocalFileLogStore] 写入日志失败 taskId={}: {}", pentestLog.getTaskId(), e.getMessage());
        }
    }

    @Override
    public Page<PentestLog> findByTaskId(String taskId, int page, int size) {
        List<PentestLog> all = findAllByTaskId(taskId);
        int total = all.size();
        int from = page * size;
        int to = Math.min(from + size, total);
        List<PentestLog> slice = (from < total) ? all.subList(from, to) : List.of();
        return new PageImpl<>(slice, PageRequest.of(page, size), total);
    }

    @Override
    public List<PentestLog> findAllByTaskId(String taskId) {
        Path file = logDir.resolve(taskId + ".jsonl");
        if (!Files.exists(file)) {
            return List.of();
        }
        List<PentestLog> result = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isBlank()) {
                    result.add(objectMapper.readValue(line, PentestLog.class));
                }
            }
        } catch (IOException e) {
            log.warn("[LocalFileLogStore] 读取日志失败 taskId={}: {}", taskId, e.getMessage());
        }
        return result;
    }
}

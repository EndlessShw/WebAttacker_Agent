package com.endlessshw.webattacker_agent.config;

import com.endlessshw.webattacker_agent.model.PentestLog;
import com.endlessshw.webattacker_agent.repository.PentestLogRepository;
import com.endlessshw.webattacker_agent.service.log.LogStore;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.elasticsearch.repository.config.EnableElasticsearchRepositories;

import java.util.List;

/**
 * Elasticsearch 日志存储配置（可插拔）
 *
 * 仅当 app.log.storage=elasticsearch 时加载。
 * 通过 @EnableElasticsearchRepositories 手动控制 Repository 扫描范围，
 * 避免默认情况下 Spring Data 自动扫描 PentestLogRepository 导致连接 ES。
 */
@Slf4j
@Configuration
@ConditionalOnProperty(name = "app.log.storage", havingValue = "elasticsearch")
@EnableElasticsearchRepositories(
        basePackageClasses = PentestLogRepository.class
)
public class ElasticsearchStorageConfig {

    @Bean
    public LogStore elasticsearchLogStore(PentestLogRepository repository) {
        log.info("[ElasticsearchStorageConfig] 使用 Elasticsearch 日志存储");
        return new LogStore() {

            @Override
            public void save(PentestLog pentestLog) {
                try {
                    repository.save(pentestLog);
                } catch (Exception e) {
                    log.warn("[ElasticsearchLogStore] 保存日志失败: {}", e.getMessage());
                }
            }

            @Override
            public Page<PentestLog> findByTaskId(String taskId, int page, int size) {
                return repository.findByTaskId(taskId,
                        PageRequest.of(page, size, Sort.by(Sort.Direction.ASC, "timestamp")));
            }

            @Override
            public List<PentestLog> findAllByTaskId(String taskId) {
                return repository.findByTaskIdOrderByTimestampAsc(taskId);
            }
        };
    }
}

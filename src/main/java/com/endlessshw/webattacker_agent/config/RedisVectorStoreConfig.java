package com.endlessshw.webattacker_agent.config;

import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.redis.RedisVectorStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import redis.clients.jedis.JedisPooled;

/**
 * Redis 向量存储配置
 *
 * 两个独立的 VectorStore：
 * - constraintsVectorStore：存储渗透测试约束规则（元数据：environment, phase）
 * - targetDocsVectorStore：存储目标参考文档（元数据：taskId, filename）
 */
@Configuration
public class RedisVectorStoreConfig {

    @Value("${spring.data.redis.host:localhost}")
    private String redisHost;

    @Value("${spring.data.redis.port:6379}")
    private int redisPort;

    @Value("${spring.data.redis.password:}")
    private String redisPassword;

    @Value("${app.rag.constraints-index:pentest-constraints}")
    private String constraintsIndex;

    @Value("${app.rag.target-docs-index:pentest-target-docs}")
    private String targetDocsIndex;

    @Bean("constraintsVectorStore")
    public VectorStore constraintsVectorStore(EmbeddingModel embeddingModel) {
        JedisPooled jedis = createJedis();
        return RedisVectorStore.builder(jedis, embeddingModel)
                .indexName(constraintsIndex)
                .metadataFields(
                        RedisVectorStore.MetadataField.tag("environment"),
                        RedisVectorStore.MetadataField.tag("phase"),
                        RedisVectorStore.MetadataField.text("filename"),
                        RedisVectorStore.MetadataField.tag("type")
                )
                .initializeSchema(true)
                .build();
    }

    @Bean("targetDocsVectorStore")
    public VectorStore targetDocsVectorStore(EmbeddingModel embeddingModel) {
        JedisPooled jedis = createJedis();
        return RedisVectorStore.builder(jedis, embeddingModel)
                .indexName(targetDocsIndex)
                .metadataFields(
                        RedisVectorStore.MetadataField.tag("taskId"),
                        RedisVectorStore.MetadataField.text("filename"),
                        RedisVectorStore.MetadataField.tag("type")
                )
                .initializeSchema(true)
                .build();
    }

    private JedisPooled createJedis() {
        if (redisPassword != null && !redisPassword.isBlank()) {
            return new JedisPooled(redisHost, redisPort, null, redisPassword);
        }
        return new JedisPooled(redisHost, redisPort);
    }
}

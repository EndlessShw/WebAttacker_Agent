package com.endlessshw.webattacker_agent.report;

import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.util.ast.Node;
import com.vladsch.flexmark.util.data.MutableDataSet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.xhtmlrenderer.pdf.ITextRenderer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Markdown → HTML → PDF 转换器
 *
 * 使用 flexmark-java 将 Markdown 渲染为 HTML，
 * 再使用 flying-saucer-pdf (xhtmlrenderer) 将 XHTML 转换为 PDF。
 */
@Slf4j
@Component
public class PdfConverter {

    private static final Parser MD_PARSER;
    private static final HtmlRenderer HTML_RENDERER;

    static {
        MutableDataSet options = new MutableDataSet();
        // 启用常用扩展：表格、删除线、任务列表
        options.set(Parser.EXTENSIONS, java.util.Arrays.asList(
                com.vladsch.flexmark.ext.tables.TablesExtension.create(),
                com.vladsch.flexmark.ext.gfm.strikethrough.StrikethroughExtension.create(),
                com.vladsch.flexmark.ext.gfm.tasklist.TaskListExtension.create()
        ));
        MD_PARSER = Parser.builder(options).build();
        HTML_RENDERER = HtmlRenderer.builder(options).build();
    }

    /**
     * 将 Markdown 字符串转换为 PDF 字节数组
     *
     * @param markdown Markdown 内容
     * @return PDF 字节数组
     */
    public byte[] convertToPdf(String markdown) {
        String html = markdownToHtml(markdown);
        String xhtml = wrapAsXhtml(html);
        return htmlToPdf(xhtml);
    }

    /**
     * 将 Markdown 转换为 HTML 片段
     */
    public String markdownToHtml(String markdown) {
        Node document = MD_PARSER.parse(markdown);
        return HTML_RENDERER.render(document);
    }

    /**
     * 将 HTML 片段包装为完整的 XHTML 文档（flying-saucer 需要 XHTML）
     */
    private String wrapAsXhtml(String htmlBody) {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
                    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
                <html xmlns="http://www.w3.org/1999/xhtml">
                <head>
                    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
                    <style>
                        body { font-family: Arial, sans-serif; font-size: 12pt; line-height: 1.6; margin: 2cm; }
                        h1 { font-size: 20pt; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 8px; }
                        h2 { font-size: 16pt; color: #34495e; margin-top: 20px; }
                        h3 { font-size: 13pt; color: #555; }
                        code { background: #f4f4f4; padding: 2px 4px; font-family: monospace; font-size: 10pt; }
                        pre { background: #f4f4f4; padding: 10px; border-left: 3px solid #3498db; overflow-x: auto; }
                        pre code { background: none; padding: 0; }
                        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
                        th { background: #3498db; color: white; padding: 8px; text-align: left; }
                        td { border: 1px solid #ddd; padding: 6px; }
                        tr:nth-child(even) { background: #f9f9f9; }
                        blockquote { border-left: 4px solid #3498db; margin: 0; padding-left: 16px; color: #666; }
                    </style>
                </head>
                <body>
                """ + htmlBody + """
                </body>
                </html>
                """;
    }

    /**
     * 将 XHTML 字符串转换为 PDF 字节数组
     */
    private byte[] htmlToPdf(String xhtml) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            // 解析 XHTML 为 DOM
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(xhtml.getBytes(StandardCharsets.UTF_8)));

            // 渲染为 PDF
            ITextRenderer renderer = new ITextRenderer();
            renderer.setDocument(doc, null);
            renderer.layout();
            renderer.createPDF(out);
            return out.toByteArray();
        } catch (Exception e) {
            log.error("[PdfConverter] PDF 生成失败", e);
            throw new RuntimeException("PDF 生成失败: " + e.getMessage(), e);
        }
    }
}

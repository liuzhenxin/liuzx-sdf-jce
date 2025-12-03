package org.liuzx.jce.provider.log;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class LiuzxProviderLogger {

    public enum LogLevel {
        DEBUG, INFO, WARN, ERROR
    }

    private static final String CONFIG_FILE = "/liuzx-jce.properties";
    private static final boolean enabled;
    private static final LogLevel currentLevel;
    private static final String logFilePattern;
    private static final BlockingQueue<String> logQueue;
    private static final Thread logWriterThread;
    
    private static volatile PrintWriter writer;
    private static volatile String currentLogDate; // e.g., "2025-12-04"

    static {
        Properties props = new Properties();
        try (InputStream is = LiuzxProviderLogger.class.getResourceAsStream(CONFIG_FILE)) {
            if (is != null) {
                props.load(is);
            }
        } catch (IOException e) {
            System.err.println("Could not load log properties file: " + CONFIG_FILE);
        }

        enabled = Boolean.parseBoolean(props.getProperty("log.enabled", "true"));

        if (enabled) {
            String logLevelName = props.getProperty("log.level", "INFO");
            // Default pattern: liuzx-jce.log -> liuzx-jce-%d{yyyy-MM-dd}.log
            logFilePattern = props.getProperty("log.file", "liuzx-jce.log")
                                  .replace(".log", "-%d{yyyy-MM-dd}.log");

            LogLevel level;
            try {
                level = LogLevel.valueOf(logLevelName.toUpperCase());
            } catch (IllegalArgumentException e) {
                level = LogLevel.INFO;
            }
            currentLevel = level;
            
            // Initialize writer for the first time
            updateWriter();

            logQueue = new LinkedBlockingQueue<>(1024);
            logWriterThread = new Thread(() -> {
                try {
                    while (!Thread.currentThread().isInterrupted()) {
                        writer.println(logQueue.take());
                    }
                } catch (InterruptedException e) {
                    while (!logQueue.isEmpty()) {
                        writer.println(logQueue.poll());
                    }
                    Thread.currentThread().interrupt();
                }
            }, "LiuzxProviderLogger-WriterThread");
            logWriterThread.setDaemon(true);
            logWriterThread.start();

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                log("LiuzxProviderLogger", LogLevel.INFO, "Logger shutting down...");
                logWriterThread.interrupt();
                try {
                    logWriterThread.join(1000);
                } catch (InterruptedException ignored) {}
                if (writer != null) {
                    writer.close();
                }
            }));
        } else {
            currentLevel = LogLevel.ERROR;
            logFilePattern = null;
            logQueue = null;
            logWriterThread = null;
            writer = null;
        }
    }

    private static synchronized void updateWriter() {
        String today = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
        if (today.equals(currentLogDate)) {
            return; // No need to change writer
        }

        if (writer != null) {
            writer.close();
        }

        try {
            String newLogFileName = logFilePattern.replace("%d{yyyy-MM-dd}", today);
            writer = new PrintWriter(new FileWriter(newLogFileName, true), true);
            currentLogDate = today;
            log("LiuzxProviderLogger", LogLevel.INFO, "Logging to new file: " + newLogFileName);
        } catch (IOException e) {
            System.err.println("Failed to create new log file: " + e.getMessage());
            writer = new PrintWriter(System.err, true); // Fallback to stderr
        }
    }

    private final String className;

    private LiuzxProviderLogger(String className) {
        this.className = className;
    }

    public static LiuzxProviderLogger getLogger(Class<?> clazz) {
        return new LiuzxProviderLogger(clazz.getSimpleName());
    }

    public void debug(String message, Object... args) {
        log(className, LogLevel.DEBUG, formatMessage(message, args));
    }

    public void info(String message, Object... args) {
        log(className, LogLevel.INFO, formatMessage(message, args));
    }

    public void warn(String message, Object... args) {
        log(className, LogLevel.WARN, formatMessage(message, args));
    }

    public void error(String message, Throwable t) {
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        log(className, LogLevel.ERROR, message + "\n" + sw.toString());
    }
    
    public void error(String message, Object... args) {
        log(className, LogLevel.ERROR, formatMessage(message, args));
    }

    private static void log(String className, LogLevel level, String message) {
        if (!enabled || level.ordinal() < currentLevel.ordinal()) {
            return;
        }
        
        updateWriter(); // Check if we need to roll the log file

        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
        String threadName = Thread.currentThread().getName();
        String fullMessage = String.format("%s [%s] %s - %s - %s", timestamp, threadName, level, className, message);
        if (logQueue != null) {
            logQueue.offer(fullMessage);
        }
    }

    private static String formatMessage(String message, Object... args) {
        if (args == null || args.length == 0) {
            return message;
        }
        for (Object arg : args) {
            if (message.contains("{}")) {
                message = message.replaceFirst("\\{\\}", String.valueOf(arg));
            }
        }
        return message;
    }
}

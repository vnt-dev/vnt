package com.vnt;

import org.json.JSONObject;

/**
 * 实例日志条目
 *
 * level 为 "info"/"warn"/"error"，time 为本地时间 HH:MM:SS。
 * 每个实例只保留最近 50 条，按时间正序返回。
 */
public class LogEntry {

    private final String level;
    private final String message;
    private final String time;

    private LogEntry(String level, String message, String time) {
        this.level = level;
        this.message = message;
        this.time = time;
    }

    static LogEntry fromJson(JSONObject obj) {
        return new LogEntry(
                obj.optString("level", "info"),
                obj.optString("message", ""),
                obj.optString("time", "")
        );
    }

    /**
     * 日志级别: "info"/"warn"/"error"
     */
    public String getLevel() {
        return level;
    }

    /**
     * 日志内容
     */
    public String getMessage() {
        return message;
    }

    /**
     * 本地时间 HH:MM:SS
     */
    public String getTime() {
        return time;
    }

    @Override
    public String toString() {
        return "[" + time + "] " + level + ": " + message;
    }
}

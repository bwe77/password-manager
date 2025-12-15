package com.project.password.manager.models;

public enum AuditAction {
    LOGIN,
    PASSWORD_ACCESSED,
    PASSWORD_CREATED,
    PASSWORD_UPDATED,
    PASSWORD_DELETED,
    LOGOUT,
    FAILED_LOGIN_ATTEMPT,
    MASTER_PASSWORD_CHANGED
}

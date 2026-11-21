package com.devmonitor.agent;

/** A problem the user can act on; the message is shown as-is. */
public final class EnrollmentException extends Exception {
    public EnrollmentException(String message) {
        super(message);
    }
}

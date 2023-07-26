package com.ruben.athleticlab.exception;

public class ApiException extends RuntimeException{

    public ApiException(String message) {
        super(message);
    }
}

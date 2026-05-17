package com.codingshuttle.youtube.hospitalManagement.exception;

import lombok.Data;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

@Data
public class ApiResponse {
    private LocalDateTime timeStamp;
    private String ex;
    private HttpStatus statusCode;



    public ApiResponse(String ex , HttpStatus httpStatus ){
        this.ex = ex;
        this.statusCode = httpStatus;
        this.timeStamp = LocalDateTime.now();
    }
}

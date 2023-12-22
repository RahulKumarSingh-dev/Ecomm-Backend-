package com.backend.ecomm.controller;

import com.backend.ecomm.entity.Test;
import com.backend.ecomm.service.TestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/test")
public class TestController {
    class CustomResponse {
        private boolean success;

        private Object data;

        public void setData(Object data) {
            this.data = data;
        }

        public Object getData() {
            return data;
        }

        public boolean isSuccess() {
            return success;
        }

        public void setSuccess(boolean success) {
            this.success = success;
        }
    }

    @Autowired
    private TestService testService;

    @GetMapping("/get-test")
    public ResponseEntity<CustomResponse> test() {
        CustomResponse response = new CustomResponse();
        response.setSuccess(false);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/test-save")
    public ResponseEntity<CustomResponse> saveTest(@RequestBody Test givenTest) {

        String text = givenTest.getTest();
        int id = givenTest.getId();
        Test test = testService.saveTest(new Test(id, text));

        System.out.println("test " + test);
        CustomResponse customResponse = new CustomResponse();
        customResponse.setSuccess(true);
        customResponse.setData(test);

        return new ResponseEntity<>(customResponse, HttpStatus.OK);
    }

    @GetMapping("/test-get/{id}")
    public ResponseEntity<CustomResponse> getTest(@PathVariable int id) {

        Test test = testService.getTestById(id);

        CustomResponse customResponse = new CustomResponse();
        customResponse.setData(test);
        customResponse.setSuccess(true);
        return new ResponseEntity<>(customResponse, HttpStatus.OK);
    }

    @DeleteMapping("/test-delete/{id}")
    public ResponseEntity<CustomResponse> deleteTest(@PathVariable int id) {

        Test test = testService.deleteTestById(id);

        CustomResponse customResponse = new CustomResponse();
        customResponse.setData(test);
        customResponse.setSuccess(true);
        return new ResponseEntity<>(customResponse, HttpStatus.OK);
    }
}

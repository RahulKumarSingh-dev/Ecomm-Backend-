package com.backend.ecomm.service;

import com.backend.ecomm.entity.Test;
import com.backend.ecomm.repository.TestRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TestService {

    @Autowired
    private TestRepository testRepository;

    public Test saveTest(Test test) {
        return testRepository.save(test);
    }
    public Test getTestById(int id){
        return testRepository.findById(id);
    }
    public Test deleteTestById(int id){
        Test test = getTestById(id);
        testRepository.deleteById(id);
        return test;
    }
}

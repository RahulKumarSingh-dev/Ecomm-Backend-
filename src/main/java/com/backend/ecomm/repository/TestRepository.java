package com.backend.ecomm.repository;

import com.backend.ecomm.entity.Test;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TestRepository extends JpaRepository<Test, Integer> {
    public Test findById(int id);
}

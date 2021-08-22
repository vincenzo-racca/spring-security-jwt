package com.vincenzoracca.springsecurityjwt.repo;

import com.vincenzoracca.springsecurityjwt.model.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserJpaRepository extends JpaRepository<UserEntity, Long> {

    UserEntity findByUsername(String username);
}

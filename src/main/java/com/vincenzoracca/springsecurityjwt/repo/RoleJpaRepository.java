package com.vincenzoracca.springsecurityjwt.repo;

import com.vincenzoracca.springsecurityjwt.model.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;


public interface RoleJpaRepository extends JpaRepository<RoleEntity, Long> {

    RoleEntity findByName(String name);
}

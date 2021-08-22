package com.vincenzoracca.springsecurityjwt.service.impl;

import com.vincenzoracca.springsecurityjwt.model.entity.RoleEntity;
import com.vincenzoracca.springsecurityjwt.repo.RoleJpaRepository;
import com.vincenzoracca.springsecurityjwt.service.RoleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleJpaRepository roleJpaRepository;

    @Override
    public RoleEntity save(RoleEntity roleEntity) {
        log.info("Saving role {} to the database", roleEntity.getName());
        return roleJpaRepository.save(roleEntity);
    }


}

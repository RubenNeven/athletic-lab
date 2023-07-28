package com.ruben.athleticlab.service.implementation;

import com.ruben.athleticlab.domain.Role;
import com.ruben.athleticlab.repository.RoleRepository;
import com.ruben.athleticlab.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository<Role> roleRoleRepository;

    @Override
    public Role getRoleByUserId(Long id) {
        return roleRoleRepository.getRoleByUserId(id);
    }
}

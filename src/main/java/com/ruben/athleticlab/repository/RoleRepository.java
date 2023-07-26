package com.ruben.athleticlab.repository;

import com.ruben.athleticlab.domain.Role;
import org.springframework.stereotype.Repository;

import java.util.Collection;

@Repository
public interface RoleRepository <T extends Role> {

    /** Basic CRUD operations */

    T create(T data);

    Collection<T> list(int page, int pageSize);

    T get(Long id);

    T update(T data);

    boolean delete(Long id);

    /** More complex operations */

    void addRoleToUser(Long userId, String roleName);

    Role getRoleByUserId(Long id);

    Role getRoleByUserEmail(String email);

    void updateUserRole(Long id, String roleName);

}

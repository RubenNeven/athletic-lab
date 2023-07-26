package com.ruben.athleticlab.repository.implementation;

import com.ruben.athleticlab.domain.Role;
import com.ruben.athleticlab.exception.ApiException;
import com.ruben.athleticlab.repository.RoleRepository;
import com.ruben.athleticlab.rowmapper.RoleRowMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;

import static com.ruben.athleticlab.enumeration.RoleType.*;
import static com.ruben.athleticlab.query.RoleQuery.*;
import static java.util.Objects.*;

@Slf4j
@Repository
@RequiredArgsConstructor
public class RoleRepositoryImpl<T extends Role> implements RoleRepository<T> {


    private final NamedParameterJdbcTemplate jdbc;

    @Override
    public T create(T data) {
        return null;
    }

    @Override
    public Collection<T> list(int page, int pageSize) {
        return null;
    }

    @Override
    public T get(Long id) {
        return null;
    }

    @Override
    public T update(T data) {
        return null;
    }

    @Override
    public boolean delete(Long id) {
        return false;
    }

    @Override
    public void addRoleToUser(Long userId, String roleName) {
        log.info("Adding role {} to user id: {}", roleName, userId);

        try {
            Role role = jdbc.queryForObject(SELECT_ROLE_BY_NAME_QUERY, Map.of("name", roleName), new RoleRowMapper());
            jdbc.update(INSERT_ROLE_TO_USER_QUERY, Map.of("userId", userId, "roleId", requireNonNull(role).getId()));
        } catch (EmptyResultDataAccessException exception) {
            throw new ApiException("No role found by name: " + ROLE_USER.name());
        } catch (Exception exception) {
            throw new ApiException("An error occurred. Please try again");
        }
    }

    @Override
    public Role getRoleByUserId(Long id) {
        return null;
    }

    @Override
    public Role getRoleByUserEmail(String email) {
        return null;
    }

    @Override
    public void updateUserRole(Long id, String roleName) {

    }
}

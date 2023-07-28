package com.ruben.athleticlab.repository;

import com.ruben.athleticlab.domain.User;
import com.ruben.athleticlab.dto.UserDTO;

import java.util.Collection;

public interface UserRepository<T extends User> {

    /** Basic CRUD operations */

    T create(T data);

    Collection<T> list(int page, int pageSize);

    T get(Long id);

    T update(T data);

    boolean delete(Long id);


    User getUserByEmail(String email);

    void sendVerificationCode(UserDTO userDTO);
}

package com.ruben.athleticlab.repository;

import com.ruben.athleticlab.domain.User;
import com.ruben.athleticlab.dto.UserDTO;
import com.ruben.athleticlab.form.UpdateForm;

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

    User verifyCode(String email, String code);

    void resetPassword(String email);

    T verifyPasswordKey(String key);

    void renewPassword(String key, String password, String confirmPassword);

    T verifyAccountKey(String key);

    T updateUserDetails(UpdateForm user);
}

package com.ruben.athleticlab.service;

import com.ruben.athleticlab.domain.User;
import com.ruben.athleticlab.dto.UserDTO;
import com.ruben.athleticlab.form.UpdateForm;

public interface UserService {

    UserDTO createUser(User user);

    UserDTO getUserByEmail(String email);

    void sendVerificationCode(UserDTO userDTO);


    UserDTO verifyCode(String email, String code);

    void resetPassword(String email);
    UserDTO verifyPasswordKey(String key);

    void renewPassword(String key, String password, String confirmPassword);

    UserDTO verifyAccountKey(String key);

    UserDTO getUserById(Long subject);

    UserDTO updateUserDetails(UpdateForm user);

}

package com.ruben.athleticlab.service;

import com.ruben.athleticlab.domain.User;
import com.ruben.athleticlab.dto.UserDTO;

public interface UserService {

    UserDTO createUser(User user);

    UserDTO getUserByEmail(String email);

    void sendVerificationCode(UserDTO userDTO);


    UserDTO verifyCode(String email, String code);

    void resetPassword(String email);
    UserDTO verifyPasswordKey(String key);

    void renewPassword(String key, String password, String confirmPassword);

    UserDTO verifyAccountKey(String key);
}

package com.ruben.athleticlab.service;

import com.ruben.athleticlab.domain.User;
import com.ruben.athleticlab.dto.UserDTO;

public interface UserService {

    UserDTO createUser(User user);

    UserDTO getUserByEmail(String email);
}

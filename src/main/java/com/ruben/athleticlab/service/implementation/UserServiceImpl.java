package com.ruben.athleticlab.service.implementation;

import com.ruben.athleticlab.domain.Role;
import com.ruben.athleticlab.domain.User;
import com.ruben.athleticlab.dto.UserDTO;
import com.ruben.athleticlab.form.UpdateForm;
import com.ruben.athleticlab.repository.RoleRepository;
import com.ruben.athleticlab.repository.UserRepository;
import com.ruben.athleticlab.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import static com.ruben.athleticlab.dtomapper.UserDTOMapper.fromUser;


@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository<User> userRepository;
    private final RoleRepository<Role> roleRoleRepository;

    @Override
    public UserDTO createUser(User user) {
        return mapToUserDTO(userRepository.create(user));
    }

    @Override
    public UserDTO getUserByEmail(String email) {
        return mapToUserDTO(userRepository.getUserByEmail(email));
    }

    @Override
    public void sendVerificationCode(UserDTO userDTO) {
        userRepository.sendVerificationCode(userDTO);
    }


    @Override
    public UserDTO verifyCode(String email, String code) {
        return mapToUserDTO(userRepository.verifyCode(email, code));
    }

    @Override
    public void resetPassword(String email) {
        userRepository.resetPassword(email);
    }

    @Override
    public UserDTO verifyPasswordKey(String key) {
        return mapToUserDTO(userRepository.verifyPasswordKey(key));
    }

    @Override
    public void renewPassword(String key, String password, String confirmPassword) {
        userRepository.renewPassword(key, password, confirmPassword);
    }

    @Override
    public UserDTO verifyAccountKey(String key) {
        return mapToUserDTO(userRepository.verifyAccountKey(key));
    }

    @Override
    public UserDTO getUserById(Long userId) {
        return mapToUserDTO(userRepository.get(userId));
    }

    @Override
    public UserDTO updateUserDetails(UpdateForm user) {
        return mapToUserDTO(userRepository.updateUserDetails(user));
    }

    private UserDTO mapToUserDTO(User user) {
        return fromUser(user, roleRoleRepository.getRoleByUserId(user.getId()));
    }
}



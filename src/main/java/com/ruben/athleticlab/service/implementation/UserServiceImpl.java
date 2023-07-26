package com.ruben.athleticlab.service.implementation;

import com.ruben.athleticlab.domain.User;
import com.ruben.athleticlab.dto.UserDTO;
import com.ruben.athleticlab.dtomapper.UserDTOMapper;
import com.ruben.athleticlab.repository.UserRepository;
import com.ruben.athleticlab.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository<User> userRepository;

    @Override
    public UserDTO createUser(User user) {
        return UserDTOMapper.fromUser(userRepository.create(user));
    }
}

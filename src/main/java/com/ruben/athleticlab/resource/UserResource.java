package com.ruben.athleticlab.resource;


import com.ruben.athleticlab.domain.HttpResponse;
import com.ruben.athleticlab.domain.User;
import com.ruben.athleticlab.domain.UserPrincipal;
import com.ruben.athleticlab.dto.UserDTO;
import com.ruben.athleticlab.event.NewUserEvent;
import com.ruben.athleticlab.exception.ApiException;
import com.ruben.athleticlab.form.LoginForm;
import com.ruben.athleticlab.provider.TokenProvider;
import com.ruben.athleticlab.service.RoleService;
import com.ruben.athleticlab.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;

import static com.ruben.athleticlab.dtomapper.UserDTOMapper.toUser;
import static com.ruben.athleticlab.enumeration.EventType.*;
import static com.ruben.athleticlab.utils.ExceptionUtils.processError;
import static com.ruben.athleticlab.utils.UserUtils.getLoggedInUser;
import static java.time.LocalDateTime.now;
import static java.util.Map.of;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.security.authentication.UsernamePasswordAuthenticationToken.unauthenticated;


@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping(path = "/user")
public class UserResource {

    private final UserService userService;
    private final RoleService roleService;
    private final AuthenticationManager authenticationManager;
    private final TokenProvider tokenProvider;
    private final ApplicationEventPublisher publisher;
    private final HttpServletRequest request;
    private final HttpServletResponse response;


    @PostMapping("/login")
    public ResponseEntity<HttpResponse> login(@RequestBody @Valid LoginForm loginForm) {
        UserDTO user = authenticate(loginForm.getEmail(), loginForm.getPassword());
        return user.isUsingMfa() ? sendVerificationCode(user) : sendResponse(user);
    }

    @PostMapping("/register")
    public ResponseEntity<HttpResponse> saveUser(@RequestBody @Valid User user){
        UserDTO userDTO = userService.createUser(user);
        return ResponseEntity.created(getUri()).body(
            HttpResponse.builder()
                    .timeStamp(now().toString())
                    .data(of("user", userDTO))
                    .message("User Created")
                    .status(CREATED)
                    .statusCode(CREATED.value())
                    .build());
    }


    @GetMapping("/profile")
    public ResponseEntity<HttpResponse> getProfile(Authentication authentication) {
        UserDTO user = userService.getUserByEmail(authentication.getName());
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of("user", user))
                        .message("Profile retrieved")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @GetMapping("/verify/code/{email}/{code}")
    public ResponseEntity<HttpResponse> verifyCode(@PathVariable("email") String email, @PathVariable("code") String code) {
        UserDTO user = userService.verifyCode(email, code);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of("user", user, "access_token", tokenProvider.createAccessToken(getUserPrincipal(user))
                                , "refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(user))))
                        .message("Login Success")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @GetMapping("/resetpassword/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email) {
        userService.resetPassword(email);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .message("Email sent. Please check your email to reset your password")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @GetMapping("/verify/password/{key}")
    public ResponseEntity<HttpResponse> verifyPasswordUrl(@PathVariable("key") String key) {
        UserDTO user = userService.verifyPasswordKey(key);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of("user", user))
                        .message("Please enter a new password")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @PostMapping("/resetpassword/{key}/{password}/{confirmPassword}")
    public ResponseEntity<HttpResponse> resetPasswordWithKey(@PathVariable("key") String key, @PathVariable("password") String password, @PathVariable("confirmPassword") String confirmPassword) {
        userService.renewPassword(key, password, confirmPassword);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .message("Please reset successfully")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    @RequestMapping("/error")
    public ResponseEntity<HttpResponse> handleError(HttpServletRequest request) {
        return ResponseEntity.badRequest().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .reason("There is no mapping for a " + request.getMethod() + " request for this path on the server")
                        .status(BAD_REQUEST)
                        .statusCode(BAD_REQUEST.value())
                        .build());
    }


    private URI getUri(){
        return URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/get/<userId>").toUriString());
    }

    private ResponseEntity<HttpResponse> sendResponse(UserDTO userDTO){
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of("user", userDTO,
                                "access_token", tokenProvider.createAccessToken(getUserPrincipal(userDTO)),
                                "refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(userDTO))))
                        .message("Login Success")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }
        private UserPrincipal getUserPrincipal(UserDTO user) {
        return new UserPrincipal(toUser(userService.getUserByEmail(user.getEmail())), roleService.getRoleByUserId(user.getId()));
    }

    private ResponseEntity<HttpResponse> sendVerificationCode(UserDTO userDTO){
        userService.sendVerificationCode(userDTO);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                        .timeStamp(now().toString())
                        .data(of("user", userDTO))
                        .message("Verification code sent")
                        .status(OK)
                        .statusCode(OK.value())
                        .build());
    }

    private UserDTO authenticate(String email, String password) {
        UserDTO userByEmail = userService.getUserByEmail(email);
        try {
            if(null != userByEmail) {
                publisher.publishEvent(new NewUserEvent(email, LOGIN_ATTEMPT));
            }
            Authentication authentication = authenticationManager.authenticate(unauthenticated(email, password));
            UserDTO loggedInUser = getLoggedInUser(authentication);
            if(!loggedInUser.isUsingMfa()) {
                publisher.publishEvent(new NewUserEvent(email, LOGIN_ATTEMPT_SUCCESS));
            }
            return loggedInUser;
        } catch (Exception exception) {
            if(null != userByEmail) {
                publisher.publishEvent(new NewUserEvent(email, LOGIN_ATTEMPT_FAILURE));
            }
            processError(request, response, exception);
            throw new ApiException(exception.getMessage());
        }
    }
}

INSERT INTO Roles (name, permission)
VALUES ('ROLE_USER', 'READ:USER, READ:CUSTOMER'),
       ('ROLE_MANAGER', 'READ:USER, READ:CUSTOMER, UPDATE:USER, UPDATE:CUSTOMER'),
       ('ROLE_ADMIN', 'READ:USER, READ:CUSTOMER, CREATE_USER, CREATE:CUSTOMER UPDATE:USER, UPDATE:CUSTOMER'),
       ('ROLE_SYSADMIN',
        'READ:USER, READ:CUSTOMER, CREATE_USER, CREATE:CUSTOMER UPDATE:USER, UPDATE:CUSTOMER, DELETE:USER, DELETE:CUSTOMER');

INSERT INTO Users(first_name, last_name, email, phone, password, using_mfa, enabled) VALUES ('Ruben', 'Neven', 'rubenneven@gmail.com', '32484482978','$12$2rx4Bm8wuv1ETpXz5DLvHOTKizSdfQuQcqd3CUCOrRQGwKIpDLtCG', true,true);

INSERT INTO Users(first_name, last_name, email, phone, password, using_mfa, enabled) VALUES ('Test', 'User', 'ruben_neven@gmail.com', '32484482978','$12$2rx4Bm8wuv1ETpXz5DLvHOTKizSdfQuQcqd3CUCOrRQGwKIpDLtCG', false,true);

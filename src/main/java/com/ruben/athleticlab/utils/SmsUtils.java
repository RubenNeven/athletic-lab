package com.ruben.athleticlab.utils;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

import static com.twilio.rest.api.v2010.account.Message.creator;

public class SmsUtils {


    public static final String FROM_NUMBER = "+17626002944";
    public static final String SID_KEY = "ACcce800cadd456ea7f72d44cf0fa95976";
    public static final String TOKEN_KEY = "8f48e06f037cc77ac0c5d3f9718a3d51";

    public static void sendSMS(String to, String messageBody){
        Twilio.init(SID_KEY, TOKEN_KEY);
        Message message = creator(new PhoneNumber("+" + to), new PhoneNumber(FROM_NUMBER), messageBody).create();
        System.out.println(message);
    }
}

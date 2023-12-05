package com.ivoronline.springboot_security_solution_jwt_endpoint.jwt;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;

@RestController
public class JWTController {

  //PROPERTIES
  @Autowired JWTUtil               jwtUtil;
  @Autowired AuthenticationManager authenticationManager;

  //==================================================================
  // CREATE JWT
  //==================================================================
  @RequestMapping("CreateJWT")
  String createJWT(@RequestParam String username, @RequestParam String password) throws IOException {

    //AUTHENTICATE (COMPARE ENTERED & STORED PASSWORD)
    Authentication inputAuthentication  = new UsernamePasswordAuthenticationToken(username, password);
    Authentication outputAuthentication = authenticationManager.authenticate(inputAuthentication); //Exception

    //CREATE JWT
    String authorities = outputAuthentication.getAuthorities().toString(); //"[ROLE_ADMIN, ROLE_USER]"
    String jwt         = jwtUtil.createJWT(username, authorities);

    //RETURN JWT
    return jwt;
    
  }

  //===============================================================
  // AUTHENTICATE
  //===============================================================
  @RequestMapping("Authenticate")
  String authenticate(
    @RequestParam (required = false) String jwt,             //When using Request Parameter
    @RequestHeader(required = false) String authorization    //When using Authorization Header
  ) throws Exception {

    //FOR AUTHORIZATION HEADER
    if (jwt == null) { jwt = jwtUtil.getJWTFromAuthorizationHeader(authorization); }

    //CREATE AUTHENTICATION OBJECT
    Authentication authentication = jwtUtil.createAuthenticationObjectFromJWT(jwt);

    //STORE AUTHENTICATION INTO CONTEXT (SESSION)
    SecurityContextHolder.getContext().setAuthentication(authentication);

    //RETURN STATUS
    return "User Authenticated";

  }

  //===============================================================
  // GET CLAIMS
  //===============================================================
  @RequestMapping("GetClaims")
  Claims getClaims(@RequestParam String jwt) {
    return jwtUtil.getClaims(jwt);
  }

  //==================================================================
  // EXCEPTION HANDLER                             (For all Endpoints)
  //==================================================================
  @ExceptionHandler
  String exceptionHandler(Exception exception) {
    return exception.getMessage(); //Bad credentials
  }

}



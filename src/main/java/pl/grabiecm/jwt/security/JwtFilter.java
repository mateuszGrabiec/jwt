package pl.grabiecm.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import java.util.Collections;


public class JwtFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        String authorization="";
        authorization= httpServletRequest.getHeader("Authorization");
       //authorization="Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik1hdGV1c3ogR3JhYmllYyIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.NwsgtHGyo24jVn4FnYrPUqeagPRs5JTUxjQ0Zg6dVWvzpSFMabLRNrKVfn66ISkc9liwIxu4_3HNFIJHemmUWA";
        UsernamePasswordAuthenticationToken authenticationToken = getInfo(authorization);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }

    private UsernamePasswordAuthenticationToken getInfo(String authorization) {
        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC512("ShVmYq3t6w9z$C&F)J@NcRfTjWnZr4u7x!A%D*G-KaPdSgVkXp2s5v8y/B?E(H+M")).build();
        DecodedJWT verify = jwtVerifier.verify(authorization.substring(7));
        String name = verify.getClaim("name").asString();
        boolean isAdmin = verify.getClaim("admin").asBoolean();
        String role = "ROLE_USER";
        if(isAdmin)
            role = "ROLE_ADMIN";
        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(role);
        return new UsernamePasswordAuthenticationToken(
                name,
                null,
                Collections.singleton(simpleGrantedAuthority));
    }
}

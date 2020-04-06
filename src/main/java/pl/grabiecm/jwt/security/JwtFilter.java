package pl.grabiecm.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        String authorization="";
        authorization= httpServletRequest.getHeader("Authorization");
        //authorization="Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik1hdGV1c3ogR3JhYmllYyIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.NwsgtHGyo24jVn4FnYrPUqeagPRs5JTUxjQ0Zg6dVWvzpSFMabLRNrKVfn66ISkc9liwIxu4_3HNFIJHemmUWA";
        UsernamePasswordAuthenticationToken authenticationToken = null;
        try {
            authenticationToken = getInfo(authorization);
        } catch (Exception e) {
            e.printStackTrace();
        }
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }


    private UsernamePasswordAuthenticationToken getInfo(String authorization) throws Exception{
        SignedJWT signedJWT = SignedJWT.parse(authorization.substring(7));
        RSAKey publicKey = new RSAKey.Builder((RSAPublicKey) getPublicKey()).build();
        JWSVerifier jwsVerifier = new RSASSAVerifier(publicKey);
        if (!signedJWT.verify(jwsVerifier)) {
            throw new Exception();
        }

        String name = signedJWT.getJWTClaimsSet().getSubject();
        boolean isAdmin = signedJWT.getJWTClaimsSet().getBooleanClaim("admin");
        String role = "ROLE_USER";
        if (isAdmin)
            role = "ROLE_ADMIN";
        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(role);
        return new UsernamePasswordAuthenticationToken(name, null, Collections.singleton(simpleGrantedAuthority));
    }

    private PublicKey getPublicKey() throws Exception {
        return PublicKeyReader.get("{path}/src/main/resources/static/public_key.der");
    }

    //symetric veryfication
//    private UsernamePasswordAuthenticationToken getInfo(String authorization) {
//        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC512("ShVmYq3t6w9z$C&F)J@NcRfTjWnZr4u7x!A%D*G-KaPdSgVkXp2s5v8y/B?E(H+M")).build();
//        DecodedJWT verify = jwtVerifier.verify(authorization.substring(7));
//        String name = verify.getClaim("name").asString();
//        boolean isAdmin = verify.getClaim("admin").asBoolean();
//        String role = "ROLE_USER";
//        if(isAdmin)
//            role = "ROLE_ADMIN";
//        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(role);
//        return new UsernamePasswordAuthenticationToken(
//                name,
//                null,
//                Collections.singleton(simpleGrantedAuthority));
//    }
}

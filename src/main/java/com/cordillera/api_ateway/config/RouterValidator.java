package com.cordillera.api_ateway.config; 
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.List;

@Component
public class RouterValidator {


    private static final List<String> PUBLIC_ROUTES = List.of(
            "/usuarios/auth/login",      
            "/usuarios/auth/registro",     
            "/actuator/**"    
    );

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public boolean isSecured(String path) {
        
        return PUBLIC_ROUTES.stream().noneMatch(pattern -> pathMatcher.match(pattern, path));
    }
}
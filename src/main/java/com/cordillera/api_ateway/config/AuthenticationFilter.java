package com.cordillera.api_ateway.config;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;
    private final RouterValidator routerValidator;

    public AuthenticationFilter(JwtUtil jwtUtil, RouterValidator routerValidator) {
        this.jwtUtil = jwtUtil;
        this.routerValidator = routerValidator;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        System.out.println("GATEWAY DEBUG - Petición recibida en: " + path);

        if (!routerValidator.isSecured(path)) {
            System.out.println("GATEWAY DEBUG - Ruta pública, pasando...");
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            System.out.println("GATEWAY DEBUG - Error: Header Authorization ausente o inválido.");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);
        if (!jwtUtil.validateToken(token)) {
            System.out.println("GATEWAY DEBUG - Error: Token inválido según JwtUtil.");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        System.out.println("GATEWAY DEBUG - Token válido, reenviando a microservicio...");
        return chain.filter(exchange.mutate()
            .request(exchange.getRequest().mutate()
             .header(HttpHeaders.AUTHORIZATION, authHeader)
             .build())
            .build());
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
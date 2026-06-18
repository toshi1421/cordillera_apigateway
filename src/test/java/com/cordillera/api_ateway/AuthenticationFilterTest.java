package com.cordillera.api_ateway;

import com.cordillera.api_ateway.config.AuthenticationFilter;
import com.cordillera.api_ateway.config.JwtUtil;
import com.cordillera.api_ateway.config.RouterValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class AuthenticationFilterTest {

    private JwtUtil jwtUtil;
    private RouterValidator routerValidator;
    private AuthenticationFilter filter;
    private GatewayFilterChain chain;

    @BeforeEach
    void setUp() {
        jwtUtil = mock(JwtUtil.class);
        routerValidator = mock(RouterValidator.class);
        filter = new AuthenticationFilter(jwtUtil, routerValidator);
        chain = mock(GatewayFilterChain.class);

        when(chain.filter(any())).thenReturn(Mono.empty());
    }

    @Test
    void testFilter_PublicRoute_ShouldPass() {
        when(routerValidator.isSecured("/public/path")).thenReturn(false);
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/public/path"));

        filter.filter(exchange, chain);

        verify(chain).filter(exchange);
    }

    @Test
    void testFilter_MissingAuthHeader_ShouldReturnUnauthorized() {
        when(routerValidator.isSecured("/private/path")).thenReturn(true);
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/private/path"));

        filter.filter(exchange, chain);

        assertEquals(401, exchange.getResponse().getStatusCode().value());
    }

    @Test
    void testFilter_InvalidToken_ShouldReturnUnauthorized() {
        when(routerValidator.isSecured("/private/path")).thenReturn(true);
        when(jwtUtil.validateToken("invalid-token")).thenReturn(false);

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/private/path")
                .header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token"));

        filter.filter(exchange, chain);

        assertEquals(401, exchange.getResponse().getStatusCode().value());
    }

    @Test
    void testFilter_ValidToken_ShouldPass() {
        when(routerValidator.isSecured("/private/path")).thenReturn(true);
        when(jwtUtil.validateToken("valid-token")).thenReturn(true);

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/private/path")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token"));

        filter.filter(exchange, chain);

        verify(chain).filter(any());
    }
}
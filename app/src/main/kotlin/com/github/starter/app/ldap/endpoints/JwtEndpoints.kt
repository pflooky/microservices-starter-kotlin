package com.github.starter.app.ldap.endpoints

import com.github.starter.app.util.JwtUtil
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import reactor.core.publisher.Mono

@RestController
@RequestMapping("/jwt")
class JwtEndpoints(private val jwtUtil: JwtUtil) {

    @PostMapping(value = ["/create"], consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun createJwtToken(@RequestBody body: String): Mono<String> {
        return Mono.just(jwtUtil.createJwt(body))
    }

}

//curl -k -X POST https://localhost:8080/jwt/create -d "hello world"
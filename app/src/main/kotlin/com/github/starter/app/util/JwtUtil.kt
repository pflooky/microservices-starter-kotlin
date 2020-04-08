package com.github.starter.app.util

import com.fasterxml.jackson.databind.ObjectMapper
import com.github.starter.app.config.JwtConfig
import com.github.starter.app.ldap.service.DefaultLdapService
import com.github.starter.core.container.Container
import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import java.security.Key
import java.util.Date
import javax.crypto.spec.SecretKeySpec

@Component
class JwtUtil(private val jwtConfig: JwtConfig) {

    companion object {
        val objectMapper = ObjectMapper()
        private val LOGGER: Logger = LoggerFactory.getLogger(JwtUtil::class.java)
    }

    fun createJwt(subject: Any): String {
        val signatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm.HS256
        val nowMillis = System.currentTimeMillis()
        val now = Date(nowMillis)

        val apiKeySecretBytes: ByteArray = jwtConfig.secretKey.toByteArray()
        val signingKey: Key = SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.jcaName)

        val subjectAsString = objectMapper.writeValueAsString(Container(subject))

        val builder: JwtBuilder = Jwts.builder()
                .setIssuedAt(now)
                .setSubject(subjectAsString)
                .setIssuer(jwtConfig.issuer)
                .signWith(signatureAlgorithm, signingKey)

        setExpiration(nowMillis, builder)
        return builder.compact()
    }

    private fun setExpiration(nowMillis: Long, builder: JwtBuilder): JwtBuilder {
        if (jwtConfig.ttlMillis > 0) {
            val expMillis = nowMillis + jwtConfig.ttlMillis
            val exp = Date(expMillis)
            builder.setExpiration(exp)
        } else {
            LOGGER.warn("no expiration set on JWT token, ttlMillis in jwt config set to <= 0, ttlMillis={}", jwtConfig.ttlMillis)
        }

        return builder
    }
}
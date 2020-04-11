package com.github.starter.app.util

import com.github.starter.app.config.JwtConfig
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
        private val LOGGER: Logger = LoggerFactory.getLogger(JwtUtil::class.java)
        private val signatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm.HS256
    }

    fun createJwt(subject: String): String {
        val nowMillis = System.currentTimeMillis()
        val now = Date(nowMillis)

        val apiKeySecretBytes: ByteArray = jwtConfig.secretKey.toByteArray()
        val signingKey: Key = SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.jcaName)

        val builder: JwtBuilder = Jwts.builder()
                .setIssuedAt(now)
                .setSubject(subject)
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
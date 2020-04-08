package com.github.starter.app.config

import com.github.starter.app.R
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "jwt")
class JwtConfig {
    lateinit var secretKey: String

    val issuer: String = R.APP_NAME
    val ttlMillis: Long = R.JWT_DEFAULT_TTL_MILLIS
}
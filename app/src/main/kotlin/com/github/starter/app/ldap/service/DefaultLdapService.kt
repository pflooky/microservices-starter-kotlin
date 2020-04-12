package com.github.starter.app.ldap.service

import com.github.starter.app.config.LdapConfig
import com.github.starter.app.ldap.exception.UnknownUserException
import org.apache.directory.api.ldap.model.message.SearchScope
import org.apache.directory.ldap.client.api.LdapConnection
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import java.lang.RuntimeException

@Service
@ConditionalOnProperty(name = ["ldap.enabled"], havingValue = "true")
class DefaultLdapService(private val ldapConnection: LdapConnection, private val ldapConfig: LdapConfig) : LdapService {

    companion object {
        private val LOGGER: Logger = LoggerFactory.getLogger(DefaultLdapService::class.java)
    }

    override fun checkMembers(group: String): Mono<List<String>> {
        val searchResult = ldapConnection.search(ldapConfig.baseDn, "(cn=$group)", SearchScope.ONELEVEL).toList()
        LOGGER.info("search for members in group: {}, number of members = {}", group, searchResult.size)
        val members = searchResult.map{entry ->
            println(entry)
            entry.get("cn").string
        }
        return Mono.just(members)
    }

    override fun getAttribute(user: String, attribute: String): Mono<String> {
        val searchResult = ldapConnection.search(ldapConfig.baseDn, "(cn=$user)", SearchScope.ONELEVEL).toList() //sAMAccountName
        LOGGER.info("search for attribute ({}) for user: {}", attribute, user)
        return if (searchResult.isEmpty()) {
            LOGGER.error("did not find entry for user: {}", user)
            Mono.error(UnknownUserException("failed to find entry for user $user"))
        } else {
            val userAttribute = searchResult.first().get(attribute).string
            Mono.just(userAttribute)
        }
    }
}